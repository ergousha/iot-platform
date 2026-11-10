package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	"github.com/aws/aws-sdk-go-v2/service/iot/types"
)

const (
	// jobIDPrefix marks the jobs this Lambda creates. Only jobs carrying it are
	// ever cancelled as superseded; anything else targeting the group is left alone.
	jobIDPrefix = "ota-"

	// presignedURLExpirySeconds is how long each download URL stays valid (the
	// API maximum). AWS IoT signs it when the device fetches its job document,
	// not when the job is created, so a device joining the group months later
	// still gets a working URL.
	presignedURLExpirySeconds = 3600
)

// IoTAPI defines the AWS IoT Core operations utilized by this Lambda.
type IoTAPI interface {
	CreateJob(ctx context.Context, params *iot.CreateJobInput, optFns ...func(*iot.Options)) (*iot.CreateJobOutput, error)
	ListJobs(ctx context.Context, params *iot.ListJobsInput, optFns ...func(*iot.Options)) (*iot.ListJobsOutput, error)
	CancelJob(ctx context.Context, params *iot.CancelJobInput, optFns ...func(*iot.Options)) (*iot.CancelJobOutput, error)
	DescribeJob(ctx context.Context, params *iot.DescribeJobInput, optFns ...func(*iot.Options)) (*iot.DescribeJobOutput, error)
}

// productIDPattern is what Terraform accepts as a product id.
var productIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]{1,15}$`)

// ProductGroup is the fleet thing group a product's OTA jobs target.
type ProductGroup struct {
	ARN  string
	Name string
}

// OTAConfig is the deployment configuration: the OTA_* environment variables
// Terraform sets, plus the AWS_REGION the Lambda runtime sets (the bucket's
// region too, since S3 only notifies functions in its own region).
type OTAConfig struct {
	Region string

	// Products maps each product id to its fleet thing group. An upload under
	// <id>/ becomes a job for that group only.
	Products map[string]ProductGroup
	// LegacyRootProduct owns uploads at the bucket root, where releases went
	// before there were products. Empty: such uploads are ignored.
	LegacyRootProduct string

	PresignRoleARN string

	RolloutBaseRatePerMinute int32
	RolloutIncrementFactor   float64
	RolloutSucceededThings   int32
	RolloutMaxPerMinute      int32

	AbortFailurePercentage float64
	AbortMinExecutedThings int32

	InProgressTimeoutMinutes int64
}

// App encapsulates the application context, facilitating unit testing via client interfaces.
type App struct {
	iotClient IoTAPI
	cfg       OTAConfig
}

// Response represents the Lambda proxy response structure.
type Response struct {
	StatusCode int    `json:"statusCode"`
	Body       string `json:"body"`
}

// envParser reads required settings and collects every problem, so a broken
// deployment reports all of them at once instead of one per redeploy.
type envParser struct {
	getenv func(string) string
	errs   []error
}

func (p *envParser) fail(name, value, format string, args ...any) {
	p.errs = append(p.errs, fmt.Errorf("%s=%q: %s", name, value, fmt.Sprintf(format, args...)))
}

func (p *envParser) required(name string) (string, bool) {
	value := p.getenv(name)
	if value == "" {
		p.errs = append(p.errs, fmt.Errorf("%s is not set", name))
		return "", false
	}
	return value, true
}

func (p *envParser) integer(name string, lo, hi int64) int64 {
	value, ok := p.required(name)
	if !ok {
		return 0
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < lo || n > hi {
		p.fail(name, value, "must be an integer from %d to %d", lo, hi)
		return 0
	}
	return n
}

// decimal parses a number with at most `places` digits after the point: AWS IoT
// rejects more precision than that for increment factors and abort thresholds.
func (p *envParser) decimal(name string, places int, lo, hi float64) float64 {
	value, ok := p.required(name)
	if !ok {
		return 0
	}
	format := regexp.MustCompile(fmt.Sprintf(`^[0-9]+(\.[0-9]{1,%d})?$`, places))
	f, err := strconv.ParseFloat(value, 64)
	if !format.MatchString(value) || err != nil || f < lo || f > hi {
		p.fail(name, value, "must be a number from %g to %g with at most %d decimal place(s)", lo, hi, places)
		return 0
	}
	return f
}

// resourceName returns <name> from an ARN of the given service whose resource
// is `<resourceType>/<name>`.
func resourceName(value, service, resourceType string) (string, bool) {
	parsed, err := arn.Parse(value)
	name, found := strings.CutPrefix(parsed.Resource, resourceType+"/")
	if err != nil || parsed.Service != service || !found || name == "" {
		return "", false
	}
	return name, true
}

// arnName parses an ARN for the given service whose resource is
// `<resourceType>/<name>`, and returns the ARN and the name.
func (p *envParser) arnName(name, service, resourceType string) (string, string) {
	value, ok := p.required(name)
	if !ok {
		return "", ""
	}
	resource, ok := resourceName(value, service, resourceType)
	if !ok {
		p.fail(name, value, "must be an ARN of the form arn:aws:%s:...:%s/<name>", service, resourceType)
		return "", ""
	}
	return value, resource
}

// productGroups parses a JSON object of product id -> thing group ARN.
func (p *envParser) productGroups(name string) map[string]ProductGroup {
	value, ok := p.required(name)
	if !ok {
		return nil
	}
	var raw map[string]string
	if err := json.Unmarshal([]byte(value), &raw); err != nil || len(raw) == 0 {
		p.fail(name, value, "must be a non-empty JSON object of product id to thing group ARN")
		return nil
	}
	groups := make(map[string]ProductGroup, len(raw))
	for id, groupARN := range raw {
		groupName, ok := resourceName(groupARN, "iot", "thinggroup")
		if !productIDPattern.MatchString(id) || !ok {
			p.fail(name, value, "product %q: needs an id of 2-16 lowercase letters and digits and an ARN of the form arn:aws:iot:...:thinggroup/<name>", id)
			continue
		}
		groups[id] = ProductGroup{ARN: groupARN, Name: groupName}
	}
	return groups
}

// loadConfig reads and validates the configuration from the environment.
//
// Every value is required. Terraform is the one place that holds the defaults
// (and validates them at plan time); a missing or malformed value here means a
// broken deployment, and the Lambda refuses to start rather than roll out a
// release without its brakes. The ranges are the ones the IoT API enforces.
func loadConfig(getenv func(string) string) (OTAConfig, error) {
	p := &envParser{getenv: getenv}
	var c OTAConfig

	c.Region, _ = p.required("AWS_REGION")
	c.Products = p.productGroups("OTA_PRODUCT_GROUPS")
	// Optional: empty means root-level uploads belong to no product.
	c.LegacyRootProduct = getenv("OTA_LEGACY_ROOT_PRODUCT")
	if _, known := c.Products[c.LegacyRootProduct]; c.LegacyRootProduct != "" && c.Products != nil && !known {
		p.fail("OTA_LEGACY_ROOT_PRODUCT", c.LegacyRootProduct, "is not one of the products in OTA_PRODUCT_GROUPS")
	}
	c.PresignRoleARN, _ = p.arnName("OTA_PRESIGN_ROLE_ARN", "iam", "role")

	c.RolloutBaseRatePerMinute = int32(p.integer("OTA_ROLLOUT_BASE_RATE_PER_MINUTE", 1, 1000))
	c.RolloutIncrementFactor = p.decimal("OTA_ROLLOUT_INCREMENT_FACTOR", 1, 1.1, 5)
	c.RolloutSucceededThings = int32(p.integer("OTA_ROLLOUT_SUCCEEDED_THINGS", 1, math.MaxInt32))
	c.RolloutMaxPerMinute = int32(p.integer("OTA_ROLLOUT_MAX_PER_MINUTE", 1, math.MaxInt32))
	if c.RolloutBaseRatePerMinute > 0 && c.RolloutMaxPerMinute > 0 && c.RolloutBaseRatePerMinute > c.RolloutMaxPerMinute {
		p.errs = append(p.errs, fmt.Errorf("OTA_ROLLOUT_BASE_RATE_PER_MINUTE (%d) must not exceed OTA_ROLLOUT_MAX_PER_MINUTE (%d)",
			c.RolloutBaseRatePerMinute, c.RolloutMaxPerMinute))
	}

	c.AbortFailurePercentage = p.decimal("OTA_ABORT_FAILURE_PERCENTAGE", 2, 0.01, 100)
	c.AbortMinExecutedThings = int32(p.integer("OTA_ABORT_MIN_EXECUTED_THINGS", 1, math.MaxInt32))

	c.InProgressTimeoutMinutes = p.integer("OTA_IN_PROGRESS_TIMEOUT_MINUTES", 1, 10080)

	if err := errors.Join(p.errs...); err != nil {
		return OTAConfig{}, err
	}
	return c, nil
}

// buildJobID builds `ota-<product>-<version>-<timestamp>`, with the version
// normalized and shortened so the ID fits the 64 characters AWS IoT allows.
func buildJobID(product, version string, timestamp int64) string {
	reg := regexp.MustCompile(`[^A-Za-z0-9_-]+`)
	safeVersion := reg.ReplaceAllString(version, "-")
	safeVersion = strings.Trim(safeVersion, "-_")
	if safeVersion == "" {
		safeVersion = "firmware"
	}
	prefix := jobIDPrefix + product + "-"
	suffix := fmt.Sprintf("-%d", timestamp)
	const maxJobIDLength = 64
	availableLength := maxJobIDLength - len(prefix) - len(suffix)
	if len(safeVersion) > availableLength {
		safeVersion = safeVersion[:availableLength]
	}
	return prefix + safeVersion + suffix
}

// jobTimestamp returns the timestamp buildJobID put at the end of a job ID.
func jobTimestamp(jobID string) (int64, bool) {
	i := strings.LastIndexByte(jobID, '-')
	if i < 0 {
		return 0, false
	}
	ts, err := strconv.ParseInt(jobID[i+1:], 10, 64)
	return ts, err == nil
}

// newerJob reports whether job a comes from a later upload than job b. Equal
// timestamps fall back to the ID, so every invocation agrees on the order.
func newerJob(a, b string) bool {
	tsA, _ := jobTimestamp(a)
	tsB, _ := jobTimestamp(b)
	if tsA != tsB {
		return tsA > tsB
	}
	return a > b
}

// s3EscapeKey percent-encodes an object key the way the S3 SDKs do: RFC 3986
// unreserved characters and "/" stay, every other byte is encoded.
func s3EscapeKey(key string) string {
	var b strings.Builder
	for i := 0; i < len(key); i++ {
		c := key[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || strings.IndexByte("-._~/", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// presignedURLPlaceholder returns the placeholder AWS IoT Jobs replaces with a
// freshly presigned GET URL every time a device fetches its job document. The
// `-v2` form expects the object URL S3-encoded.
func presignedURLPlaceholder(region, bucket, key string) string {
	return fmt.Sprintf("${aws:iot:s3-presigned-url-v2:https://s3.%s.amazonaws.com/%s/%s}", region, bucket, s3EscapeKey(key))
}

// route returns the product an uploaded object belongs to: `<product>/<file>`
// for a configured product, or a file at the bucket root for the legacy
// product. Anything else (an unknown prefix, a deeper path) belongs to none.
func (c OTAConfig) route(key string) (string, bool) {
	dir, file, nested := strings.Cut(key, "/")
	if !nested {
		return c.LegacyRootProduct, c.LegacyRootProduct != ""
	}
	if _, known := c.Products[dir]; !known || file == "" || strings.Contains(file, "/") {
		return "", false
	}
	return dir, true
}

// createJobInput builds the OTA job for the product's thing group.
//
// CONTINUOUS so a device that joins the group after the upload (a newly
// provisioned one) still gets the release. The rollout starts slowly and only
// speeds up as devices report SUCCEEDED; the abort criterion cancels the job
// once too many executions end badly; the timeout turns a device that never
// reports back into TIMED_OUT instead of IN_PROGRESS forever.
func (a *App) createJobInput(product string, group ProductGroup, jobID, version, document string) *iot.CreateJobInput {
	c := a.cfg
	return &iot.CreateJobInput{
		JobId:           aws.String(jobID),
		Targets:         []string{group.ARN},
		Document:        aws.String(document),
		Description:     aws.String(fmt.Sprintf("OTA update %s for %s", version, product)),
		TargetSelection: types.TargetSelectionContinuous,
		PresignedUrlConfig: &types.PresignedUrlConfig{
			RoleArn:      aws.String(c.PresignRoleARN),
			ExpiresInSec: aws.Int64(presignedURLExpirySeconds),
		},
		JobExecutionsRolloutConfig: &types.JobExecutionsRolloutConfig{
			ExponentialRate: &types.ExponentialRolloutRate{
				BaseRatePerMinute: aws.Int32(c.RolloutBaseRatePerMinute),
				IncrementFactor:   aws.Float64(c.RolloutIncrementFactor),
				RateIncreaseCriteria: &types.RateIncreaseCriteria{
					NumberOfSucceededThings: aws.Int32(c.RolloutSucceededThings),
				},
			},
			MaximumPerMinute: aws.Int32(c.RolloutMaxPerMinute),
		},
		// ALL counts FAILED (e.g. an image that rolled back), TIMED_OUT (a device
		// that never came back) and REJECTED together: any of them is a reason to
		// stop a release, and a mix of them should add up.
		AbortConfig: &types.AbortConfig{
			CriteriaList: []types.AbortCriteria{{
				Action:                    types.AbortActionCancel,
				FailureType:               types.JobExecutionFailureTypeAll,
				MinNumberOfExecutedThings: aws.Int32(c.AbortMinExecutedThings),
				ThresholdPercentage:       aws.Float64(c.AbortFailurePercentage),
			}},
		},
		TimeoutConfig: &types.TimeoutConfig{
			InProgressTimeoutInMinutes: aws.Int64(c.InProgressTimeoutMinutes),
		},
	}
}

// cancelSupersededJobs keeps one OTA job in flight for the product's thing
// group: the newest upload. Each product has its own group, so a release only
// ever supersedes releases of the same product. A CONTINUOUS job never completes on its own, so without this
// every release would stay active forever, and a device joining the group would
// be sent all of them, oldest first.
//
// Older jobs are cancelled without force: their QUEUED executions are dropped,
// while a device already IN_PROGRESS finishes (and then picks up the newest
// job). "Newest" is by upload time, read back from the job ID, so concurrent or
// out-of-order invocations converge on the same survivor; if a newer job is
// already active, jobID itself is the one cancelled. created says whether this
// invocation created jobID. It returns the surviving job's ID.
//
// Only jobs that TARGET this group compete. Listing a child group's jobs also
// returns the jobs aimed at its parent: the product's canary group lists the
// fleet jobs scripts/promote.sh created. Those keep serving the fleet (devices
// that join it, or come back online) until the next promotion replaces them, so
// a new canary release must not cancel them.
func (a *App) cancelSupersededJobs(ctx context.Context, group ProductGroup, jobID string, created bool) (string, error) {
	var active []string
	ownActive := created

	paginator := iot.NewListJobsPaginator(a.iotClient, &iot.ListJobsInput{
		Status:         types.JobStatusInProgress,
		ThingGroupName: aws.String(group.Name),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return "", fmt.Errorf("listing jobs for thing group %s: %w", group.Name, err)
		}
		for _, job := range page.Jobs {
			id := aws.ToString(job.JobId)
			if id == jobID {
				ownActive = true
				continue
			}
			if !strings.HasPrefix(id, jobIDPrefix) {
				continue // not an OTA release job
			}
			if _, ok := jobTimestamp(id); !ok {
				slog.Warn("Leaving ota- job without an upload timestamp alone", "jobID", id)
				continue
			}
			targetsGroup, err := a.jobTargets(ctx, id, group.ARN)
			if err != nil {
				return "", err
			}
			if !targetsGroup {
				continue // e.g. a promoted fleet job, listed through the parent group
			}
			active = append(active, id)
		}
	}
	if ownActive {
		active = append(active, jobID)
	}

	newest := jobID
	for _, id := range active {
		if newerJob(id, newest) {
			newest = id
		}
	}

	var errs []error
	for _, id := range active {
		if id == newest {
			continue
		}
		_, err := a.iotClient.CancelJob(ctx, &iot.CancelJobInput{
			JobId:      aws.String(id),
			ReasonCode: aws.String("SUPERSEDED"),
			Comment:    aws.String("Superseded by OTA job " + newest),
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("cancelling job %s: %w", id, err))
			continue
		}
		slog.Info("Cancelled superseded job", "jobID", id, "supersededBy", newest)
	}
	return newest, errors.Join(errs...)
}

// jobTargets reports whether job id targets groupARN directly. A job that was
// deleted since it was listed targets nothing.
func (a *App) jobTargets(ctx context.Context, id, groupARN string) (bool, error) {
	out, err := a.iotClient.DescribeJob(ctx, &iot.DescribeJobInput{JobId: aws.String(id)})
	if err != nil {
		var gone *types.ResourceNotFoundException
		if errors.As(err, &gone) {
			return false, nil
		}
		return false, fmt.Errorf("describing job %s: %w", id, err)
	}
	if out.Job == nil {
		return false, nil
	}
	for _, t := range out.Job.Targets {
		if t == groupARN {
			return true, nil
		}
	}
	return false, nil
}

// Handler turns a firmware upload into an OTA job for its product's thing
// group, then cancels that group's older OTA jobs. An upload that belongs to no
// product is logged and ignored, never retried.
//
// Failures are returned as errors so Lambda retries the asynchronous S3 event.
// That is safe: the job ID is derived from the upload, so a retried or
// redelivered event finds its job already created and only finishes the rest.
func (a *App) Handler(ctx context.Context, event events.S3Event) (Response, error) {
	eventJSON, _ := json.Marshal(event)
	slog.Info("Received S3 event", "event", string(eventJSON))

	if len(event.Records) == 0 {
		slog.Warn("No records found in S3 event")
		return Response{StatusCode: 400, Body: "No records found"}, nil
	}

	record := event.Records[0]
	bucketName := record.S3.Bucket.Name
	objectKey := record.S3.Object.URLDecodedKey
	if objectKey == "" {
		objectKey = record.S3.Object.Key
	}

	product, ok := a.cfg.route(objectKey)
	if !ok {
		slog.Warn("Ignoring upload: its key belongs to no product", "key", objectKey)
		return Response{StatusCode: 200, Body: fmt.Sprintf("Ignored %s: it belongs to no product.", objectKey)}, nil
	}
	group := a.cfg.Products[product]

	// Extract version from the object key (e.g. vaktus/firmware_v0.0.1.bin)
	parts := strings.Split(objectKey, "/")
	version := strings.TrimSuffix(parts[len(parts)-1], ".bin")

	// The upload's event time, not the clock: every delivery of the same event
	// maps to the same job ID, while a new upload of the same file gets a new one.
	uploadedAt := record.EventTime
	if uploadedAt.IsZero() {
		slog.Warn("S3 event has no eventTime; using the current time")
		uploadedAt = time.Now()
	}
	jobID := buildJobID(product, version, uploadedAt.UnixMilli())

	// The document the firmware parses. AWS IoT replaces the download_url
	// placeholder with an HTTPS URL when the device fetches the document (and
	// the firmware refuses anything that is not https). `product` lets a device
	// refuse an image meant for another product; older firmware ignores it.
	jobDocument := map[string]interface{}{
		"operation":        "firmware_update",
		"product":          product,
		"firmware_version": version,
		"download_url":     presignedURLPlaceholder(a.cfg.Region, bucketName, objectKey),
	}
	docBytes, err := json.Marshal(jobDocument)
	if err != nil {
		slog.Error("Error marshalling job document", "error", err)
		return Response{StatusCode: 500, Body: "Error marshalling job document"}, err
	}

	created := true
	_, err = a.iotClient.CreateJob(ctx, a.createJobInput(product, group, jobID, version, string(docBytes)))
	var exists *types.ResourceAlreadyExistsException
	switch {
	case errors.As(err, &exists):
		created = false
		slog.Info("Job already exists; the S3 event was delivered again", "jobID", jobID)
	case err != nil:
		slog.Error("Error creating job", "error", err)
		return Response{StatusCode: 500, Body: "Error creating job"}, err
	default:
		slog.Info("Created job successfully", "jobID", jobID, "product", product, "thingGroup", group.Name)
	}

	newest, err := a.cancelSupersededJobs(ctx, group, jobID, created)
	if err != nil {
		slog.Error("Error cancelling superseded jobs", "error", err)
		return Response{StatusCode: 500, Body: "Error cancelling superseded jobs"}, err
	}
	if newest != jobID {
		return Response{
			StatusCode: 200,
			Body:       fmt.Sprintf("OTA job %s superseded by %s.", jobID, newest),
		}, nil
	}

	return Response{
		StatusCode: 200,
		Body:       fmt.Sprintf("OTA job %s created for thing group %s.", jobID, group.Name),
	}, nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	otaCfg, err := loadConfig(os.Getenv)
	if err != nil {
		slog.Error("Invalid OTA configuration", "error", err)
		panic(fmt.Sprintf("invalid OTA configuration: %v", err))
	}

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		slog.Error("Unable to load AWS SDK config", "error", err)
		panic(fmt.Sprintf("unable to load SDK config, %v", err))
	}

	app := &App{
		iotClient: iot.NewFromConfig(cfg),
		cfg:       otaCfg,
	}

	lambda.Start(app.Handler)
}
