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
}

// OTAConfig is the deployment configuration: the OTA_* environment variables
// Terraform sets, plus the AWS_REGION the Lambda runtime sets (the bucket's
// region too, since S3 only notifies functions in its own region).
type OTAConfig struct {
	Region         string
	ThingGroupARN  string
	ThingGroupName string
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

// arnName parses an ARN for the given service whose resource is
// `<resourceType>/<name>`, and returns the ARN and the name.
func (p *envParser) arnName(name, service, resourceType string) (string, string) {
	value, ok := p.required(name)
	if !ok {
		return "", ""
	}
	parsed, err := arn.Parse(value)
	resourceName, found := strings.CutPrefix(parsed.Resource, resourceType+"/")
	if err != nil || parsed.Service != service || !found || resourceName == "" {
		p.fail(name, value, "must be an ARN of the form arn:aws:%s:...:%s/<name>", service, resourceType)
		return "", ""
	}
	return value, resourceName
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
	c.ThingGroupARN, c.ThingGroupName = p.arnName("OTA_THING_GROUP_ARN", "iot", "thinggroup")
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

// buildJobID normalizes and limits the job ID to 64 characters to comply with AWS requirements.
func buildJobID(version string, timestamp int64) string {
	reg := regexp.MustCompile(`[^A-Za-z0-9_-]+`)
	safeVersion := reg.ReplaceAllString(version, "-")
	safeVersion = strings.Trim(safeVersion, "-_")
	if safeVersion == "" {
		safeVersion = "firmware"
	}
	prefix := jobIDPrefix
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

// createJobInput builds the OTA job for the thing group.
//
// CONTINUOUS so a device that joins the group after the upload (a newly
// provisioned one) still gets the release. The rollout starts slowly and only
// speeds up as devices report SUCCEEDED; the abort criterion cancels the job
// once too many executions end badly; the timeout turns a device that never
// reports back into TIMED_OUT instead of IN_PROGRESS forever.
func (a *App) createJobInput(jobID, version, document string) *iot.CreateJobInput {
	c := a.cfg
	return &iot.CreateJobInput{
		JobId:           aws.String(jobID),
		Targets:         []string{c.ThingGroupARN},
		Document:        aws.String(document),
		Description:     aws.String(fmt.Sprintf("OTA Update for %s", version)),
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

// cancelSupersededJobs keeps one OTA job in flight for the thing group: the
// newest upload. A CONTINUOUS job never completes on its own, so without this
// every release would stay active forever, and a device joining the group would
// be sent all of them, oldest first.
//
// Older jobs are cancelled without force: their QUEUED executions are dropped,
// while a device already IN_PROGRESS finishes (and then picks up the newest
// job). "Newest" is by upload time, read back from the job ID, so concurrent or
// out-of-order invocations converge on the same survivor; if a newer job is
// already active, jobID itself is the one cancelled. created says whether this
// invocation created jobID. It returns the surviving job's ID.
func (a *App) cancelSupersededJobs(ctx context.Context, jobID string, created bool) (string, error) {
	var active []string
	ownActive := created

	paginator := iot.NewListJobsPaginator(a.iotClient, &iot.ListJobsInput{
		Status:         types.JobStatusInProgress,
		ThingGroupName: aws.String(a.cfg.ThingGroupName),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return "", fmt.Errorf("listing jobs for thing group %s: %w", a.cfg.ThingGroupName, err)
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

// Handler turns a firmware upload into an OTA job for the configured thing
// group, then cancels the group's older OTA jobs.
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

	// Extract version from the object key (e.g. firmware_v0.0.1.bin)
	parts := strings.Split(objectKey, "/")
	version := strings.TrimSuffix(parts[len(parts)-1], ".bin")

	// The upload's event time, not the clock: every delivery of the same event
	// maps to the same job ID, while a new upload of the same file gets a new one.
	uploadedAt := record.EventTime
	if uploadedAt.IsZero() {
		slog.Warn("S3 event has no eventTime; using the current time")
		uploadedAt = time.Now()
	}
	jobID := buildJobID(version, uploadedAt.UnixMilli())

	// The document the firmware parses, with the same fields as before. AWS IoT
	// replaces the download_url placeholder with an HTTPS URL when the device
	// fetches the document (and the firmware refuses anything that is not https).
	jobDocument := map[string]interface{}{
		"operation":        "firmware_update",
		"firmware_version": version,
		"download_url":     presignedURLPlaceholder(a.cfg.Region, bucketName, objectKey),
	}
	docBytes, err := json.Marshal(jobDocument)
	if err != nil {
		slog.Error("Error marshalling job document", "error", err)
		return Response{StatusCode: 500, Body: "Error marshalling job document"}, err
	}

	created := true
	_, err = a.iotClient.CreateJob(ctx, a.createJobInput(jobID, version, string(docBytes)))
	var exists *types.ResourceAlreadyExistsException
	switch {
	case errors.As(err, &exists):
		created = false
		slog.Info("Job already exists; the S3 event was delivered again", "jobID", jobID)
	case err != nil:
		slog.Error("Error creating job", "error", err)
		return Response{StatusCode: 500, Body: "Error creating job"}, err
	default:
		slog.Info("Created job successfully", "jobID", jobID, "thingGroup", a.cfg.ThingGroupName)
	}

	newest, err := a.cancelSupersededJobs(ctx, jobID, created)
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
		Body:       fmt.Sprintf("OTA job %s created for thing group %s.", jobID, a.cfg.ThingGroupName),
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
