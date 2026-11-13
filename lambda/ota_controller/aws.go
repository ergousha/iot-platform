package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	iottypes "github.com/aws/aws-sdk-go-v2/service/iot/types"
	"github.com/aws/aws-sdk-go-v2/service/iotdataplane"
	iotdatatypes "github.com/aws/aws-sdk-go-v2/service/iotdataplane/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// IoTAPI is the AWS IoT subset the controller uses.
type IoTAPI interface {
	ListJobs(context.Context, *iot.ListJobsInput, ...func(*iot.Options)) (*iot.ListJobsOutput, error)
	ListJobExecutionsForJob(context.Context, *iot.ListJobExecutionsForJobInput, ...func(*iot.Options)) (*iot.ListJobExecutionsForJobOutput, error)
	DescribeJobExecution(context.Context, *iot.DescribeJobExecutionInput, ...func(*iot.Options)) (*iot.DescribeJobExecutionOutput, error)
	CreateJob(context.Context, *iot.CreateJobInput, ...func(*iot.Options)) (*iot.CreateJobOutput, error)
	CancelJob(context.Context, *iot.CancelJobInput, ...func(*iot.Options)) (*iot.CancelJobOutput, error)
	CancelJobExecution(context.Context, *iot.CancelJobExecutionInput, ...func(*iot.Options)) (*iot.CancelJobExecutionOutput, error)

	DescribeThingGroup(context.Context, *iot.DescribeThingGroupInput, ...func(*iot.Options)) (*iot.DescribeThingGroupOutput, error)
	UpdateThingGroup(context.Context, *iot.UpdateThingGroupInput, ...func(*iot.Options)) (*iot.UpdateThingGroupOutput, error)
	ListThingsInThingGroup(context.Context, *iot.ListThingsInThingGroupInput, ...func(*iot.Options)) (*iot.ListThingsInThingGroupOutput, error)
	UpdateThingGroupsForThing(context.Context, *iot.UpdateThingGroupsForThingInput, ...func(*iot.Options)) (*iot.UpdateThingGroupsForThingOutput, error)

	ListTargetsForPolicy(context.Context, *iot.ListTargetsForPolicyInput, ...func(*iot.Options)) (*iot.ListTargetsForPolicyOutput, error)
	DescribeCertificate(context.Context, *iot.DescribeCertificateInput, ...func(*iot.Options)) (*iot.DescribeCertificateOutput, error)
	UpdateCertificate(context.Context, *iot.UpdateCertificateInput, ...func(*iot.Options)) (*iot.UpdateCertificateOutput, error)
	DeleteCertificate(context.Context, *iot.DeleteCertificateInput, ...func(*iot.Options)) (*iot.DeleteCertificateOutput, error)
	CreateCertificateFromCsr(context.Context, *iot.CreateCertificateFromCsrInput, ...func(*iot.Options)) (*iot.CreateCertificateFromCsrOutput, error)
	AttachPolicy(context.Context, *iot.AttachPolicyInput, ...func(*iot.Options)) (*iot.AttachPolicyOutput, error)
	DetachPolicy(context.Context, *iot.DetachPolicyInput, ...func(*iot.Options)) (*iot.DetachPolicyOutput, error)
	ListCertificates(context.Context, *iot.ListCertificatesInput, ...func(*iot.Options)) (*iot.ListCertificatesOutput, error)
	ListThings(context.Context, *iot.ListThingsInput, ...func(*iot.Options)) (*iot.ListThingsOutput, error)
	ListThingPrincipals(context.Context, *iot.ListThingPrincipalsInput, ...func(*iot.Options)) (*iot.ListThingPrincipalsOutput, error)
	DetachThingPrincipal(context.Context, *iot.DetachThingPrincipalInput, ...func(*iot.Options)) (*iot.DetachThingPrincipalOutput, error)

	// Owner actions (admin.go).
	AddThingToThingGroup(context.Context, *iot.AddThingToThingGroupInput, ...func(*iot.Options)) (*iot.AddThingToThingGroupOutput, error)
	RemoveThingFromThingGroup(context.Context, *iot.RemoveThingFromThingGroupInput, ...func(*iot.Options)) (*iot.RemoveThingFromThingGroupOutput, error)
	DeleteThing(context.Context, *iot.DeleteThingInput, ...func(*iot.Options)) (*iot.DeleteThingOutput, error)
	EnableTopicRule(context.Context, *iot.EnableTopicRuleInput, ...func(*iot.Options)) (*iot.EnableTopicRuleOutput, error)
}

// ShadowAPI reads device shadows.
type ShadowAPI interface {
	GetThingShadow(context.Context, *iotdataplane.GetThingShadowInput, ...func(*iotdataplane.Options)) (*iotdataplane.GetThingShadowOutput, error)
}

// S3API reads releases.
type S3API interface {
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
}

// SSMAPI reads the guard and signing keys and keeps the claim.
type SSMAPI interface {
	GetParameter(context.Context, *ssm.GetParameterInput, ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	PutParameter(context.Context, *ssm.PutParameterInput, ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

// DynamoAPI scans the registry and presence tables (both a few items).
type DynamoAPI interface {
	Scan(context.Context, *dynamodb.ScanInput, ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
}

// SNSAPI emails the owner.
type SNSAPI interface {
	Publish(context.Context, *sns.PublishInput, ...func(*sns.Options)) (*sns.PublishOutput, error)
}

// HTTPDoer is the GitHub API client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// App holds the clients and the configuration.
type App struct {
	cfg    Config
	iot    IoTAPI
	shadow ShadowAPI
	s3     S3API
	ssm    SSMAPI
	ddb    DynamoAPI
	sns    SNSAPI
	http   HTTPDoer
	now    func() time.Time
	sleep  func(time.Duration) // nil: time.Sleep
}

// ---------------------------------------------------------------------------
// Account-wide views, loaded once per invocation.
// ---------------------------------------------------------------------------

// Record is a device registry record.
type Record struct {
	Thing       string // MAC12
	Product     string
	Allowed     bool
	Provisioned bool
	Canary      bool
	EnrolBy     time.Time
}

// windowOpen: the record may still enrol.
func (r Record) windowOpen(now time.Time) bool {
	return r.Allowed && !r.Provisioned && now.Before(r.EnrolBy)
}

type global struct {
	jobs     []iottypes.JobSummary
	presence map[string]*Device // thing -> presence (no shadow)
	records  []Record
}

func (a *App) scanAll(ctx context.Context, table string) ([]map[string]ddbtypes.AttributeValue, error) {
	var items []map[string]ddbtypes.AttributeValue
	var start map[string]ddbtypes.AttributeValue
	for {
		out, err := a.ddb.Scan(ctx, &dynamodb.ScanInput{TableName: aws.String(table), ExclusiveStartKey: start, ConsistentRead: aws.Bool(true)})
		if err != nil {
			return nil, fmt.Errorf("scanning %s: %w", table, err)
		}
		items = append(items, out.Items...)
		if len(out.LastEvaluatedKey) == 0 {
			return items, nil
		}
		start = out.LastEvaluatedKey
	}
}

func attrS(item map[string]ddbtypes.AttributeValue, k string) string {
	if v, ok := item[k].(*ddbtypes.AttributeValueMemberS); ok {
		return v.Value
	}
	return ""
}

func attrN(item map[string]ddbtypes.AttributeValue, k string) int64 {
	if v, ok := item[k].(*ddbtypes.AttributeValueMemberN); ok {
		n, _ := strconv.ParseInt(strings.SplitN(v.Value, ".", 2)[0], 10, 64)
		return n
	}
	return 0
}

func attrB(item map[string]ddbtypes.AttributeValue, k string) bool {
	v, ok := item[k].(*ddbtypes.AttributeValueMemberBOOL)
	return ok && v.Value
}

// thingName turns a registry MAC (AA:BB:...) into the thing name (MAC12).
func thingName(mac string) string {
	return strings.ToUpper(strings.NewReplacer(":", "", "-", "").Replace(mac))
}

func (a *App) loadRecords(ctx context.Context) ([]Record, error) {
	items, err := a.scanAll(ctx, a.cfg.RegistryTable)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, it := range items {
		r := Record{
			Thing:       thingName(attrS(it, "mac_address")),
			Product:     attrS(it, "product"),
			Allowed:     attrB(it, "allowed"),
			Provisioned: attrB(it, "provisioned"),
			Canary:      attrB(it, "canary"),
		}
		if n := attrN(it, "enrol_by"); n > 0 {
			r.EnrolBy = time.Unix(n, 0)
		}
		out = append(out, r)
	}
	return out, nil
}

// loadPresence reads the presence table the lifecycle rule writes: one item
// per thing and event type (connected, disconnected), each the latest.
// A thing is online when its latest connect is newer than its latest
// disconnect (versionNumber orders the sessions; events can arrive late).
func (a *App) loadPresence(ctx context.Context) (map[string]*Device, error) {
	items, err := a.scanAll(ctx, a.cfg.PresenceTable)
	if err != nil {
		return nil, err
	}
	type ev struct {
		at        time.Time
		session   int64
		principal string
	}
	conn, disc := map[string]ev{}, map[string]ev{}
	for _, it := range items {
		e := ev{at: time.UnixMilli(attrN(it, "at")), session: attrN(it, "session"), principal: attrS(it, "principal")}
		switch attrS(it, "event") {
		case "connected":
			conn[attrS(it, "thing")] = e
		case "disconnected":
			disc[attrS(it, "thing")] = e
		}
	}
	out := map[string]*Device{}
	for thing, c := range conn {
		d, seen := disc[thing]
		out[thing] = &Device{
			Thing:       thing,
			Online:      !seen || c.session > d.session || (c.session == d.session && c.at.After(d.at)),
			ConnectedAt: c.at,
			Principal:   c.principal,
		}
	}
	return out, nil
}

func (a *App) listAllJobs(ctx context.Context) ([]iottypes.JobSummary, error) {
	var jobs []iottypes.JobSummary
	p := iot.NewListJobsPaginator(a.iot, &iot.ListJobsInput{MaxResults: aws.Int32(250)})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing jobs: %w", err)
		}
		jobs = append(jobs, page.Jobs...)
	}
	return jobs, nil
}

func (a *App) loadGlobal(ctx context.Context) (*global, error) {
	g := &global{}
	var err error
	if g.jobs, err = a.listAllJobs(ctx); err != nil {
		return nil, err
	}
	if g.presence, err = a.loadPresence(ctx); err != nil {
		return nil, err
	}
	if g.records, err = a.loadRecords(ctx); err != nil {
		return nil, err
	}
	return g, nil
}

// GuardState is the kill switch's SSM state.
type GuardState struct {
	Tripped bool   `json:"tripped"`
	Scope   string `json:"scope,omitempty"`
	// DisabledRules are the product rules (<product>_*) the trip disabled
	// while they were enabled.
	DisabledRules []string `json:"disabled_rules,omitempty"`
}

// guard reads the guard state. Unreadable counts as tripped: never arm or
// roll out on an unknown guard.
func (a *App) guard(ctx context.Context) (GuardState, error) {
	out, err := a.ssm.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(a.cfg.GuardStateParameter)})
	if err != nil {
		return GuardState{Tripped: true, Scope: "unknown"}, fmt.Errorf("reading the guard state: %w", err)
	}
	var g GuardState
	if err := json.Unmarshal([]byte(aws.ToString(out.Parameter.Value)), &g); err != nil {
		return GuardState{Tripped: true, Scope: "unreadable"}, nil
	}
	return g, nil
}

// ---------------------------------------------------------------------------
// Per-product snapshot.
// ---------------------------------------------------------------------------

type loadOptions struct {
	allVersions bool // overrides: rollback and target need versions at or below the fleet's
	shadows     bool // force reading shadows
	orphans     bool // hourly: compare GitHub Releases with S3
}

type groupMeta struct {
	version     int64
	description string
}

func (a *App) groupState(ctx context.Context, p ProductConfig) (FleetState, groupMeta, error) {
	out, err := a.iot.DescribeThingGroup(ctx, &iot.DescribeThingGroupInput{ThingGroupName: aws.String(p.Fleet.Name)})
	if err != nil {
		return FleetState{}, groupMeta{}, fmt.Errorf("describing %s: %w", p.Fleet.Name, err)
	}
	attrs := map[string]string{}
	meta := groupMeta{version: out.Version}
	if props := out.ThingGroupProperties; props != nil {
		meta.description = aws.ToString(props.ThingGroupDescription)
		if props.AttributePayload != nil {
			attrs = props.AttributePayload.Attributes
		}
	}
	return stateFromAttributes(attrs, p.SoakHours), meta, nil
}

func (a *App) groupThings(ctx context.Context, group string, recursive bool) ([]string, error) {
	var things []string
	p := iot.NewListThingsInThingGroupPaginator(a.iot, &iot.ListThingsInThingGroupInput{
		ThingGroupName: aws.String(group), Recursive: recursive, MaxResults: aws.Int32(250),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing things in %s: %w", group, err)
		}
		things = append(things, page.Things...)
	}
	return things, nil
}

func (a *App) snapshot(ctx context.Context, p ProductConfig, g *global, opt loadOptions) (*Snapshot, groupMeta, error) {
	s := &Snapshot{
		Product: p, Now: a.now(), ThingARN: a.cfg.thingARN,
		Fleet: map[string]*Device{}, Canary: map[string]bool{}, Excluded: map[string]bool{},
	}
	var meta groupMeta
	var err error
	if s.State, meta, err = a.groupState(ctx, p); err != nil {
		return nil, meta, err
	}

	fleet, err := a.groupThings(ctx, p.Fleet.Name, true)
	if err != nil {
		return nil, meta, err
	}
	for _, t := range fleet {
		d := &Device{Thing: t}
		if pr := g.presence[t]; pr != nil {
			cp := *pr
			d = &cp
		}
		s.Fleet[t] = d
	}
	for _, grp := range []struct {
		name string
		into map[string]bool
	}{{p.Canary.Name, s.Canary}, {p.Excluded.Name, s.Excluded}} {
		things, err := a.groupThings(ctx, grp.name, false)
		if err != nil {
			return nil, meta, err
		}
		for _, t := range things {
			grp.into[t] = true
		}
	}
	for _, r := range g.records {
		if r.Product == p.ID && r.Canary && r.Provisioned {
			s.Preferred = append(s.Preferred, r.Thing)
		}
	}
	sort.Strings(s.Preferred)

	floor := s.State.FleetVersion
	if opt.allVersions {
		floor = Version{}
	}
	if s.Releases, s.Bad, err = a.releases(ctx, p, floor, opt.allVersions); err != nil {
		return nil, meta, err
	}

	for _, js := range g.jobs {
		raw := aws.ToString(js.JobId)
		id, ok := ParseJobID(raw, a.cfg.Products)
		if !ok || id.Product != p.ID {
			continue
		}
		s.Jobs = append(s.Jobs, &Job{ID: id, RawID: raw, Status: string(js.Status), CreatedAt: aws.ToTime(js.CreatedAt)})
	}
	if err := a.loadExecutions(ctx, s); err != nil {
		return nil, meta, err
	}

	pending := false
	for _, r := range s.Releases {
		pending = pending || s.State.FleetVersion.Less(r.Version)
	}
	if pending || opt.shadows {
		for _, d := range s.Fleet {
			if d.Shadow, err = a.platformShadow(ctx, d.Thing); err != nil {
				return nil, meta, err
			}
		}
	}

	if opt.orphans {
		s.Orphans = a.orphans(ctx, p, s)
	}
	return s, meta, nil
}

// loadExecutions loads the executions the planner looks into: every active
// job's, the newest canary job's of each version above the fleet's, and the
// newest target job's of each thing at the fleet version (a fleet device's
// download retry).
func (a *App) loadExecutions(ctx context.Context, s *Snapshot) error {
	newestCanary := map[Version]*Job{}
	newestTarget := map[string]*Job{}
	for _, j := range s.Jobs {
		switch {
		case j.ID.Legacy:
		case j.ID.Kind == KindCanary && s.State.FleetVersion.Less(j.ID.Version):
			if cur := newestCanary[j.ID.Version]; cur == nil || cur.ID.Rerun < j.ID.Rerun {
				newestCanary[j.ID.Version] = j
			}
		case j.ID.Kind == KindTarget && j.ID.Version == s.State.FleetVersion:
			if cur := newestTarget[j.ID.Thing]; cur == nil || cur.ID.Rerun < j.ID.Rerun {
				newestTarget[j.ID.Thing] = j
			}
		}
	}
	for _, j := range s.Jobs {
		if j.ID.Legacy || (!j.active() && newestCanary[j.ID.Version] != j && newestTarget[j.ID.Thing] != j) {
			continue
		}
		p := iot.NewListJobExecutionsForJobPaginator(a.iot, &iot.ListJobExecutionsForJobInput{JobId: aws.String(j.RawID), MaxResults: aws.Int32(250)})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return fmt.Errorf("listing executions of %s: %w", j.RawID, err)
			}
			for _, sum := range page.ExecutionSummaries {
				thing := aws.ToString(sum.ThingArn)
				thing = thing[strings.LastIndexByte(thing, '/')+1:]
				e := Exec{Thing: thing}
				if es := sum.JobExecutionSummary; es != nil {
					e.Status = string(es.Status)
					e.QueuedAt = aws.ToTime(es.QueuedAt)
					e.LastUpdatedAt = aws.ToTime(es.LastUpdatedAt)
				}
				if e.failed() {
					out, err := a.iot.DescribeJobExecution(ctx, &iot.DescribeJobExecutionInput{JobId: aws.String(j.RawID), ThingName: aws.String(thing)})
					if err != nil {
						return fmt.Errorf("describing %s on %s: %w", j.RawID, thing, err)
					}
					if out.Execution != nil && out.Execution.StatusDetails != nil {
						e.Reason = attrSafe(out.Execution.StatusDetails.DetailsMap["reason"])
					}
				}
				j.Execs = append(j.Execs, e)
			}
		}
	}
	return nil
}

// platformShadow reads a device's `platform` shadow; nil when it has none.
func (a *App) platformShadow(ctx context.Context, thing string) (*Shadow, error) {
	out, err := a.shadow.GetThingShadow(ctx, &iotdataplane.GetThingShadowInput{ThingName: aws.String(thing), ShadowName: aws.String("platform")})
	if err != nil {
		var missing *iotdatatypes.ResourceNotFoundException
		if errors.As(err, &missing) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading the platform shadow of %s: %w", thing, err)
	}
	return parseShadow(out.Payload), nil
}

func parseShadow(payload []byte) *Shadow {
	var doc struct {
		State struct {
			Reported struct {
				FW        string   `json:"fw"`
				Boot      string   `json:"boot_reason"`
				BootCount int      `json:"boot_count_since_update"`
				KeyIDs    []string `json:"key_id"`
			} `json:"reported"`
		} `json:"state"`
		Metadata struct {
			Reported struct {
				FW struct {
					Timestamp int64 `json:"timestamp"`
				} `json:"fw"`
			} `json:"reported"`
		} `json:"metadata"`
	}
	if json.Unmarshal(payload, &doc) != nil || doc.State.Reported.FW == "" {
		return nil
	}
	r := doc.State.Reported
	return &Shadow{
		FW: r.FW, BootReason: r.Boot, BootCount: r.BootCount, KeyIDs: r.KeyIDs,
		ReportedAt: time.Unix(doc.Metadata.Reported.FW.Timestamp, 0),
	}
}

// ---------------------------------------------------------------------------
// Releases.
// ---------------------------------------------------------------------------

func (a *App) object(ctx context.Context, key string) ([]byte, error) {
	out, err := a.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(a.cfg.Bucket), Key: aws.String(key)})
	if err != nil {
		return nil, err
	}
	defer func() { _ = out.Body.Close() }()
	return io.ReadAll(io.LimitReader(out.Body, 64<<10))
}

func isNotFound(err error) bool {
	var nsk *s3types.NoSuchKey
	var nf *s3types.NotFound
	return errors.As(err, &nsk) || errors.As(err, &nf)
}

// releases lists releases/<p>/<X.Y.Z>/ and verifies every version above
// floor (or all): the manifest must be canonical, signed by one of the
// product's keys, and name this product and this version; app.bin must have
// the manifest's size. A directory without manifest.sig is an upload in
// progress (the release workflow writes it last) and is skipped.
func (a *App) releases(ctx context.Context, p ProductConfig, floor Version, all bool) ([]Release, []BadRelease, error) {
	prefix := "releases/" + p.ID + "/"
	var dirs []string
	pg := s3.NewListObjectsV2Paginator(a.s3, &s3.ListObjectsV2Input{Bucket: aws.String(a.cfg.Bucket), Prefix: aws.String(prefix), Delimiter: aws.String("/")})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("listing %s: %w", prefix, err)
		}
		for _, cp := range page.CommonPrefixes {
			dirs = append(dirs, strings.TrimSuffix(strings.TrimPrefix(aws.ToString(cp.Prefix), prefix), "/"))
		}
	}

	var ring Keyring
	var ringErr error
	ringLoaded := false
	var good []Release
	var bad []BadRelease
	for _, dir := range dirs {
		v, err := ParseVersion(dir)
		if err != nil || v.String() != dir {
			bad = append(bad, BadRelease{Version: attrSafe(dir), Reason: "not a bare X.Y.Z directory"})
			continue
		}
		if !all && !floor.Less(v) {
			continue
		}
		base := prefix + dir + "/"
		sig, err := a.object(ctx, base+"manifest.sig")
		if isNotFound(err) {
			continue
		} else if err != nil {
			return nil, nil, fmt.Errorf("reading %smanifest.sig: %w", base, err)
		}
		if !ringLoaded {
			ring, ringErr = a.keyring(ctx, p.ID)
			ringLoaded = true
		}
		reject := func(format string, args ...any) {
			bad = append(bad, BadRelease{Version: dir, Reason: fmt.Sprintf(format, args...)})
		}
		if ringErr != nil {
			reject("%v", ringErr)
			continue
		}
		manifest, err := a.object(ctx, base+"manifest.json")
		if err != nil {
			reject("manifest.json: %v", err)
			continue
		}
		keyID, err := ring.Verify(manifest, string(sig))
		if err != nil {
			reject("%v", err)
			continue
		}
		m, err := ParseManifest(manifest)
		switch {
		case err != nil:
			reject("%v", err)
			continue
		case m.Product != p.ID:
			reject("the manifest is for product %q", m.Product)
			continue
		case m.Version != dir:
			reject("the manifest is for version %s", m.Version)
			continue
		}
		head, err := a.s3.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(a.cfg.Bucket), Key: aws.String(base + "app.bin")})
		if err != nil {
			reject("app.bin: %v", err)
			continue
		}
		if aws.ToInt64(head.ContentLength) != m.Size {
			reject("app.bin is %d bytes, the manifest says %d", aws.ToInt64(head.ContentLength), m.Size)
			continue
		}
		good = append(good, Release{Version: v, Manifest: string(manifest), Sig: strings.TrimSpace(string(sig)), KeyID: keyID})
	}
	sort.Slice(good, func(i, j int) bool { return good[i].Version.Less(good[j].Version) })
	return good, bad, nil
}

func (a *App) keyring(ctx context.Context, product string) (Keyring, error) {
	name := a.cfg.signingKeysParameter(product)
	out, err := a.ssm.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(name)})
	if err != nil {
		var missing *ssmtypes.ParameterNotFound
		if errors.As(err, &missing) {
			return nil, fmt.Errorf("no signing keys: SSM %s does not exist", name)
		}
		return nil, fmt.Errorf("reading %s: %w", name, err)
	}
	return ParseKeyring(aws.ToString(out.Parameter.Value))
}

// orphans are GitHub releases of the release workflow (they carry a
// manifest.sig asset, uploaded before S3) above the fleet version, older than
// an hour, whose manifest never reached S3 (a publish that failed after the
// tag). Full releases and the pre-releases of older workflows alike: the
// GitHub status means nothing to the rollout. Releases from before the
// workflow carry no manifest.sig and are not reported. Best effort: the unauthenticated API is rate limited, and
// errors are only logged.
func (a *App) orphans(ctx context.Context, p ProductConfig, s *Snapshot) []string {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/"+p.Repository+"/releases?per_page=20", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "iot-platform-ota-controller")
	resp, err := a.http.Do(req)
	if err != nil {
		slog.Warn("GitHub releases unavailable", "product", p.ID, "error", err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		slog.Warn("GitHub releases unavailable", "product", p.ID, "status", resp.StatusCode)
		return nil
	}
	var rels []struct {
		Tag       string    `json:"tag_name"`
		Draft     bool      `json:"draft"`
		CreatedAt time.Time `json:"created_at"`
		Assets    []struct {
			Name string `json:"name"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rels); err != nil {
		slog.Warn("GitHub releases unreadable", "product", p.ID, "error", err)
		return nil
	}
	known := map[string]bool{}
	for _, r := range s.Releases {
		known[r.Version.String()] = true
	}
	for _, b := range s.Bad {
		known[b.Version] = true
	}
	var out []string
	for _, r := range rels {
		v, err := ParseVersion(r.Tag)
		if err != nil || r.Draft || s.Now.Sub(r.CreatedAt) < time.Hour ||
			!s.State.FleetVersion.Less(v) || known[v.String()] {
			continue
		}
		signed := false
		for _, as := range r.Assets {
			signed = signed || as.Name == "manifest.sig"
		}
		if !signed {
			continue
		}
		out = append(out, v.String())
	}
	return out
}

// ---------------------------------------------------------------------------
// Executing a plan.
// ---------------------------------------------------------------------------

// jobDocument is the job document: the contract v1 fields and, always, the
// v1.1 signed manifest. Every image is signed-only (plan Phase 6) and refuses
// a job without it.
func (a *App) jobDocument(p ProductConfig, j *NewJob) (string, error) {
	doc := map[string]any{
		"operation":        "firmware_update",
		"product":          p.ID,
		"firmware_version": j.Release.Version.String(),
		"download_url":     a.cfg.downloadURL(p, j.Release.Version),
		"contract":         1,
		"manifest":         j.Release.Manifest,
		"sig":              j.Release.Sig,
		"key_id":           j.Release.KeyID,
	}
	if j.Downgrade {
		doc["downgrade"] = true
	}
	b, err := json.Marshal(doc)
	return string(b), err
}

func (a *App) createJobInput(p ProductConfig, j *NewJob) (*iot.CreateJobInput, error) {
	doc, err := a.jobDocument(p, j)
	if err != nil {
		return nil, err
	}
	in := &iot.CreateJobInput{
		JobId:           aws.String(j.ID.String()),
		Targets:         j.Targets,
		Document:        aws.String(doc),
		Description:     aws.String(fmt.Sprintf("OTA %s %s (%s)", p.ID, j.Release.Version, map[string]string{KindCanary: "canary", KindFleet: "fleet", KindTarget: "target"}[j.ID.Kind])),
		TargetSelection: iottypes.TargetSelectionSnapshot,
		TimeoutConfig:   &iottypes.TimeoutConfig{InProgressTimeoutInMinutes: aws.Int64(a.cfg.InProgressTimeoutMinutes)},
		// A device that went quiet mid-update gets two more chances. A FAILED
		// execution is final: its reason decides (halt, exclusion, rerun).
		JobExecutionsRetryConfig: &iottypes.JobExecutionsRetryConfig{
			CriteriaList: []iottypes.RetryCriteria{{FailureType: iottypes.RetryableFailureTypeTimedOut, NumberOfRetries: aws.Int32(2)}},
		},
	}
	if j.Continuous {
		in.TargetSelection = iottypes.TargetSelectionContinuous
		in.JobExecutionsRolloutConfig = &iottypes.JobExecutionsRolloutConfig{
			ExponentialRate: &iottypes.ExponentialRolloutRate{
				BaseRatePerMinute:    aws.Int32(a.cfg.RolloutBaseRatePerMinute),
				IncrementFactor:      aws.Float64(a.cfg.RolloutIncrementFactor),
				RateIncreaseCriteria: &iottypes.RateIncreaseCriteria{NumberOfSucceededThings: aws.Int32(a.cfg.RolloutSucceededThings)},
			},
			MaximumPerMinute: aws.Int32(a.cfg.RolloutMaxPerMinute),
		}
	}
	return in, nil
}

// execute runs a plan's actions in order and stops at the first failure: the
// next tick replans from what actually happened. Every step is idempotent.
func (a *App) execute(ctx context.Context, s *Snapshot, meta groupMeta, plan Plan) error {
	p := s.Product
	for _, act := range plan.Actions {
		var err error
		switch act.Kind {
		case ActCreateJob:
			in, ierr := a.createJobInput(p, act.Job)
			if ierr != nil {
				return ierr
			}
			_, err = a.iot.CreateJob(ctx, in)
			var exists *iottypes.ResourceAlreadyExistsException
			if errors.As(err, &exists) {
				err = nil
			}
		case ActCancelJob:
			_, err = a.iot.CancelJob(ctx, &iot.CancelJobInput{JobId: aws.String(act.JobID), ReasonCode: aws.String("SUPERSEDED"), Comment: aws.String(truncate(act.Comment, 2028))})
			var gone *iottypes.ResourceNotFoundException
			if errors.As(err, &gone) {
				err = nil
			}
		case ActCancelExecution:
			_, err = a.iot.CancelJobExecution(ctx, &iot.CancelJobExecutionInput{JobId: aws.String(act.JobID), ThingName: aws.String(act.Thing)})
			var bad *iottypes.InvalidStateTransitionException
			if errors.As(err, &bad) {
				err = nil // already ended
			}
		case ActMove:
			_, err = a.iot.UpdateThingGroupsForThing(ctx, &iot.UpdateThingGroupsForThingInput{
				ThingName: aws.String(act.Thing), ThingGroupsToAdd: act.Add, ThingGroupsToRemove: act.Remove,
			})
		case ActNotify:
			err = a.notify(ctx, act.Subject, act.Body)
		case ActSaveState:
			_, err = a.iot.UpdateThingGroup(ctx, &iot.UpdateThingGroupInput{
				ThingGroupName: aws.String(p.Fleet.Name),
				ThingGroupProperties: &iottypes.ThingGroupProperties{
					ThingGroupDescription: aws.String(meta.description),
					AttributePayload:      &iottypes.AttributePayload{Attributes: plan.State.attributes(), Merge: true},
				},
				ExpectedVersion: aws.Int64(meta.version),
			})
		}
		if err != nil {
			return fmt.Errorf("%s: %s: %w", p.ID, Plan{Actions: []Action{act}}, err)
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// notify emails the owner through the OTA topic. Subjects are ASCII, at most
// 100 characters; device-reported text only ever reaches the body.
func (a *App) notify(ctx context.Context, subject, body string) error {
	subject = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return ' '
		}
		return r
	}, subject)
	_, err := a.sns.Publish(ctx, &sns.PublishInput{
		TopicArn: aws.String(a.cfg.TopicARN),
		Subject:  aws.String(truncate("IoT OTA: "+subject, 100)),
		Message:  aws.String(body + "\n\n-- iot-platform ota-controller"),
	})
	if err != nil {
		return fmt.Errorf("publishing %q: %w", subject, err)
	}
	slog.Info("Notified", "subject", subject)
	return nil
}
