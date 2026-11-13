package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	iottypes "github.com/aws/aws-sdk-go-v2/service/iot/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// ---- fakes -----------------------------------------------------------------

type fakeS3 struct {
	S3API
	objects map[string][]byte
}

func (f *fakeS3) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	prefix := aws.ToString(in.Prefix)
	seen := map[string]bool{}
	out := &s3.ListObjectsV2Output{}
	for k := range f.objects {
		rest, ok := strings.CutPrefix(k, prefix)
		if !ok {
			continue
		}
		if dir, _, nested := strings.Cut(rest, "/"); nested && !seen[dir] {
			seen[dir] = true
			out.CommonPrefixes = append(out.CommonPrefixes, s3types.CommonPrefix{Prefix: aws.String(prefix + dir + "/")})
		}
	}
	sort.Slice(out.CommonPrefixes, func(i, j int) bool {
		return *out.CommonPrefixes[i].Prefix < *out.CommonPrefixes[j].Prefix
	})
	return out, nil
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	b, ok := f.objects[aws.ToString(in.Key)]
	if !ok {
		return nil, &s3types.NoSuchKey{}
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(b))}, nil
}

func (f *fakeS3) HeadObject(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	b, ok := f.objects[aws.ToString(in.Key)]
	if !ok {
		return nil, &s3types.NotFound{}
	}
	return &s3.HeadObjectOutput{ContentLength: aws.Int64(int64(len(b)))}, nil
}

type fakeSSM struct {
	SSMAPI
	params map[string]string
	puts   []string
}

func (f *fakeSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	v, ok := f.params[aws.ToString(in.Name)]
	if !ok {
		return nil, &ssmtypes.ParameterNotFound{}
	}
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: aws.String(v)}}, nil
}

func (f *fakeSSM) PutParameter(_ context.Context, in *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	f.params[aws.ToString(in.Name)] = aws.ToString(in.Value)
	f.puts = append(f.puts, aws.ToString(in.Name))
	return &ssm.PutParameterOutput{}, nil
}

type fakeSNS struct {
	SNSAPI
	subjects []string
}

func (f *fakeSNS) Publish(_ context.Context, in *sns.PublishInput, _ ...func(*sns.Options)) (*sns.PublishOutput, error) {
	f.subjects = append(f.subjects, aws.ToString(in.Subject))
	return &sns.PublishOutput{}, nil
}

type fakeDDB struct {
	DynamoAPI
	tables map[string][]map[string]ddbtypes.AttributeValue
}

func (f *fakeDDB) Scan(_ context.Context, in *dynamodb.ScanInput, _ ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
	return &dynamodb.ScanOutput{Items: f.tables[aws.ToString(in.TableName)]}, nil
}

// fakeIoT models certificates and the claim policy's targets.
type fakeIoT struct {
	IoTAPI
	certs   map[string]iottypes.CertificateStatus
	targets []string // claim policy target ARNs
	calls   []string
	nextID  int
	// execs: job id -> thing -> status (and reason, for failures).
	execs  map[string]map[string][2]string
	listed []string // jobs whose executions were listed
}

func (f *fakeIoT) ListJobExecutionsForJob(_ context.Context, in *iot.ListJobExecutionsForJobInput, _ ...func(*iot.Options)) (*iot.ListJobExecutionsForJobOutput, error) {
	id := aws.ToString(in.JobId)
	f.listed = append(f.listed, id)
	out := &iot.ListJobExecutionsForJobOutput{}
	for thing, st := range f.execs[id] {
		out.ExecutionSummaries = append(out.ExecutionSummaries, iottypes.JobExecutionSummaryForJob{
			ThingArn:            aws.String("arn:aws:iot:eu-central-1:1:thing/" + thing),
			JobExecutionSummary: &iottypes.JobExecutionSummary{Status: iottypes.JobExecutionStatus(st[0])},
		})
	}
	return out, nil
}

func (f *fakeIoT) DescribeJobExecution(_ context.Context, in *iot.DescribeJobExecutionInput, _ ...func(*iot.Options)) (*iot.DescribeJobExecutionOutput, error) {
	st := f.execs[aws.ToString(in.JobId)][aws.ToString(in.ThingName)]
	return &iot.DescribeJobExecutionOutput{Execution: &iottypes.JobExecution{
		StatusDetails: &iottypes.JobExecutionStatusDetails{DetailsMap: map[string]string{"reason": st[1]}},
	}}, nil
}

func certARN(id string) string { return "arn:aws:iot:eu-central-1:111122223333:cert/" + id }

func (f *fakeIoT) ListTargetsForPolicy(context.Context, *iot.ListTargetsForPolicyInput, ...func(*iot.Options)) (*iot.ListTargetsForPolicyOutput, error) {
	return &iot.ListTargetsForPolicyOutput{Targets: append([]string(nil), f.targets...)}, nil
}

func (f *fakeIoT) DescribeCertificate(_ context.Context, in *iot.DescribeCertificateInput, _ ...func(*iot.Options)) (*iot.DescribeCertificateOutput, error) {
	return &iot.DescribeCertificateOutput{CertificateDescription: &iottypes.CertificateDescription{Status: f.certs[aws.ToString(in.CertificateId)]}}, nil
}

func (f *fakeIoT) UpdateCertificate(_ context.Context, in *iot.UpdateCertificateInput, _ ...func(*iot.Options)) (*iot.UpdateCertificateOutput, error) {
	id := aws.ToString(in.CertificateId)
	f.certs[id] = in.NewStatus
	f.calls = append(f.calls, fmt.Sprintf("update %.6s %s", id, in.NewStatus))
	return &iot.UpdateCertificateOutput{}, nil
}

func (f *fakeIoT) CreateCertificateFromCsr(_ context.Context, in *iot.CreateCertificateFromCsrInput, _ ...func(*iot.Options)) (*iot.CreateCertificateFromCsrOutput, error) {
	if !strings.Contains(aws.ToString(in.CertificateSigningRequest), "CERTIFICATE REQUEST") || in.SetAsActive {
		return nil, fmt.Errorf("bad request")
	}
	f.nextID++
	pemText, id := testCert(f.nextID)
	f.certs[id] = iottypes.CertificateStatusInactive
	f.calls = append(f.calls, "create")
	return &iot.CreateCertificateFromCsrOutput{CertificateId: aws.String(id), CertificateArn: aws.String(certARN(id)), CertificatePem: aws.String(pemText)}, nil
}

func (f *fakeIoT) AttachPolicy(_ context.Context, in *iot.AttachPolicyInput, _ ...func(*iot.Options)) (*iot.AttachPolicyOutput, error) {
	f.targets = append(f.targets, aws.ToString(in.Target))
	f.calls = append(f.calls, "attach")
	return &iot.AttachPolicyOutput{}, nil
}

func (f *fakeIoT) DetachPolicy(_ context.Context, in *iot.DetachPolicyInput, _ ...func(*iot.Options)) (*iot.DetachPolicyOutput, error) {
	var keep []string
	for _, t := range f.targets {
		if t != aws.ToString(in.Target) {
			keep = append(keep, t)
		}
	}
	f.targets = keep
	f.calls = append(f.calls, "detach")
	return &iot.DetachPolicyOutput{}, nil
}

func (f *fakeIoT) DeleteCertificate(_ context.Context, in *iot.DeleteCertificateInput, _ ...func(*iot.Options)) (*iot.DeleteCertificateOutput, error) {
	id := aws.ToString(in.CertificateId)
	if f.certs[id] != iottypes.CertificateStatusInactive {
		return nil, fmt.Errorf("deleting an active certificate")
	}
	delete(f.certs, id)
	f.calls = append(f.calls, fmt.Sprintf("delete %.6s", id))
	return &iot.DeleteCertificateOutput{}, nil
}

// testCert is a fixed self-signed certificate PEM per n, and its IoT id.
func testCert(n int) (string, string) {
	pemText := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n",
		strings.Repeat(fmt.Sprintf("QUJD%04d", n), 8))
	id, err := certID(pemText)
	if err != nil {
		panic(err)
	}
	return pemText, id
}

// ---- app -------------------------------------------------------------------

func testConfig() Config {
	return Config{
		Region: "eu-central-1", Account: "111122223333", Bucket: "fw",
		Products:            map[string]ProductConfig{"vaktus": vaktus},
		DownloadURLTemplate: "https://d111.cloudfront.net/{product}/{version}/app.bin",
		RegistryTable:       "registry", PresenceTable: "presence",
		GuardStateParameter: "/guard", SigningKeysParameter: "/iot-platform/products/{product}/signing_keys",
		ClaimPolicy:        "claim-policy",
		ClaimCertParameter: "/iot-platform/claim/cert", ClaimKeyParameter: "/iot-platform/claim/key",
		ClaimStateParameter:      "/iot-platform/claim/state",
		InProgressTimeoutMinutes: 60,
		Quarantine:               Group{Name: "esp32-ztp-quarantine", ARN: "arn:aws:iot:eu-central-1:111122223333:thinggroup/esp32-ztp-quarantine"},
		DenyPolicy:               "deny-all",
		RestoreRules:             []string{"esp32_ztp_presence"},
		ViewerRoles:              []string{"esp32-ztp-portal-viewer"},
	}
}

func testApp() (*App, *fakeS3, *fakeSSM, *fakeIoT, *fakeSNS, *fakeDDB) {
	s3f := &fakeS3{objects: map[string][]byte{}}
	ssmf := &fakeSSM{params: map[string]string{"/guard": `{"tripped":false}`}}
	iotf := &fakeIoT{certs: map[string]iottypes.CertificateStatus{}}
	snsf := &fakeSNS{}
	ddbf := &fakeDDB{tables: map[string][]map[string]ddbtypes.AttributeValue{}}
	a := &App{cfg: testConfig(), s3: s3f, ssm: ssmf, iot: iotf, sns: snsf, ddb: ddbf, now: func() time.Time { return t0 }}
	return a, s3f, ssmf, iotf, snsf, ddbf
}

// publish puts a release the way the release workflow does.
func publish(t *testing.T, f *fakeS3, sign func([]byte) string, dir, product, version string, image []byte) {
	t.Helper()
	m := fmt.Sprintf(`{"contract":1,"factory_sha256":"%s","product":"%s","sha256":"%s","size":%d,"version":"%s"}`,
		strings.Repeat("ab", 32), product, strings.Repeat("cd", 32), len(image), version)
	base := "releases/vaktus/" + dir + "/"
	f.objects[base+"app.bin"] = image
	f.objects[base+"manifest.json"] = []byte(m)
	if sign != nil {
		f.objects[base+"manifest.sig"] = []byte(sign([]byte(m)) + "\n")
	}
}

// Exit criterion 4: unsigned or renamed uploads are refused.
func TestReleasesAreVerified(t *testing.T) {
	a, s3f, ssmf, _, _, _ := testApp()
	key, pub := testKey(t)
	foreign, _ := testKey(t)
	ring, _ := json.Marshal(map[string]string{"vaktus-a": pub})
	ssmf.params["/iot-platform/products/vaktus/signing_keys"] = string(ring)
	good := func(m []byte) string { return sign(t, key, m) }

	publish(t, s3f, good, "0.9.1", "vaktus", "0.9.1", []byte("old"))    // at the floor: not looked at
	publish(t, s3f, good, "0.9.2", "vaktus", "0.9.2", []byte("image"))  // good
	publish(t, s3f, good, "0.9.3", "vaktus", "0.9.2", []byte("image"))  // renamed: signed for 0.9.2
	publish(t, s3f, good, "0.9.4", "gateway", "0.9.4", []byte("image")) // another product's
	publish(t, s3f, func(m []byte) string { return sign(t, foreign, m) }, "0.9.5", "vaktus", "0.9.5", []byte("x"))
	publish(t, s3f, nil, "0.9.6", "vaktus", "0.9.6", []byte("x")) // upload in progress
	publish(t, s3f, good, "0.9.7", "vaktus", "0.9.7", []byte("x"))
	s3f.objects["releases/vaktus/0.9.7/app.bin"] = []byte("swapped image") // size differs
	publish(t, s3f, good, "latest", "vaktus", "0.9.8", []byte("x"))

	got, bad, err := a.releases(context.Background(), vaktus, ver("0.9.1"), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Version != ver("0.9.2") || got[0].KeyID != "vaktus-a" || got[0].Sig == "" {
		t.Fatalf("verified: %+v", got)
	}
	reasons := map[string]string{}
	for _, b := range bad {
		reasons[b.Version] = b.Reason
	}
	for v, want := range map[string]string{
		"0.9.3": "version 0.9.2", "0.9.4": `product "gateway"`, "0.9.5": "verifies with none",
		"0.9.7": "manifest says", "latest": "X.Y.Z",
	} {
		if !strings.Contains(reasons[v], want) {
			t.Errorf("%s: %q, want %q", v, reasons[v], want)
		}
	}
	if _, ok := reasons["0.9.6"]; ok || len(bad) != 5 {
		t.Errorf("bad: %+v", bad)
	}

	// No signing keys in SSM: nothing verifies.
	delete(ssmf.params, "/iot-platform/products/vaktus/signing_keys")
	got, bad, _ = a.releases(context.Background(), vaktus, ver("0.9.1"), false)
	if len(got) != 0 || !strings.Contains(bad[0].Reason, "no signing keys") {
		t.Errorf("no keys: %+v %+v", got, bad)
	}
}

func TestJobDocument(t *testing.T) {
	a, _, _, _, _, _ := testApp()
	r := rel("0.9.2")
	plain, _ := a.jobDocument(vaktus, &NewJob{Release: r})
	down, _ := a.jobDocument(vaktus, &NewJob{Release: r, Downgrade: true})
	var u, d map[string]any
	_ = json.Unmarshal([]byte(plain), &u)
	_ = json.Unmarshal([]byte(down), &d)
	// Every document is signed: the images refuse anything else.
	if u["operation"] != "firmware_update" || u["product"] != "vaktus" || u["firmware_version"] != "0.9.2" ||
		u["download_url"] != "https://d111.cloudfront.net/vaktus/0.9.2/app.bin" || u["downgrade"] != nil ||
		u["manifest"] != r.Manifest || u["sig"] != r.Sig || u["key_id"] != "vaktus-a" {
		t.Errorf("job document %s", plain)
	}
	if d["downgrade"] != true || d["manifest"] != r.Manifest {
		t.Errorf("downgrade %s", down)
	}
	in, _ := a.createJobInput(vaktus, &NewJob{ID: JobID{Product: "vaktus", Version: r.Version, Kind: KindFleet}, Release: r, Continuous: true})
	if in.TargetSelection != iottypes.TargetSelectionContinuous || in.JobExecutionsRolloutConfig == nil || in.PresignedUrlConfig != nil {
		t.Errorf("fleet job input %+v", in)
	}
}

// The planner sees a fleet device's download retry: the newest target job of
// each thing at the fleet version, finished or not.
func TestLoadExecutionsIncludesTheNewestRetry(t *testing.T) {
	a, _, _, iotf, _, _ := testApp()
	iotf.execs = map[string]map[string][2]string{
		"ota-vaktus-0_9_1-f":       {"C1": {"FAILED", "download"}},
		"ota-vaktus-0_9_1-t-C1-r1": {"C1": {"SUCCEEDED", ""}},
	}
	s := fixture()
	s.Jobs[0].Execs = nil
	addJob(s, "ota-vaktus-0_9_1-t-C1", JobCompleted, t0)
	addJob(s, "ota-vaktus-0_9_1-t-C1-r1", JobCompleted, t0)
	addJob(s, "ota-vaktus-0_9_0-t-C1", JobCompleted, t0) // another version
	addJob(s, "ota-vaktus-0_9_0-c", JobCompleted, t0)    // a canary below the fleet version
	if err := a.loadExecutions(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	eq(t, "listed", iotf.listed, []string{"ota-vaktus-0_9_1-f", "ota-vaktus-0_9_1-t-C1-r1"})
	if e := s.Jobs[0].Execs; len(e) != 1 || e[0].failureReason() != "download" {
		t.Errorf("fleet execs %+v", e)
	}
}

func TestShadowAndPresence(t *testing.T) {
	sh := parseShadow([]byte(`{"state":{"reported":{"fw":"0.9.2","boot_reason":"panic","boot_count_since_update":2,"key_id":["vaktus-a"]}},
		"metadata":{"reported":{"fw":{"timestamp":1763640000}}}}`))
	if sh == nil || sh.FW != "0.9.2" || !isCrash(sh.BootReason) || sh.BootCount != 2 || sh.ReportedAt.Unix() != 1763640000 {
		t.Fatalf("shadow %+v", sh)
	}
	if parseShadow([]byte(`{"state":{"reported":{}}}`)) != nil {
		t.Error("empty shadow parsed")
	}

	a, _, _, _, _, ddbf := testApp()
	item := func(thing, event string, at, session int64) map[string]ddbtypes.AttributeValue {
		return map[string]ddbtypes.AttributeValue{
			"thing": &ddbtypes.AttributeValueMemberS{Value: thing}, "event": &ddbtypes.AttributeValueMemberS{Value: event},
			"at": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprint(at)}, "session": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprint(session)},
			"principal": &ddbtypes.AttributeValueMemberS{Value: "cert-" + thing},
		}
	}
	ddbf.tables["presence"] = []map[string]ddbtypes.AttributeValue{
		item("UP", "connected", 2000, 5),
		item("UP", "disconnected", 3000, 4), // the old session's disconnect, delivered late
		item("DOWN", "connected", 1000, 7),
		item("DOWN", "disconnected", 1500, 7),
		item("NEW", "connected", 1000, 1),
	}
	p, err := a.loadPresence(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !p["UP"].Online || p["DOWN"].Online || !p["NEW"].Online || p["UP"].Principal != "cert-UP" {
		t.Errorf("presence UP=%+v DOWN=%+v NEW=%+v", p["UP"], p["DOWN"], p["NEW"])
	}
}

func registryItem(mac string, provisioned bool, enrolBy time.Time) map[string]ddbtypes.AttributeValue {
	return map[string]ddbtypes.AttributeValue{
		"mac_address": &ddbtypes.AttributeValueMemberS{Value: mac},
		"product":     &ddbtypes.AttributeValueMemberS{Value: "vaktus"},
		"allowed":     &ddbtypes.AttributeValueMemberBOOL{Value: true},
		"provisioned": &ddbtypes.AttributeValueMemberBOOL{Value: provisioned},
		"enrol_by":    &ddbtypes.AttributeValueMemberN{Value: fmt.Sprint(enrolBy.Unix())},
	}
}

func TestClaimLifecycle(t *testing.T) {
	ctx := context.Background()
	a, _, ssmf, iotf, snsf, ddbf := testApp()

	// First run after the migration: no claim in SSM, the old Terraform claim
	// attached. It is rotated: new INACTIVE claim, SSM written, old deleted.
	oldPEM, oldID := testCert(99)
	_ = oldPEM
	iotf.certs[oldID] = iottypes.CertificateStatusInactive
	iotf.targets = []string{certARN(oldID)}
	if err := a.claimTick(ctx, nil, false); err != nil {
		t.Fatal(err)
	}
	newPEM, newID := testCert(1)
	if ssmf.params["/iot-platform/claim/cert"] != newPEM || !strings.Contains(ssmf.params["/iot-platform/claim/key"], "EC PRIVATE KEY") {
		t.Fatalf("SSM after rotation: %v", ssmf.puts)
	}
	if _, left := iotf.certs[oldID]; left || len(iotf.targets) != 1 || iotf.targets[0] != certARN(newID) || iotf.certs[newID] != iottypes.CertificateStatusInactive {
		t.Fatalf("certs %v targets %v calls %v", iotf.certs, iotf.targets, iotf.calls)
	}
	if len(snsf.subjects) != 1 || !strings.Contains(snsf.subjects[0], "claim rotated") {
		t.Errorf("emails %v", snsf.subjects)
	}

	// A site window opens: the tick arms the claim and remembers to rotate.
	records := []Record{{Thing: "AABBCCDDEEFF", Product: "vaktus", Allowed: true, EnrolBy: t0.Add(48 * time.Hour)}}
	if err := a.claimTick(ctx, records, false); err != nil {
		t.Fatal(err)
	}
	if iotf.certs[newID] != iottypes.CertificateStatusActive || !strings.Contains(ssmf.params["/iot-platform/claim/state"], `"rotate_pending":true`) {
		t.Fatalf("arm: %v %s", iotf.certs, ssmf.params["/iot-platform/claim/state"])
	}

	// A trip disarms at once and arms nothing.
	if err := a.claimTick(ctx, records, true); err != nil {
		t.Fatal(err)
	}
	if iotf.certs[newID] != iottypes.CertificateStatusInactive {
		t.Fatal("tripped guard left the claim active")
	}

	// Rotation refuses while the window is open.
	ddbf.tables["registry"] = []map[string]ddbtypes.AttributeValue{registryItem("AA:BB:CC:DD:EE:FF", false, t0.Add(time.Hour))}
	if err := a.rotateClaim(ctx, "test"); err == nil || !strings.Contains(err.Error(), "AABBCCDDEEFF") {
		t.Fatalf("rotation during a window: %v", err)
	}

	// The window closes (the device enrolled): disarm and rotate.
	ddbf.tables["registry"] = []map[string]ddbtypes.AttributeValue{registryItem("AA:BB:CC:DD:EE:FF", true, t0.Add(time.Hour))}
	iotf.certs[newID] = iottypes.CertificateStatusActive
	if err := a.claimTick(ctx, nil, false); err != nil {
		t.Fatal(err)
	}
	_, thirdID := testCert(2)
	if _, left := iotf.certs[newID]; left || iotf.targets[0] != certARN(thirdID) || strings.Contains(ssmf.params["/iot-platform/claim/state"], `"rotate_pending":true`) {
		t.Fatalf("after window: certs %v targets %v state %s", iotf.certs, iotf.targets, ssmf.params["/iot-platform/claim/state"])
	}

	// Quiet: nothing open, nothing pending.
	before := len(iotf.calls)
	if err := a.claimTick(ctx, nil, false); err != nil || len(iotf.calls) != before {
		t.Fatalf("quiet tick changed something: %v %v", err, iotf.calls[before:])
	}
}

func TestS3EventRouting(t *testing.T) {
	a, _, _, _, _, _ := testApp()
	ignored := `{"Records":[{"eventSource":"aws:s3","s3":{"object":{"key":"releases/vaktus/0.9.2/app.bin"}}},
		{"eventSource":"aws:s3","s3":{"object":{"key":"releases/other/0.9.2/manifest.sig"}}}]}`
	r, err := a.Handle(context.Background(), json.RawMessage(ignored))
	if err != nil || !r.(Result).OK {
		t.Fatalf("ignored event: %v %v", r, err)
	}
	if _, err := a.Handle(context.Background(), json.RawMessage(`{"foo":1}`)); err == nil {
		t.Error("unrecognised event accepted")
	}
}

func TestLoadConfig(t *testing.T) {
	env := map[string]string{
		"AWS_REGION": "eu-central-1", "ACCOUNT_ID": "1", "FIRMWARE_BUCKET": "fw",
		"DOWNLOAD_URL_TEMPLATE": "https://d.cloudfront.net/{product}/{version}/app.bin",
		"REGISTRY_TABLE":        "r", "PRESENCE_TABLE": "p", "GUARD_STATE_PARAMETER": "/g",
		"SIGNING_KEYS_PARAMETER": "/iot-platform/products/{product}/signing_keys",
		"CLAIM_POLICY":           "c", "CLAIM_CERT_PARAMETER": "/c", "CLAIM_KEY_PARAMETER": "/k", "CLAIM_STATE_PARAMETER": "/s",
		"NOTIFY_TOPIC_ARN": "arn:aws:sns:eu-central-1:1:t", "IOT_DATA_ENDPOINT": "x-ats.iot.eu-central-1.amazonaws.com",
		"OTA_ROLLOUT_BASE_RATE_PER_MINUTE": "1", "OTA_ROLLOUT_INCREMENT_FACTOR": "2", "OTA_ROLLOUT_SUCCEEDED_THINGS": "5",
		"OTA_ROLLOUT_MAX_PER_MINUTE": "20", "OTA_IN_PROGRESS_TIMEOUT_MINUTES": "60",
		"QUARANTINE_GROUP_ARN": "arn:aws:iot:eu-central-1:1:thinggroup/q", "DENY_POLICY": "d",
		"RESTORE_RULES": `["r"]`, "VIEWER_ROLES": `[]`,
		"PRODUCTS": `{"vaktus":{"fleet_group_arn":"` + vaktus.Fleet.ARN + `","canary_group_arn":"` + vaktus.Canary.ARN +
			`","excluded_group_arn":"` + vaktus.Excluded.ARN + `","repository":"ergousha/x","soak_hours":24}}`,
	}
	c, err := loadConfig(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if c.Quarantine.Name != "q" || len(c.RestoreRules) != 1 || len(c.ViewerRoles) != 0 {
		t.Errorf("guard config %+v", c)
	}
	if c.Products["vaktus"].Canary.Name != "esp32-ztp-vaktus-canary" || c.downloadURL(c.Products["vaktus"], ver("1.2.3")) != "https://d.cloudfront.net/vaktus/1.2.3/app.bin" {
		t.Errorf("config %+v", c)
	}
	env["DOWNLOAD_URL_TEMPLATE"] = "http://insecure/{version}"
	env["PRODUCTS"] = `{"Bad":{}}`
	delete(env, "CLAIM_POLICY")
	env["VIEWER_ROLES"] = "viewer"
	_, err = loadConfig(func(k string) string { return env[k] })
	for _, want := range []string{"DOWNLOAD_URL_TEMPLATE", "Bad", "CLAIM_POLICY", "VIEWER_ROLES"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %s in %v", want, err)
		}
	}
}

type fakeHTTP struct{ body string }

func (f fakeHTTP) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(f.body))}, nil
}

// Only the release workflow's releases (with a manifest.sig), pre-release or
// not, can be orphans; a pre-release from before it, like vaktus v0.0.1, is
// not one.
func TestOrphansAreWorkflowReleasesMissingInS3(t *testing.T) {
	a, _, _, _, _, _ := testApp()
	old := t0.Add(-2 * time.Hour).Format(time.RFC3339)
	recent := t0.Add(-10 * time.Minute).Format(time.RFC3339)
	sig := `[{"name":"app.bin"},{"name":"manifest.sig"}]`
	a.http = fakeHTTP{body: `[
		{"tag_name":"v0.0.1","prerelease":true,"created_at":"` + old + `","assets":[]},
		{"tag_name":"v0.9.8","prerelease":true,"created_at":"` + old + `","assets":[]},
		{"tag_name":"v0.9.3","prerelease":true,"created_at":"` + old + `","assets":` + sig + `},
		{"tag_name":"v0.9.4","prerelease":true,"created_at":"` + recent + `","assets":` + sig + `},
		{"tag_name":"v0.9.5","prerelease":true,"created_at":"` + old + `","assets":` + sig + `},
		{"tag_name":"v0.9.6","prerelease":false,"created_at":"` + old + `","assets":` + sig + `},
		{"tag_name":"v0.9.7","draft":true,"prerelease":true,"created_at":"` + old + `","assets":` + sig + `},
		{"tag_name":"v0.9.1","prerelease":true,"created_at":"` + old + `","assets":` + sig + `}
	]`}
	s := &Snapshot{Now: t0}
	s.State.FleetVersion, _ = ParseVersion("0.9.2")
	v5, _ := ParseVersion("0.9.5")
	s.Releases = []Release{{Version: v5}}
	got := a.orphans(context.Background(), ProductConfig{ID: "vaktus", Repository: "ergousha/vaktus"}, s)
	if strings.Join(got, ",") != "0.9.3,0.9.6" {
		t.Fatalf("orphans %v, want [0.9.3 0.9.6]", got)
	}
}
