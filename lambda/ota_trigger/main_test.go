package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	iottypes "github.com/aws/aws-sdk-go-v2/service/iot/types"
)

// MockIoTClient is a mock of the IoTAPI interface that records the calls it receives.
type MockIoTClient struct {
	CreateJobFunc func(ctx context.Context, params *iot.CreateJobInput) (*iot.CreateJobOutput, error)
	ListJobsFunc  func(ctx context.Context, params *iot.ListJobsInput) (*iot.ListJobsOutput, error)
	CancelJobFunc func(ctx context.Context, params *iot.CancelJobInput) (*iot.CancelJobOutput, error)

	createJobCalls []*iot.CreateJobInput
	listJobsCalls  []*iot.ListJobsInput
	cancelJobCalls []*iot.CancelJobInput
}

func (m *MockIoTClient) CreateJob(ctx context.Context, params *iot.CreateJobInput, optFns ...func(*iot.Options)) (*iot.CreateJobOutput, error) {
	m.createJobCalls = append(m.createJobCalls, params)
	if m.CreateJobFunc != nil {
		return m.CreateJobFunc(ctx, params)
	}
	return &iot.CreateJobOutput{}, nil
}

func (m *MockIoTClient) ListJobs(ctx context.Context, params *iot.ListJobsInput, optFns ...func(*iot.Options)) (*iot.ListJobsOutput, error) {
	m.listJobsCalls = append(m.listJobsCalls, params)
	if m.ListJobsFunc != nil {
		return m.ListJobsFunc(ctx, params)
	}
	return &iot.ListJobsOutput{}, nil
}

func (m *MockIoTClient) CancelJob(ctx context.Context, params *iot.CancelJobInput, optFns ...func(*iot.Options)) (*iot.CancelJobOutput, error) {
	m.cancelJobCalls = append(m.cancelJobCalls, params)
	if m.CancelJobFunc != nil {
		return m.CancelJobFunc(ctx, params)
	}
	return &iot.CancelJobOutput{}, nil
}

func (m *MockIoTClient) cancelledIDs() []string {
	var ids []string
	for _, c := range m.cancelJobCalls {
		ids = append(ids, aws.ToString(c.JobId))
	}
	return ids
}

const (
	testGroupARN = "arn:aws:iot:eu-central-1:123456789012:thinggroup/esp32-ztp-fleet"
	testRoleARN  = "arn:aws:iam::123456789012:role/esp32-ztp-ota-presign-role"
)

// validEnv is a complete, valid Lambda environment.
func validEnv() map[string]string {
	return map[string]string{
		"AWS_REGION":                       "eu-central-1",
		"OTA_THING_GROUP_ARN":              testGroupARN,
		"OTA_PRESIGN_ROLE_ARN":             testRoleARN,
		"OTA_ROLLOUT_BASE_RATE_PER_MINUTE": "1",
		"OTA_ROLLOUT_INCREMENT_FACTOR":     "2",
		"OTA_ROLLOUT_SUCCEEDED_THINGS":     "5",
		"OTA_ROLLOUT_MAX_PER_MINUTE":       "20",
		"OTA_ABORT_FAILURE_PERCENTAGE":     "20",
		"OTA_ABORT_MIN_EXECUTED_THINGS":    "10",
		"OTA_IN_PROGRESS_TIMEOUT_MINUTES":  "30",
	}
}

// testConfig is what validEnv parses to.
func testConfig() OTAConfig {
	return OTAConfig{
		Region:                   "eu-central-1",
		ThingGroupARN:            testGroupARN,
		ThingGroupName:           "esp32-ztp-fleet",
		PresignRoleARN:           testRoleARN,
		RolloutBaseRatePerMinute: 1,
		RolloutIncrementFactor:   2,
		RolloutSucceededThings:   5,
		RolloutMaxPerMinute:      20,
		AbortFailurePercentage:   20,
		AbortMinExecutedThings:   10,
		InProgressTimeoutMinutes: 30,
	}
}

// Upload time of the test event, and the job ID it maps to.
var testUploadTime = time.UnixMilli(1790500000123).UTC()

const testJobID = "ota-firmware_v1-0-0-1790500000123"

func s3Event(key string) events.S3Event {
	return events.S3Event{
		Records: []events.S3EventRecord{
			{
				EventTime: testUploadTime,
				S3: events.S3Entity{
					Bucket: events.S3Bucket{Name: "test-bucket"},
					Object: events.S3Object{URLDecodedKey: key},
				},
			},
		},
	}
}

func jobSummaries(ids ...string) []iottypes.JobSummary {
	var jobs []iottypes.JobSummary
	for _, id := range ids {
		jobs = append(jobs, iottypes.JobSummary{JobId: aws.String(id), Status: iottypes.JobStatusInProgress})
	}
	return jobs
}

func TestBuildJobID(t *testing.T) {
	timestamp := int64(1700000000)
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "Simple version",
			version:  "v1.0.0",
			expected: "ota-v1-0-0-1700000000",
		},
		{
			name:     "Invalid characters replaced",
			version:  "release/v2.1.0-beta@foo",
			expected: "ota-release-v2-1-0-beta-foo-1700000000",
		},
		{
			name:     "Extremely long version truncated",
			version:  strings.Repeat("a", 100),
			expected: "ota-" + strings.Repeat("a", 49) + "-1700000000", // 64 - 4 (prefix) - 11 (suffix) = 49
		},
		{
			name:     "Empty version fallback",
			version:  "",
			expected: "ota-firmware-1700000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildJobID(tt.version, timestamp)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
			if len(result) > 64 {
				t.Errorf("job ID exceeds 64 chars: %s (len: %d)", result, len(result))
			}
		})
	}

	// A millisecond timestamp still fits.
	if id := buildJobID(strings.Repeat("a", 100), testUploadTime.UnixMilli()); len(id) != 64 {
		t.Errorf("expected a 64-char job ID, got %s (len: %d)", id, len(id))
	}
}

func TestJobOrdering(t *testing.T) {
	if ts, ok := jobTimestamp("ota-firmware_v0-1-0-1790540983"); !ok || ts != 1790540983 {
		t.Errorf("expected timestamp 1790540983, got %d (ok=%v)", ts, ok)
	}
	for _, id := range []string{"ota-hotfix", "otafirmware", "ota-v1-"} {
		if _, ok := jobTimestamp(id); ok {
			t.Errorf("expected no timestamp in %q", id)
		}
	}

	if !newerJob("ota-a-2000", "ota-b-1000") {
		t.Error("expected the later upload to be newer")
	}
	if newerJob("ota-b-1000", "ota-a-2000") {
		t.Error("expected the earlier upload not to be newer")
	}
	// Same timestamp: the ID decides, the same way in either direction.
	if newerJob("ota-a-1000", "ota-b-1000") == newerJob("ota-b-1000", "ota-a-1000") {
		t.Error("expected a strict order between jobs with the same timestamp")
	}
}

func TestPresignedURLPlaceholder(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{
			name: "Release key unchanged",
			key:  "firmware_v0.1.0.bin",
			want: "${aws:iot:s3-presigned-url-v2:https://s3.eu-central-1.amazonaws.com/test-bucket/firmware_v0.1.0.bin}",
		},
		{
			name: "Reserved characters encoded, slashes kept",
			key:  "rc/fw v1+2}.bin",
			want: "${aws:iot:s3-presigned-url-v2:https://s3.eu-central-1.amazonaws.com/test-bucket/rc/fw%20v1%2B2%7D.bin}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := presignedURLPlaceholder("eu-central-1", "test-bucket", tt.key); got != tt.want {
				t.Errorf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	t.Run("Valid environment", func(t *testing.T) {
		env := validEnv()
		cfg, err := loadConfig(func(k string) string { return env[k] })
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(cfg, testConfig()) {
			t.Errorf("expected %+v, got %+v", testConfig(), cfg)
		}
	})

	t.Run("Fractional values", func(t *testing.T) {
		env := validEnv()
		env["OTA_ROLLOUT_INCREMENT_FACTOR"] = "1.5"
		env["OTA_ABORT_FAILURE_PERCENTAGE"] = "12.25"
		cfg, err := loadConfig(func(k string) string { return env[k] })
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.RolloutIncrementFactor != 1.5 || cfg.AbortFailurePercentage != 12.25 {
			t.Errorf("unexpected values: %+v", cfg)
		}
	})

	tests := []struct {
		name    string
		key     string
		value   string // "" unsets the variable
		wantErr string
	}{
		{"Missing thing group", "OTA_THING_GROUP_ARN", "", "OTA_THING_GROUP_ARN is not set"},
		{"Thing group not an ARN", "OTA_THING_GROUP_ARN", "esp32-ztp-fleet", "OTA_THING_GROUP_ARN"},
		{"Thing group ARN of a thing", "OTA_THING_GROUP_ARN", "arn:aws:iot:eu-central-1:123456789012:thing/28848553144F", "OTA_THING_GROUP_ARN"},
		{"Thing group ARN without a name", "OTA_THING_GROUP_ARN", "arn:aws:iot:eu-central-1:123456789012:thinggroup/", "OTA_THING_GROUP_ARN"},
		{"Thing group ARN of another service", "OTA_THING_GROUP_ARN", "arn:aws:s3:eu-central-1:123456789012:thinggroup/x", "OTA_THING_GROUP_ARN"},
		{"Missing presign role", "OTA_PRESIGN_ROLE_ARN", "", "OTA_PRESIGN_ROLE_ARN is not set"},
		{"Presign role ARN of a user", "OTA_PRESIGN_ROLE_ARN", "arn:aws:iam::123456789012:user/someone", "OTA_PRESIGN_ROLE_ARN"},
		{"Missing region", "AWS_REGION", "", "AWS_REGION is not set"},
		{"Base rate zero", "OTA_ROLLOUT_BASE_RATE_PER_MINUTE", "0", "OTA_ROLLOUT_BASE_RATE_PER_MINUTE"},
		{"Base rate above API maximum", "OTA_ROLLOUT_BASE_RATE_PER_MINUTE", "1001", "OTA_ROLLOUT_BASE_RATE_PER_MINUTE"},
		{"Base rate not an integer", "OTA_ROLLOUT_BASE_RATE_PER_MINUTE", "1.5", "OTA_ROLLOUT_BASE_RATE_PER_MINUTE"},
		{"Base rate garbage", "OTA_ROLLOUT_BASE_RATE_PER_MINUTE", "fast", "OTA_ROLLOUT_BASE_RATE_PER_MINUTE"},
		{"Missing base rate", "OTA_ROLLOUT_BASE_RATE_PER_MINUTE", "", "OTA_ROLLOUT_BASE_RATE_PER_MINUTE is not set"},
		{"Increment factor too small", "OTA_ROLLOUT_INCREMENT_FACTOR", "1", "OTA_ROLLOUT_INCREMENT_FACTOR"},
		{"Increment factor too large", "OTA_ROLLOUT_INCREMENT_FACTOR", "5.1", "OTA_ROLLOUT_INCREMENT_FACTOR"},
		{"Increment factor two decimals", "OTA_ROLLOUT_INCREMENT_FACTOR", "1.55", "OTA_ROLLOUT_INCREMENT_FACTOR"},
		{"Increment factor negative", "OTA_ROLLOUT_INCREMENT_FACTOR", "-2", "OTA_ROLLOUT_INCREMENT_FACTOR"},
		{"Succeeded threshold zero", "OTA_ROLLOUT_SUCCEEDED_THINGS", "0", "OTA_ROLLOUT_SUCCEEDED_THINGS"},
		{"Maximum rate zero", "OTA_ROLLOUT_MAX_PER_MINUTE", "0", "OTA_ROLLOUT_MAX_PER_MINUTE"},
		{"Abort percentage zero", "OTA_ABORT_FAILURE_PERCENTAGE", "0", "OTA_ABORT_FAILURE_PERCENTAGE"},
		{"Abort percentage above 100", "OTA_ABORT_FAILURE_PERCENTAGE", "100.01", "OTA_ABORT_FAILURE_PERCENTAGE"},
		{"Abort percentage three decimals", "OTA_ABORT_FAILURE_PERCENTAGE", "20.555", "OTA_ABORT_FAILURE_PERCENTAGE"},
		{"Abort minimum zero", "OTA_ABORT_MIN_EXECUTED_THINGS", "0", "OTA_ABORT_MIN_EXECUTED_THINGS"},
		{"Timeout zero", "OTA_IN_PROGRESS_TIMEOUT_MINUTES", "0", "OTA_IN_PROGRESS_TIMEOUT_MINUTES"},
		{"Timeout above seven days", "OTA_IN_PROGRESS_TIMEOUT_MINUTES", "10081", "OTA_IN_PROGRESS_TIMEOUT_MINUTES"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := validEnv()
			if tt.value == "" {
				delete(env, tt.key)
			} else {
				env[tt.key] = tt.value
			}
			_, err := loadConfig(func(k string) string { return env[k] })
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error to mention %q, got: %v", tt.wantErr, err)
			}
		})
	}

	t.Run("Base rate above maximum rate", func(t *testing.T) {
		env := validEnv()
		env["OTA_ROLLOUT_BASE_RATE_PER_MINUTE"] = "30"
		_, err := loadConfig(func(k string) string { return env[k] })
		if err == nil || !strings.Contains(err.Error(), "must not exceed OTA_ROLLOUT_MAX_PER_MINUTE") {
			t.Errorf("expected a base-above-maximum error, got: %v", err)
		}
	})

	t.Run("Every problem reported at once", func(t *testing.T) {
		env := validEnv()
		delete(env, "OTA_THING_GROUP_ARN")
		env["OTA_IN_PROGRESS_TIMEOUT_MINUTES"] = "forever"
		_, err := loadConfig(func(k string) string { return env[k] })
		if err == nil {
			t.Fatal("expected an error")
		}
		for _, name := range []string{"OTA_THING_GROUP_ARN", "OTA_IN_PROGRESS_TIMEOUT_MINUTES"} {
			if !strings.Contains(err.Error(), name) {
				t.Errorf("expected error to mention %s, got: %v", name, err)
			}
		}
	})
}

// TestCreateJobRequest checks everything the job is created with.
func TestCreateJobRequest(t *testing.T) {
	mockIoT := &MockIoTClient{}
	app := &App{iotClient: mockIoT, cfg: testConfig()}

	resp, err := app.Handler(context.Background(), s3Event("firmware/firmware_v1.0.0.bin"))
	if err != nil {
		t.Fatalf("unexpected handler error: %v", err)
	}
	if resp.StatusCode != 200 || !strings.Contains(resp.Body, "created for thing group esp32-ztp-fleet") {
		t.Errorf("unexpected response: %+v", resp)
	}
	if len(mockIoT.createJobCalls) != 1 {
		t.Fatalf("expected 1 CreateJob call, got %d", len(mockIoT.createJobCalls))
	}
	in := mockIoT.createJobCalls[0]

	if got := aws.ToString(in.JobId); got != testJobID {
		t.Errorf("expected JobId %s, got %s", testJobID, got)
	}
	if !reflect.DeepEqual(in.Targets, []string{testGroupARN}) {
		t.Errorf("expected the thing group as the only target, got %v", in.Targets)
	}
	if in.TargetSelection != iottypes.TargetSelectionContinuous {
		t.Errorf("expected CONTINUOUS, got %s", in.TargetSelection)
	}

	var doc map[string]string
	if err := json.Unmarshal([]byte(aws.ToString(in.Document)), &doc); err != nil {
		t.Fatalf("job document is not a JSON object of strings: %v", err)
	}
	wantDoc := map[string]string{
		"operation":        "firmware_update",
		"firmware_version": "firmware_v1.0.0",
		"download_url":     "${aws:iot:s3-presigned-url-v2:https://s3.eu-central-1.amazonaws.com/test-bucket/firmware/firmware_v1.0.0.bin}",
	}
	if !reflect.DeepEqual(doc, wantDoc) {
		t.Errorf("expected job document %v, got %v", wantDoc, doc)
	}

	wantPresign := &iottypes.PresignedUrlConfig{RoleArn: aws.String(testRoleARN), ExpiresInSec: aws.Int64(3600)}
	if !reflect.DeepEqual(in.PresignedUrlConfig, wantPresign) {
		t.Errorf("unexpected PresignedUrlConfig: %+v", in.PresignedUrlConfig)
	}

	wantRollout := &iottypes.JobExecutionsRolloutConfig{
		ExponentialRate: &iottypes.ExponentialRolloutRate{
			BaseRatePerMinute:    aws.Int32(1),
			IncrementFactor:      aws.Float64(2),
			RateIncreaseCriteria: &iottypes.RateIncreaseCriteria{NumberOfSucceededThings: aws.Int32(5)},
		},
		MaximumPerMinute: aws.Int32(20),
	}
	if !reflect.DeepEqual(in.JobExecutionsRolloutConfig, wantRollout) {
		t.Errorf("unexpected JobExecutionsRolloutConfig: %+v", in.JobExecutionsRolloutConfig)
	}

	wantAbort := &iottypes.AbortConfig{CriteriaList: []iottypes.AbortCriteria{{
		Action:                    iottypes.AbortActionCancel,
		FailureType:               iottypes.JobExecutionFailureTypeAll,
		MinNumberOfExecutedThings: aws.Int32(10),
		ThresholdPercentage:       aws.Float64(20),
	}}}
	if !reflect.DeepEqual(in.AbortConfig, wantAbort) {
		t.Errorf("unexpected AbortConfig: %+v", in.AbortConfig)
	}

	wantTimeout := &iottypes.TimeoutConfig{InProgressTimeoutInMinutes: aws.Int64(30)}
	if !reflect.DeepEqual(in.TimeoutConfig, wantTimeout) {
		t.Errorf("unexpected TimeoutConfig: %+v", in.TimeoutConfig)
	}

	// Then it looks for older jobs in the same group, and finds none to cancel.
	if len(mockIoT.listJobsCalls) != 1 {
		t.Fatalf("expected 1 ListJobs call, got %d", len(mockIoT.listJobsCalls))
	}
	list := mockIoT.listJobsCalls[0]
	if aws.ToString(list.ThingGroupName) != "esp32-ztp-fleet" || list.Status != iottypes.JobStatusInProgress {
		t.Errorf("unexpected ListJobs filter: group=%s status=%s", aws.ToString(list.ThingGroupName), list.Status)
	}
	if len(mockIoT.cancelJobCalls) != 0 {
		t.Errorf("expected no cancellations, got %v", mockIoT.cancelledIDs())
	}
}

func TestOTAHandler(t *testing.T) {
	const (
		olderJob = "ota-firmware_v0-9-0-1790400000000"
		newerJob = "ota-firmware_v1-1-0-1790600000000"
	)

	tests := []struct {
		name          string
		event         events.S3Event
		createJobFunc func(ctx context.Context, params *iot.CreateJobInput) (*iot.CreateJobOutput, error)
		listJobsFunc  func(ctx context.Context, params *iot.ListJobsInput) (*iot.ListJobsOutput, error)
		cancelJobFunc func(ctx context.Context, params *iot.CancelJobInput) (*iot.CancelJobOutput, error)
		wantStatus    int
		wantErr       bool
		wantBodySub   string
		wantCreates   int
		wantLists     int
		wantCancelled []string
	}{
		{
			name:       "Error - Empty Records",
			event:      events.S3Event{Records: []events.S3EventRecord{}},
			wantStatus: 400,
		},
		{
			name:  "Error - CreateJob Fails",
			event: s3Event("firmware_v1.0.0.bin"),
			createJobFunc: func(ctx context.Context, params *iot.CreateJobInput) (*iot.CreateJobOutput, error) {
				return nil, errors.New("iot create job failed")
			},
			wantStatus:  500,
			wantErr:     true,
			wantCreates: 1,
			wantLists:   0, // nothing is cancelled when no replacement exists
		},
		{
			name:  "Success - Duplicate Event Reuses The Existing Job",
			event: s3Event("firmware_v1.0.0.bin"),
			createJobFunc: func(ctx context.Context, params *iot.CreateJobInput) (*iot.CreateJobOutput, error) {
				return nil, &iottypes.ResourceAlreadyExistsException{Message: aws.String("job exists")}
			},
			listJobsFunc: func(ctx context.Context, params *iot.ListJobsInput) (*iot.ListJobsOutput, error) {
				return &iot.ListJobsOutput{Jobs: jobSummaries(testJobID, olderJob)}, nil
			},
			wantStatus:    200,
			wantBodySub:   "created for thing group",
			wantCreates:   1,
			wantLists:     1,
			wantCancelled: []string{olderJob}, // finishes what the first delivery did not
		},
		{
			name:  "Success - Older OTA Jobs Cancelled, Others Left Alone",
			event: s3Event("firmware_v1.0.0.bin"),
			listJobsFunc: func(ctx context.Context, params *iot.ListJobsInput) (*iot.ListJobsOutput, error) {
				return &iot.ListJobsOutput{Jobs: jobSummaries(
					olderJob,
					"ota-firmware_v0-1-0-1790540983", // seconds-based ID from before
					testJobID,
					"shadow-reset-1790000000000", // not an OTA job
					"ota-manual",                 // no timestamp: not ours to judge
				)}, nil
			},
			wantStatus:    200,
			wantBodySub:   "created for thing group",
			wantCreates:   1,
			wantLists:     1,
			wantCancelled: []string{olderJob, "ota-firmware_v0-1-0-1790540983"},
		},
		{
			name:  "Success - Older Jobs Found Across Pages",
			event: s3Event("firmware_v1.0.0.bin"),
			listJobsFunc: func(ctx context.Context, params *iot.ListJobsInput) (*iot.ListJobsOutput, error) {
				if params.NextToken == nil {
					return &iot.ListJobsOutput{Jobs: jobSummaries(olderJob), NextToken: aws.String("page-2")}, nil
				}
				if aws.ToString(params.NextToken) != "page-2" {
					t.Errorf("unexpected NextToken %s", aws.ToString(params.NextToken))
				}
				return &iot.ListJobsOutput{Jobs: jobSummaries("ota-firmware_v0-8-0-1790300000000")}, nil
			},
			wantStatus:    200,
			wantCreates:   1,
			wantLists:     2,
			wantCancelled: []string{olderJob, "ota-firmware_v0-8-0-1790300000000"},
		},
		{
			name:  "Success - Newer Upload Already Active, This Job Cancelled",
			event: s3Event("firmware_v1.0.0.bin"),
			listJobsFunc: func(ctx context.Context, params *iot.ListJobsInput) (*iot.ListJobsOutput, error) {
				return &iot.ListJobsOutput{Jobs: jobSummaries(newerJob, olderJob)}, nil
			},
			wantStatus:    200,
			wantBodySub:   "superseded by " + newerJob,
			wantCreates:   1,
			wantLists:     1,
			wantCancelled: []string{olderJob, testJobID},
		},
		{
			name:  "Success - Late Duplicate Of A Finished Job Changes Nothing",
			event: s3Event("firmware_v1.0.0.bin"),
			createJobFunc: func(ctx context.Context, params *iot.CreateJobInput) (*iot.CreateJobOutput, error) {
				return nil, &iottypes.ResourceAlreadyExistsException{Message: aws.String("job exists")}
			},
			listJobsFunc: func(ctx context.Context, params *iot.ListJobsInput) (*iot.ListJobsOutput, error) {
				return &iot.ListJobsOutput{Jobs: jobSummaries(newerJob)}, nil
			},
			wantStatus:  200,
			wantBodySub: "superseded by " + newerJob,
			wantCreates: 1,
			wantLists:   1,
		},
		{
			name:  "Error - ListJobs Fails",
			event: s3Event("firmware_v1.0.0.bin"),
			listJobsFunc: func(ctx context.Context, params *iot.ListJobsInput) (*iot.ListJobsOutput, error) {
				return nil, errors.New("iot list jobs failed")
			},
			wantStatus:  500,
			wantErr:     true,
			wantCreates: 1,
			wantLists:   1,
		},
		{
			name:  "Error - CancelJob Fails, Remaining Jobs Still Cancelled",
			event: s3Event("firmware_v1.0.0.bin"),
			listJobsFunc: func(ctx context.Context, params *iot.ListJobsInput) (*iot.ListJobsOutput, error) {
				return &iot.ListJobsOutput{Jobs: jobSummaries(olderJob, "ota-firmware_v0-8-0-1790300000000")}, nil
			},
			cancelJobFunc: func(ctx context.Context, params *iot.CancelJobInput) (*iot.CancelJobOutput, error) {
				if aws.ToString(params.JobId) == olderJob {
					return nil, errors.New("iot cancel job failed")
				}
				return &iot.CancelJobOutput{}, nil
			},
			wantStatus:    500,
			wantErr:       true,
			wantCreates:   1,
			wantLists:     1,
			wantCancelled: []string{olderJob, "ota-firmware_v0-8-0-1790300000000"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockIoT := &MockIoTClient{
				CreateJobFunc: tt.createJobFunc,
				ListJobsFunc:  tt.listJobsFunc,
				CancelJobFunc: tt.cancelJobFunc,
			}
			app := &App{iotClient: mockIoT, cfg: testConfig()}

			resp, err := app.Handler(context.Background(), tt.event)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error=%v, got %v", tt.wantErr, err)
			}

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}

			if tt.wantBodySub != "" && !strings.Contains(resp.Body, tt.wantBodySub) {
				t.Errorf("expected body to contain %s, got %s", tt.wantBodySub, resp.Body)
			}

			if len(mockIoT.createJobCalls) != tt.wantCreates {
				t.Errorf("expected %d CreateJob calls, got %d", tt.wantCreates, len(mockIoT.createJobCalls))
			}
			if len(mockIoT.listJobsCalls) != tt.wantLists {
				t.Errorf("expected %d ListJobs calls, got %d", tt.wantLists, len(mockIoT.listJobsCalls))
			}
			if got := mockIoT.cancelledIDs(); !reflect.DeepEqual(got, tt.wantCancelled) {
				t.Errorf("expected cancelled jobs %v, got %v", tt.wantCancelled, got)
			}
			for _, c := range mockIoT.cancelJobCalls {
				if c.Force {
					t.Errorf("job %s cancelled with force; IN_PROGRESS devices must be left to finish", aws.ToString(c.JobId))
				}
				if aws.ToString(c.ReasonCode) != "SUPERSEDED" || !strings.HasPrefix(aws.ToString(c.Comment), "Superseded by OTA job ota-") {
					t.Errorf("unexpected cancel reason for %s: %s / %s", aws.ToString(c.JobId), aws.ToString(c.ReasonCode), aws.ToString(c.Comment))
				}
			}
		})
	}
}
