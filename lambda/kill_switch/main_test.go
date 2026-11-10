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
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type mockIoT struct {
	certs    []string // "id=status"
	rules    []string
	attached []string // "policy@target"

	attachErr  func(target string) error
	disableErr error
	certErr    error
}

func (m *mockIoT) UpdateCertificate(ctx context.Context, p *iot.UpdateCertificateInput, _ ...func(*iot.Options)) (*iot.UpdateCertificateOutput, error) {
	m.certs = append(m.certs, aws.ToString(p.CertificateId)+"="+string(p.NewStatus))
	return &iot.UpdateCertificateOutput{}, m.certErr
}

func (m *mockIoT) DisableTopicRule(ctx context.Context, p *iot.DisableTopicRuleInput, _ ...func(*iot.Options)) (*iot.DisableTopicRuleOutput, error) {
	m.rules = append(m.rules, aws.ToString(p.RuleName))
	return &iot.DisableTopicRuleOutput{}, m.disableErr
}

func (m *mockIoT) AttachPolicy(ctx context.Context, p *iot.AttachPolicyInput, _ ...func(*iot.Options)) (*iot.AttachPolicyOutput, error) {
	m.attached = append(m.attached, aws.ToString(p.PolicyName)+"@"+aws.ToString(p.Target))
	if m.attachErr != nil {
		return nil, m.attachErr(aws.ToString(p.Target))
	}
	return &iot.AttachPolicyOutput{}, nil
}

type mockSSM struct {
	value  *string // nil: parameter missing
	puts   []string
	getErr error
	putErr error
	// afterPut runs after each successful put: a concurrent invocation's write.
	afterPut func(m *mockSSM)
}

func (m *mockSSM) GetParameter(ctx context.Context, p *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.value == nil {
		return nil, &ssmtypes.ParameterNotFound{}
	}
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: m.value}}, nil
}

func (m *mockSSM) PutParameter(ctx context.Context, p *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	if m.putErr != nil {
		return nil, m.putErr
	}
	m.puts = append(m.puts, aws.ToString(p.Value))
	m.value = p.Value
	if m.afterPut != nil {
		m.afterPut(m)
	}
	return &ssm.PutParameterOutput{}, nil
}

const (
	claimID    = "claim123"
	denyPolicy = "esp32-ztp-guard-deny-all"
	groupA     = "arn:aws:iot:eu-central-1:1:thinggroup/esp32-ztp-fleet"
	groupB     = "arn:aws:iot:eu-central-1:1:thinggroup/esp32-ztp-vaktus-fleet"
)

var fixedNow = time.Date(2026, 11, 10, 20, 0, 0, 0, time.UTC)

func testEnv() map[string]string {
	return map[string]string{
		"ALARM_SCOPES": `{"esp32-ztp-guard-publish-5m":"traffic","esp32-ztp-guard-publish-30m":"fleet",` +
			`"esp32-ztp-guard-connect-5m":"provisioning","esp32-ztp-guard-hook-5m":"provisioning","esp32-ztp-guard-ota-errors":"notify"}`,
		"BUDGET_SCOPES":         `{"esp32-ztp-guard-traffic":"traffic","esp32-ztp-guard-fleet":"fleet"}`,
		"CLAIM_CERTIFICATE_ID":  claimID,
		"KILLABLE_RULES":        `["esp32_ztp_telemetry_to_logs","esp32_ztp_opcua_telemetry_to_logs"]`,
		"DENY_POLICY":           denyPolicy,
		"FLEET_GROUP_ARNS":      `["` + groupA + `","` + groupB + `"]`,
		"GUARD_STATE_PARAMETER": "/esp32-ztp/guard/state",
	}
}

func newApp(t *testing.T, s *mockSSM) (*App, *mockIoT) {
	t.Helper()
	env := testEnv()
	cfg, err := loadConfig(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	m := &mockIoT{}
	if s == nil {
		s = &mockSSM{}
	}
	return &App{iot: m, ssm: s, cfg: cfg, now: func() time.Time { return fixedNow }}, m
}

func alarm(name, state string) string {
	b, _ := json.Marshal(map[string]string{"AlarmName": name, "NewStateValue": state, "NewStateReason": "Threshold Crossed"})
	return string(b)
}

func snsEvent(messages ...string) events.SNSEvent {
	var e events.SNSEvent
	for _, m := range messages {
		e.Records = append(e.Records, events.SNSEventRecord{SNS: events.SNSEntity{Message: m}})
	}
	return e
}

const budgetFleetText = `AWS Budget Notification November 10, 2026
AWS Account 637423178579

Dear AWS Customer,

You requested that we alert you when the ACTUAL Cost associated with your esp32-ztp-guard-fleet budget is greater than $25.00 for the current month.

Budget Name: esp32-ztp-guard-fleet
Budget Type: Cost
Budgeted Amount: $25.00
Alert Type: ACTUAL
Alert Threshold: > $25.00`

func TestScopes(t *testing.T) {
	claimOff := []string{claimID + "=INACTIVE"}
	rules := []string{"esp32_ztp_telemetry_to_logs", "esp32_ztp_opcua_telemetry_to_logs"}
	denied := []string{denyPolicy + "@" + groupA, denyPolicy + "@" + groupB}

	tests := []struct {
		name         string
		message      string
		wantCerts    []string
		wantRules    []string
		wantAttached []string
		wantScope    string // stored; "" = nothing stored
	}{
		{"provisioning alarm", alarm("esp32-ztp-guard-hook-5m", "ALARM"), claimOff, nil, nil, "provisioning"},
		{"traffic alarm", alarm("esp32-ztp-guard-publish-5m", "ALARM"), claimOff, rules, nil, "traffic"},
		{"fleet alarm", alarm("esp32-ztp-guard-publish-30m", "ALARM"), claimOff, rules, denied, "fleet"},
		{"fleet budget", budgetFleetText, claimOff, rules, denied, "fleet"},
		{"traffic budget", strings.ReplaceAll(budgetFleetText, "esp32-ztp-guard-fleet", "esp32-ztp-guard-traffic"), claimOff, rules, nil, "traffic"},
		{"alarm back to OK", alarm("esp32-ztp-guard-publish-30m", "OK"), nil, nil, nil, ""},
		{"INSUFFICIENT_DATA", alarm("esp32-ztp-guard-publish-30m", "INSUFFICIENT_DATA"), nil, nil, nil, ""},
		{"notify-only alarm", alarm("esp32-ztp-guard-ota-errors", "ALARM"), nil, nil, nil, ""},
		{"unknown alarm", alarm("someone-elses-alarm", "ALARM"), nil, nil, nil, ""},
		{"unrelated text", "hello", nil, nil, nil, ""},
		{"another budget's text", strings.ReplaceAll(budgetFleetText, "esp32-ztp-guard-fleet", "my-other-budget"), nil, nil, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &mockSSM{}
			app, m := newApp(t, s)
			if err := app.Handler(context.Background(), snsEvent(tt.message)); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(m.certs, tt.wantCerts) || !reflect.DeepEqual(m.rules, tt.wantRules) || !reflect.DeepEqual(m.attached, tt.wantAttached) {
				t.Errorf("actions: certs=%v rules=%v attached=%v", m.certs, m.rules, m.attached)
			}
			if tt.wantScope == "" {
				if len(s.puts) != 0 {
					t.Errorf("nothing must be stored, got %v", s.puts)
				}
				return
			}
			var st GuardState
			if err := json.Unmarshal([]byte(*s.value), &st); err != nil {
				t.Fatal(err)
			}
			if !st.Tripped || st.Scope != tt.wantScope || st.Since != "2026-11-10T20:00:00Z" || len(st.Reasons) != 1 {
				t.Errorf("unexpected state %+v", st)
			}
		})
	}
}

// A narrower notification after a wider trip keeps enforcing the wider scope.
func TestTripNeverNarrows(t *testing.T) {
	prev := `{"tripped":true,"scope":"fleet","since":"2026-11-10T19:00:00Z","reasons":["earlier"]}`
	s := &mockSSM{value: aws.String(prev)}
	app, m := newApp(t, s)
	if err := app.Handler(context.Background(), snsEvent(alarm("esp32-ztp-guard-hook-5m", "ALARM"))); err != nil {
		t.Fatal(err)
	}
	if len(m.attached) != 2 {
		t.Errorf("the fleet trip must be re-asserted, got attached=%v", m.attached)
	}
	var st GuardState
	_ = json.Unmarshal([]byte(*s.value), &st)
	if st.Scope != "fleet" || st.Since != "2026-11-10T19:00:00Z" || len(st.Reasons) != 2 {
		t.Errorf("unexpected state %+v", st)
	}
}

// A reset state (tripped=false) starts a new trip with a fresh since/reasons.
func TestTripAfterReset(t *testing.T) {
	s := &mockSSM{value: aws.String(`{"tripped":false,"reasons":["old"]}`)}
	app, _ := newApp(t, s)
	if err := app.Handler(context.Background(), snsEvent(alarm("esp32-ztp-guard-connect-5m", "ALARM"))); err != nil {
		t.Fatal(err)
	}
	var st GuardState
	_ = json.Unmarshal([]byte(*s.value), &st)
	if st.Scope != "provisioning" || len(st.Reasons) != 1 || st.Since == "" {
		t.Errorf("unexpected state %+v", st)
	}
}

// Stopping the cost matters more than the record: a failing state write still
// enforces, and the error is returned so Lambda retries.
func TestStateFailureStillEnforces(t *testing.T) {
	for _, s := range []*mockSSM{{getErr: errors.New("ssm down")}, {putErr: errors.New("ssm down")}} {
		app, m := newApp(t, s)
		err := app.Handler(context.Background(), snsEvent(alarm("esp32-ztp-guard-publish-30m", "ALARM")))
		if err == nil {
			t.Error("expected the state error to be returned")
		}
		if len(m.certs) != 1 || len(m.rules) != 2 || len(m.attached) != 2 {
			t.Errorf("all actions must run, got certs=%v rules=%v attached=%v", m.certs, m.rules, m.attached)
		}
	}
}

func TestActionFailuresAreCollected(t *testing.T) {
	app, m := newApp(t, nil)
	m.disableErr = errors.New("throttled")
	m.attachErr = func(target string) error {
		if target == groupA {
			return &iottypes.ResourceAlreadyExistsException{Message: aws.String("already attached")}
		}
		return errors.New("denied")
	}
	err := app.Handler(context.Background(), snsEvent(alarm("esp32-ztp-guard-publish-30m", "ALARM")))
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "disabling rule") || !strings.Contains(msg, groupB) || strings.Contains(msg, groupA) {
		t.Errorf("unexpected error %q (an already-attached policy is success)", msg)
	}
	if len(m.certs) != 1 || len(m.attached) != 2 {
		t.Errorf("every action must still be tried, got certs=%v attached=%v", m.certs, m.attached)
	}
}

func TestLoadConfig(t *testing.T) {
	env := testEnv()
	if _, err := loadConfig(func(k string) string { return env[k] }); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for key, bad := range map[string]string{
		"ALARM_SCOPES":          `{"a":"everything"}`,
		"BUDGET_SCOPES":         `not json`,
		"KILLABLE_RULES":        `[""]`,
		"FLEET_GROUP_ARNS":      `[]`,
		"CLAIM_CERTIFICATE_ID":  "",
		"DENY_POLICY":           "",
		"GUARD_STATE_PARAMETER": "",
	} {
		e := testEnv()
		e[key] = bad
		if _, err := loadConfig(func(k string) string { return e[k] }); err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("%s=%q: expected an error naming it, got %v", key, bad, err)
		}
	}
}

func TestScopeString(t *testing.T) {
	for s, want := range map[Scope]string{ScopeNone: "none", ScopeProvisioning: "provisioning", ScopeTraffic: "traffic", ScopeFleet: "fleet"} {
		if s.String() != want {
			t.Errorf("%d.String() = %q, want %q", s, s.String(), want)
		}
	}
}

// Two trips race: right after this fleet trip writes, a concurrent traffic trip
// (which had read the old, untripped state) overwrites the record. The read-back
// restores the wider scope and keeps both reasons.
func TestConcurrentTripIsMerged(t *testing.T) {
	overwritten := false
	s := &mockSSM{afterPut: func(m *mockSSM) {
		if !overwritten {
			overwritten = true
			m.value = aws.String(`{"tripped":true,"scope":"traffic","since":"2026-11-10T20:00:01Z","reasons":["other trip (traffic)"]}`)
		}
	}}
	app, m := newApp(t, s)
	if err := app.Handler(context.Background(), snsEvent(alarm("esp32-ztp-guard-publish-30m", "ALARM"))); err != nil {
		t.Fatal(err)
	}
	var st GuardState
	_ = json.Unmarshal([]byte(*s.value), &st)
	if st.Scope != "fleet" || len(st.Reasons) != 2 || !strings.Contains(st.Reasons[0], "other trip") {
		t.Errorf("the record must end at the wider scope with both reasons, got %+v", st)
	}
	if len(s.puts) != 2 {
		t.Errorf("expected one re-write after the race, got %d puts", len(s.puts))
	}
	if len(m.attached) != 2 {
		t.Errorf("fleet must be enforced, got %v", m.attached)
	}
}
