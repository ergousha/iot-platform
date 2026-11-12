package main

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	iottypes "github.com/aws/aws-sdk-go-v2/service/iot/types"
)

// adminIoT models group membership, thing principals and the deny policy.
type adminIoT struct {
	IoTAPI
	groups     map[string][]string // group name -> things
	principals map[string][]string // thing -> principal ARNs
	certs      map[string]iottypes.CertificateStatus
	denied     []string // deny-all policy targets
	deleteErrs int      // DeleteThing fails this many times first
	calls      []string
}

func (f *adminIoT) ListThingsInThingGroup(_ context.Context, in *iot.ListThingsInThingGroupInput, _ ...func(*iot.Options)) (*iot.ListThingsInThingGroupOutput, error) {
	things := slices.Clone(f.groups[aws.ToString(in.ThingGroupName)])
	if in.Recursive && aws.ToString(in.ThingGroupName) == vaktus.Fleet.Name {
		things = append(things, f.groups[vaktus.Canary.Name]...)
	}
	return &iot.ListThingsInThingGroupOutput{Things: things}, nil
}

func (f *adminIoT) AddThingToThingGroup(_ context.Context, in *iot.AddThingToThingGroupInput, _ ...func(*iot.Options)) (*iot.AddThingToThingGroupOutput, error) {
	f.calls = append(f.calls, "add "+aws.ToString(in.ThingName)+" "+aws.ToString(in.ThingGroupArn))
	return &iot.AddThingToThingGroupOutput{}, nil
}

func (f *adminIoT) RemoveThingFromThingGroup(_ context.Context, in *iot.RemoveThingFromThingGroupInput, _ ...func(*iot.Options)) (*iot.RemoveThingFromThingGroupOutput, error) {
	f.calls = append(f.calls, "remove "+aws.ToString(in.ThingName)+" "+aws.ToString(in.ThingGroupArn))
	return &iot.RemoveThingFromThingGroupOutput{}, nil
}

func (f *adminIoT) ListThingPrincipals(_ context.Context, in *iot.ListThingPrincipalsInput, _ ...func(*iot.Options)) (*iot.ListThingPrincipalsOutput, error) {
	return &iot.ListThingPrincipalsOutput{Principals: slices.Clone(f.principals[aws.ToString(in.ThingName)])}, nil
}

func (f *adminIoT) UpdateCertificate(_ context.Context, in *iot.UpdateCertificateInput, _ ...func(*iot.Options)) (*iot.UpdateCertificateOutput, error) {
	f.certs[aws.ToString(in.CertificateId)] = in.NewStatus
	f.calls = append(f.calls, "cert "+aws.ToString(in.CertificateId)+" "+string(in.NewStatus))
	return &iot.UpdateCertificateOutput{}, nil
}

func (f *adminIoT) DetachThingPrincipal(_ context.Context, in *iot.DetachThingPrincipalInput, _ ...func(*iot.Options)) (*iot.DetachThingPrincipalOutput, error) {
	thing := aws.ToString(in.ThingName)
	f.principals[thing] = slices.DeleteFunc(f.principals[thing], func(p string) bool { return p == aws.ToString(in.Principal) })
	f.calls = append(f.calls, "detach "+thing)
	return &iot.DetachThingPrincipalOutput{}, nil
}

func (f *adminIoT) DeleteThing(_ context.Context, in *iot.DeleteThingInput, _ ...func(*iot.Options)) (*iot.DeleteThingOutput, error) {
	if f.deleteErrs > 0 {
		f.deleteErrs--
		return nil, &iottypes.InvalidRequestException{Message: aws.String("principals attached")}
	}
	f.calls = append(f.calls, "delete "+aws.ToString(in.ThingName))
	return &iot.DeleteThingOutput{}, nil
}

func (f *adminIoT) ListTargetsForPolicy(_ context.Context, in *iot.ListTargetsForPolicyInput, _ ...func(*iot.Options)) (*iot.ListTargetsForPolicyOutput, error) {
	if aws.ToString(in.PolicyName) != "deny-all" {
		return nil, errors.New("unexpected policy " + aws.ToString(in.PolicyName))
	}
	return &iot.ListTargetsForPolicyOutput{Targets: slices.Clone(f.denied)}, nil
}

func (f *adminIoT) DetachPolicy(_ context.Context, in *iot.DetachPolicyInput, _ ...func(*iot.Options)) (*iot.DetachPolicyOutput, error) {
	f.denied = slices.DeleteFunc(f.denied, func(t string) bool { return t == aws.ToString(in.Target) })
	f.calls = append(f.calls, "detach-policy "+aws.ToString(in.Target))
	return &iot.DetachPolicyOutput{}, nil
}

func (f *adminIoT) EnableTopicRule(_ context.Context, in *iot.EnableTopicRuleInput, _ ...func(*iot.Options)) (*iot.EnableTopicRuleOutput, error) {
	f.calls = append(f.calls, "enable "+aws.ToString(in.RuleName))
	return &iot.EnableTopicRuleOutput{}, nil
}

func adminApp() (*App, *adminIoT, *fakeSSM, *fakeSNS) {
	a, _, ssmf, _, snsf, _ := testApp()
	f := &adminIoT{
		groups: map[string][]string{
			vaktus.Fleet.Name:    {"AAAAAAAAAAAA"},
			vaktus.Canary.Name:   {"38182B8456F4"},
			vaktus.Excluded.Name: {"CCCCCCCCCCCC"},
		},
		principals: map[string][]string{},
		certs:      map[string]iottypes.CertificateStatus{},
	}
	a.iot = f
	a.sleep = func(time.Duration) {}
	return a, f, ssmf, snsf
}

const viewerARN = "arn:aws:sts::111122223333:assumed-role/esp32-ztp-portal-viewer/CognitoIdentityCredentials"

func urlEvent(t *testing.T, userARN, body string) json.RawMessage {
	t.Helper()
	ev := map[string]any{
		"requestContext": map[string]any{
			"http": map[string]any{"method": "POST"},
			"authorizer": map[string]any{"iam": map[string]any{
				"userArn": userARN, "accessKey": "ASIAEXAMPLE",
				"cognitoIdentity": map[string]any{"identityId": "eu-central-1:abc"},
			}},
		},
		"body": body,
	}
	if userARN == "" {
		delete(ev["requestContext"].(map[string]any), "authorizer")
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Exit criterion: the viewer role cannot write, not even through the
// controller's Function URL.
func TestFunctionURLViewerMayOnlyRead(t *testing.T) {
	a, f, _, _ := adminApp()
	for _, body := range []string{
		`{"action":"hold","product":"vaktus"}`,
		`{"action":"guard-reset"}`,
		`{"action":"quarantine","product":"vaktus","thing":"AAAAAAAAAAAA"}`,
	} {
		r, err := a.Handle(context.Background(), urlEvent(t, viewerARN, body))
		resp := r.(events.LambdaFunctionURLResponse)
		if err != nil || resp.StatusCode != 403 || !strings.Contains(resp.Body, "may only read") {
			t.Errorf("%s: %d %s %v", body, resp.StatusCode, resp.Body, err)
		}
	}
	r, _ := a.Handle(context.Background(), urlEvent(t, "", `{"action":"hold","product":"vaktus"}`))
	if r.(events.LambdaFunctionURLResponse).StatusCode != 403 {
		t.Errorf("a caller without an IAM identity was let through")
	}
	if len(f.calls) != 0 {
		t.Errorf("refused requests made calls: %v", f.calls)
	}
	if err := a.allowed(Caller{UserARN: viewerARN}, Override{Action: "status"}); err != nil {
		t.Errorf("viewer status: %v", err)
	}
	owner := Caller{UserARN: "arn:aws:sts::111122223333:assumed-role/esp32-ztp-portal-owner/CognitoIdentityCredentials"}
	if err := a.allowed(owner, Override{Action: "decommission"}); err != nil {
		t.Errorf("owner: %v", err)
	}
}

func TestFunctionURLOwnerIsAttributed(t *testing.T) {
	a, f, _, snsf := adminApp()
	owner := "arn:aws:sts::111122223333:assumed-role/esp32-ztp-portal-owner/CognitoIdentityCredentials"
	r, err := a.Handle(context.Background(), urlEvent(t, owner, `{"action":"quarantine","product":"vaktus","thing":"38182B8456F4"}`))
	resp := r.(events.LambdaFunctionURLResponse)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%d %s %v", resp.StatusCode, resp.Body, err)
	}
	if !slices.Equal(f.calls, []string{"add 38182B8456F4 " + a.cfg.Quarantine.ARN}) {
		t.Errorf("calls %v", f.calls)
	}
	if len(snsf.subjects) != 1 || !strings.Contains(snsf.subjects[0], "quarantine 38182B8456F4") {
		t.Errorf("emails %v", snsf.subjects)
	}
}

func TestQuarantineStaysInItsProduct(t *testing.T) {
	a, f, _, _ := adminApp()
	r := a.override(context.Background(), Override{Action: "quarantine", Product: "vaktus", Thing: "28848553144F"})
	if r.OK || !strings.Contains(r.Error, "not a vaktus device") {
		t.Errorf("foreign thing: %+v", r)
	}
	r = a.override(context.Background(), Override{Action: "unquarantine", Product: "vaktus", Thing: "CCCCCCCCCCCC"})
	if !r.OK || !slices.Equal(f.calls, []string{"remove CCCCCCCCCCCC " + a.cfg.Quarantine.ARN}) {
		t.Errorf("excluded thing: %+v %v", r, f.calls)
	}
}

func TestDecommission(t *testing.T) {
	a, f, _, snsf := adminApp()
	cert := "arn:aws:iot:eu-central-1:111122223333:cert/abcdef0123456789"
	f.principals["AAAAAAAAAAAA"] = []string{cert}
	f.deleteErrs = 2

	r := a.override(context.Background(), Override{Action: "decommission", Product: "vaktus", Thing: "AAAAAAAAAAAA", Confirm: "AAAAAAAAAAAB"})
	if r.OK || !strings.Contains(r.Error, "confirm") || len(f.calls) != 0 {
		t.Fatalf("unconfirmed: %+v %v", r, f.calls)
	}
	r = a.override(context.Background(), Override{Action: "decommission", Product: "vaktus", Thing: "AAAAAAAAAAAA", Confirm: "AAAAAAAAAAAA"})
	if !r.OK {
		t.Fatalf("decommission: %+v", r)
	}
	want := []string{"cert abcdef0123456789 INACTIVE", "detach AAAAAAAAAAAA", "delete AAAAAAAAAAAA"}
	if !slices.Equal(f.calls, want) {
		t.Errorf("calls %v, want %v", f.calls, want)
	}
	if len(snsf.subjects) != 1 || !strings.Contains(snsf.subjects[0], "decommissioned AAAAAAAAAAAA") {
		t.Errorf("emails %v", snsf.subjects)
	}

	f.calls, f.deleteErrs = nil, 10
	f.groups[vaktus.Fleet.Name] = append(f.groups[vaktus.Fleet.Name], "BBBBBBBBBBBB")
	r = a.override(context.Background(), Override{Action: "decommission", Product: "vaktus", Thing: "BBBBBBBBBBBB", Confirm: "BBBBBBBBBBBB"})
	if r.OK || !strings.Contains(r.Error, "run decommission again") {
		t.Errorf("stuck delete: %+v", r)
	}
}

func TestGuardReset(t *testing.T) {
	a, f, ssmf, snsf := adminApp()
	fleet := vaktus.Fleet.ARN
	tripped := `{"tripped":true,"scope":"fleet","since":"2026-11-12T01:00:00Z","reasons":["alarm publish-30m"],"last":{"old":1}}`
	ssmf.params["/guard"] = tripped
	f.denied = []string{fleet, a.cfg.Quarantine.ARN}

	r := a.override(context.Background(), Override{Action: "guard-reset", by: "the owner"})
	if !r.OK {
		t.Fatalf("reset: %+v", r)
	}
	if !slices.Equal(f.denied, []string{a.cfg.Quarantine.ARN}) {
		t.Errorf("deny-all left on %v", f.denied)
	}
	if !slices.Contains(f.calls, "enable esp32_ztp_presence") {
		t.Errorf("rules not restored: %v", f.calls)
	}
	var st struct {
		Tripped bool           `json:"tripped"`
		ResetBy string         `json:"reset_by"`
		Last    map[string]any `json:"last"`
	}
	if err := json.Unmarshal([]byte(ssmf.params["/guard"]), &st); err != nil || st.Tripped || st.ResetBy != "the owner" ||
		st.Last["scope"] != "fleet" || st.Last["last"] != nil {
		t.Errorf("state %s (%v)", ssmf.params["/guard"], err)
	}
	if len(snsf.subjects) != 1 {
		t.Errorf("emails %v", snsf.subjects)
	}

	// Nothing tripped: nothing to do.
	f.calls = nil
	r = a.override(context.Background(), Override{Action: "guard-reset"})
	if !r.OK || len(f.calls) != 0 || !strings.Contains(r.Log[0], "not tripped") {
		t.Errorf("idle reset: %+v %v", r, f.calls)
	}
}

// A trip that lands during the reset is never overwritten.
func TestGuardResetKeepsANewTrip(t *testing.T) {
	a, f, ssmf, _ := adminApp()
	ssmf.params["/guard"] = `{"tripped":true,"scope":"traffic"}`
	f.denied = nil
	a.iot = &tripDuringReset{adminIoT: f, ssm: ssmf}
	r := a.override(context.Background(), Override{Action: "guard-reset"})
	if r.OK || !strings.Contains(r.Error, "changed during the reset") {
		t.Fatalf("reset over a new trip: %+v", r)
	}
	if !strings.Contains(ssmf.params["/guard"], `"fleet"`) {
		t.Errorf("the new trip was overwritten: %s", ssmf.params["/guard"])
	}
}

type tripDuringReset struct {
	*adminIoT
	ssm *fakeSSM
}

func (f *tripDuringReset) EnableTopicRule(ctx context.Context, in *iot.EnableTopicRuleInput, o ...func(*iot.Options)) (*iot.EnableTopicRuleOutput, error) {
	f.ssm.params["/guard"] = `{"tripped":true,"scope":"fleet"}`
	return f.adminIoT.EnableTopicRule(ctx, in, o...)
}
