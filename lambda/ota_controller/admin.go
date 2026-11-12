package main

// Owner actions the portal needs beyond the release overrides: quarantine a
// device, decommission it, and reset the guard. Each also
// works through `aws lambda invoke` (scripts/ota.sh).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	iottypes "github.com/aws/aws-sdk-go-v2/service/iot/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

var thingNamePattern = regexp.MustCompile(`^[A-Za-z0-9_:-]{1,128}$`)

// Caller is the signer of a Function URL request, as AWS_IAM auth verified
// it (requestContext.authorizer.iam). A portal session is an assumed role
// session of the owner or viewer role; its access key is what CloudTrail
// ties to the Cognito user (the `username` session tag).
type Caller struct {
	UserARN    string `json:"userArn"`
	AccessKey  string `json:"accessKey"`
	IdentityID string `json:"-"`
}

// role is the IAM role name of an assumed-role caller, else "".
// arn:aws:sts::<account>:assumed-role/<role>/<session>
func (c Caller) role() string {
	_, rest, ok := strings.Cut(c.UserARN, ":assumed-role/")
	if !ok {
		return ""
	}
	role, _, _ := strings.Cut(rest, "/")
	return role
}

func (c Caller) String() string {
	s := c.UserARN
	if c.AccessKey != "" {
		s += " (access key " + c.AccessKey + ")"
	}
	if c.IdentityID != "" {
		s += ", Cognito identity " + c.IdentityID
	}
	return s
}

// readOnly actions are open to viewers.
func (o Override) readOnly() bool { return o.Action == "status" }

// allowed: a viewer-role caller may only read. Every other principal that
// passed AWS_IAM auth holds lambda:InvokeFunctionUrl on this function, which
// only the owner's roles do.
func (a *App) allowed(c Caller, o Override) error {
	if c.UserARN == "" {
		return errors.New("unauthenticated caller")
	}
	if slices.Contains(a.cfg.ViewerRoles, c.role()) && !o.readOnly() {
		return fmt.Errorf("role %s may only read (status)", c.role())
	}
	return nil
}

// attribute adds the requester to every email of a plan.
func attribute(plan Plan, by string) Plan {
	if by == "" {
		return plan
	}
	for i := range plan.Actions {
		if plan.Actions[i].Kind == ActNotify {
			plan.Actions[i].Body += "\n\nRequested through the Function URL by " + by + "."
		}
	}
	return plan
}

// notifyBy emails the owner, naming the requester.
func (a *App) notifyBy(ctx context.Context, subject, body, by string) error {
	if by != "" {
		body += "\n\nRequested through the Function URL by " + by + "."
	}
	return a.notify(ctx, subject, body)
}

// productThing checks that thing is one of p's devices (fleet, canary or
// excluded), so an action for one product never touches another's.
func (a *App) productThing(ctx context.Context, p ProductConfig, thing string) error {
	if !thingNamePattern.MatchString(thing) {
		return fmt.Errorf("%q is not a thing name", thing)
	}
	for _, g := range []struct {
		name      string
		recursive bool
	}{{p.Fleet.Name, true}, {p.Excluded.Name, false}} {
		things, err := a.groupThings(ctx, g.name, g.recursive)
		if err != nil {
			return err
		}
		if slices.Contains(things, thing) {
			return nil
		}
	}
	return fmt.Errorf("%s is not a %s device", thing, p.ID)
}

// quarantine adds a device to the quarantine group, whose deny-all policy
// refuses its next publish or connect; unquarantine takes it out again.
func (a *App) quarantine(ctx context.Context, p ProductConfig, o Override) (Result, error) {
	if err := a.productThing(ctx, p, o.Thing); err != nil {
		return Result{}, err
	}
	in := o.Action == "quarantine"
	var err error
	if in {
		_, err = a.iot.AddThingToThingGroup(ctx, &iot.AddThingToThingGroupInput{
			ThingName: aws.String(o.Thing), ThingGroupArn: aws.String(a.cfg.Quarantine.ARN),
		})
	} else {
		_, err = a.iot.RemoveThingFromThingGroup(ctx, &iot.RemoveThingFromThingGroupInput{
			ThingName: aws.String(o.Thing), ThingGroupArn: aws.String(a.cfg.Quarantine.ARN),
		})
	}
	if err != nil {
		return Result{}, fmt.Errorf("%s %s: %w", o.Action, o.Thing, err)
	}
	msg := fmt.Sprintf("%s is quarantined: AWS IoT refuses its next publish or connect.", o.Thing)
	if !in {
		msg = fmt.Sprintf("%s is out of quarantine; it connects again on its next retry.", o.Thing)
	}
	return Result{OK: true, Log: []string{msg}}, a.notifyBy(ctx, fmt.Sprintf("[%s] %s %s", p.ID, o.Action, o.Thing), msg, o.by)
}

// decommission retires a device: every certificate of the thing INACTIVE
// and detached, then the thing deleted (which also drops it from its
// groups). The certificates go with the hourly hygiene a day later. The
// registry record stays provisioned, so the device cannot enrol again until
// `ergo commission --reprovision`.
func (a *App) decommission(ctx context.Context, p ProductConfig, o Override) (Result, error) {
	if o.Confirm != o.Thing {
		return Result{}, errors.New("confirm must repeat the thing name")
	}
	if err := a.productThing(ctx, p, o.Thing); err != nil {
		return Result{}, err
	}
	var log []string
	var principals []string
	pg := iot.NewListThingPrincipalsPaginator(a.iot, &iot.ListThingPrincipalsInput{ThingName: aws.String(o.Thing)})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return Result{}, fmt.Errorf("listing the certificates of %s: %w", o.Thing, err)
		}
		principals = append(principals, page.Principals...)
	}
	for _, principal := range principals {
		if strings.Contains(principal, ":cert/") {
			if err := a.setCert(ctx, idFromARN(principal), iottypes.CertificateStatusInactive); err != nil {
				return Result{OK: false, Log: log}, err
			}
		}
		if _, err := a.iot.DetachThingPrincipal(ctx, &iot.DetachThingPrincipalInput{
			ThingName: aws.String(o.Thing), Principal: aws.String(principal),
		}); err != nil {
			return Result{OK: false, Log: log}, fmt.Errorf("detaching %.40s from %s: %w", principal, o.Thing, err)
		}
		log = append(log, fmt.Sprintf("certificate %.12s inactive and detached", idFromARN(principal)))
	}

	// Detaching propagates asynchronously, and a thing with principals cannot
	// be deleted: retry briefly. Running decommission again is safe.
	var err error
	for attempt := range 6 {
		if attempt > 0 {
			a.pause(2 * time.Second)
		}
		if _, err = a.iot.DeleteThing(ctx, &iot.DeleteThingInput{ThingName: aws.String(o.Thing)}); err == nil {
			break
		}
	}
	if err != nil {
		return Result{OK: false, Log: log}, fmt.Errorf("deleting %s (its certificates are already inactive; run decommission again): %w", o.Thing, err)
	}
	log = append(log, "thing "+o.Thing+" deleted")
	slog.Info("Decommissioned", "product", p.ID, "thing", o.Thing, "by", o.by)
	return Result{OK: true, Log: log}, a.notifyBy(ctx, fmt.Sprintf("[%s] decommissioned %s", p.ID, o.Thing),
		fmt.Sprintf("%s was decommissioned: %s. Its registry record stays provisioned; "+
			"`ergo commission --reprovision` brings it back.", o.Thing, strings.Join(log, "; ")), o.by)
}

// guardReset undoes a kill-switch trip, like scripts/guard-reset.sh: the
// deny-all policy comes off every target but the quarantine group, the rules
// Terraform keeps enabled are enabled again, and the state is cleared. The
// claim stays INACTIVE (its normal state; the tick arms it for windows).
func (a *App) guardReset(ctx context.Context, by string) (Result, error) {
	read := func() (string, error) {
		out, err := a.ssm.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(a.cfg.GuardStateParameter)})
		if err != nil {
			return "", fmt.Errorf("reading the guard state: %w", err)
		}
		return aws.ToString(out.Parameter.Value), nil
	}
	before, err := read()
	if err != nil {
		return Result{}, err
	}
	denied := func() ([]string, error) {
		var targets []string
		pg := iot.NewListTargetsForPolicyPaginator(a.iot, &iot.ListTargetsForPolicyInput{PolicyName: aws.String(a.cfg.DenyPolicy)})
		for pg.HasMorePages() {
			page, err := pg.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("listing the targets of %s: %w", a.cfg.DenyPolicy, err)
			}
			for _, t := range page.Targets {
				if t != a.cfg.Quarantine.ARN {
					targets = append(targets, t)
				}
			}
		}
		return targets, nil
	}
	targets, err := denied()
	if err != nil {
		return Result{}, err
	}
	var g GuardState
	if json.Unmarshal([]byte(before), &g) == nil && !g.Tripped && len(targets) == 0 {
		return Result{OK: true, Log: []string{"the guard is not tripped: nothing to reset"}}, nil
	}
	var log []string
	for _, t := range targets {
		if _, err := a.iot.DetachPolicy(ctx, &iot.DetachPolicyInput{PolicyName: aws.String(a.cfg.DenyPolicy), Target: aws.String(t)}); err != nil {
			return Result{Log: log}, fmt.Errorf("detaching %s from %s: %w", a.cfg.DenyPolicy, t, err)
		}
		log = append(log, "deny-all detached from "+t)
	}
	if left, err := denied(); err != nil || len(left) > 0 {
		return Result{Log: log}, fmt.Errorf("deny-all is still attached to %v (%v); the guard stays tripped", left, err)
	}
	for _, r := range a.cfg.RestoreRules {
		if _, err := a.iot.EnableTopicRule(ctx, &iot.EnableTopicRuleInput{RuleName: aws.String(r)}); err != nil {
			return Result{Log: log}, fmt.Errorf("enabling rule %s: %w", r, err)
		}
		log = append(log, "rule "+r+" enabled")
	}

	// A trip that landed while we worked must not be overwritten.
	if now, err := read(); err != nil {
		return Result{Log: log}, err
	} else if now != before {
		return Result{Log: log}, errors.New("the guard state changed during the reset (a new trip?); look again before resetting")
	}
	var prev map[string]any
	if json.Unmarshal([]byte(before), &prev) != nil {
		prev = map[string]any{"unreadable": before}
	}
	delete(prev, "last")
	state, _ := json.Marshal(map[string]any{
		"tripped": false, "reset_at": a.now().UTC().Format(time.RFC3339), "reset_by": by, "last": prev,
	})
	if _, err := a.ssm.PutParameter(ctx, &ssm.PutParameterInput{
		Name: aws.String(a.cfg.GuardStateParameter), Value: aws.String(string(state)),
		Type: ssmtypes.ParameterTypeString, Overwrite: aws.Bool(true),
	}); err != nil {
		return Result{Log: log}, fmt.Errorf("clearing the guard state: %w", err)
	}
	log = append(log, "guard state cleared")
	slog.Info("Guard reset", "by", by, "log", log)
	return Result{OK: true, Log: log}, a.notifyBy(ctx, "guard reset",
		"The guard was reset: "+strings.Join(log, "; ")+". Devices reconnect on their next retry. "+
			"Previous state: "+truncate(before, 1500)+
			"\n\nA budget already over its limit this month trips the kill switch again only at 150 %.", by)
}

// pause sleeps between retries; tests replace it.
func (a *App) pause(d time.Duration) {
	if a.sleep != nil {
		a.sleep(d)
		return
	}
	time.Sleep(d)
}
