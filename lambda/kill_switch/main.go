// Command kill_switch is the platform's automatic cost brake.
//
// CloudWatch alarms and AWS Budgets publish to the guard SNS topic, which
// invokes this Lambda. Each allow-listed alarm or budget maps to a scope, and
// every scope includes the ones below it:
//
//	provisioning  the claim certificate goes INACTIVE (no enrolment at all)
//	traffic       also disables the killable IoT rules (telemetry -> Logs)
//	fleet         also attaches the deny-all policy to every fleet thing group:
//	              each device is refused on its next publish or connect, the
//	              fleet goes offline and its messaging cost stops
//
// The trip is recorded in an SSM parameter first, so claim-window.sh refuses
// to open an enrolment window while the guard is tripped even if an action
// below fails. scripts/guard-reset.sh undoes a trip.
//
// Everything is idempotent: a redelivered or repeated notification re-asserts
// the same state.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	iottypes "github.com/aws/aws-sdk-go-v2/service/iot/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// Scope is how far a trip goes. Higher includes lower.
type Scope int

const (
	ScopeNone Scope = iota
	ScopeProvisioning
	ScopeTraffic
	ScopeFleet
)

var scopeNames = map[string]Scope{
	"notify":       ScopeNone, // email only: the topic's email subscription is enough
	"provisioning": ScopeProvisioning,
	"traffic":      ScopeTraffic,
	"fleet":        ScopeFleet,
}

func (s Scope) String() string {
	for name, v := range scopeNames {
		if v == s && name != "notify" {
			return name
		}
	}
	return "none"
}

func parseScope(name string) (Scope, error) {
	s, ok := scopeNames[name]
	if !ok {
		return ScopeNone, fmt.Errorf("unknown scope %q", name)
	}
	return s, nil
}

// Config is the Lambda's environment.
type Config struct {
	AlarmScopes    map[string]Scope
	BudgetScopes   map[string]Scope
	ClaimCertID    string
	KillableRules  []string
	DenyPolicy     string
	FleetGroupARNs []string
	StateParameter string
}

func parseScopes(name, value string) (map[string]Scope, error) {
	var raw map[string]string
	if err := json.Unmarshal([]byte(value), &raw); err != nil {
		return nil, fmt.Errorf("%s is not a JSON object of strings: %w", name, err)
	}
	scopes := make(map[string]Scope, len(raw))
	for k, v := range raw {
		s, err := parseScope(v)
		if err != nil {
			return nil, fmt.Errorf("%s[%q]: %w", name, k, err)
		}
		scopes[k] = s
	}
	return scopes, nil
}

func parseList(name, value string) ([]string, error) {
	var list []string
	if err := json.Unmarshal([]byte(value), &list); err != nil {
		return nil, fmt.Errorf("%s is not a JSON array of strings: %w", name, err)
	}
	for _, v := range list {
		if v == "" {
			return nil, fmt.Errorf("%s contains an empty entry", name)
		}
	}
	return list, nil
}

func loadConfig(getenv func(string) string) (Config, error) {
	var c Config
	var errs []error
	var err error

	if c.AlarmScopes, err = parseScopes("ALARM_SCOPES", getenv("ALARM_SCOPES")); err != nil {
		errs = append(errs, err)
	}
	if c.BudgetScopes, err = parseScopes("BUDGET_SCOPES", getenv("BUDGET_SCOPES")); err != nil {
		errs = append(errs, err)
	}
	if c.KillableRules, err = parseList("KILLABLE_RULES", getenv("KILLABLE_RULES")); err != nil {
		errs = append(errs, err)
	}
	if c.FleetGroupARNs, err = parseList("FLEET_GROUP_ARNS", getenv("FLEET_GROUP_ARNS")); err != nil {
		errs = append(errs, err)
	} else if len(c.FleetGroupARNs) == 0 {
		errs = append(errs, errors.New("FLEET_GROUP_ARNS lists no group"))
	}
	for _, name := range []string{"CLAIM_CERTIFICATE_ID", "DENY_POLICY", "GUARD_STATE_PARAMETER"} {
		if getenv(name) == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	c.ClaimCertID = getenv("CLAIM_CERTIFICATE_ID")
	c.DenyPolicy = getenv("DENY_POLICY")
	c.StateParameter = getenv("GUARD_STATE_PARAMETER")
	return c, errors.Join(errs...)
}

// IoTAPI is the AWS IoT subset the kill switch uses.
type IoTAPI interface {
	UpdateCertificate(ctx context.Context, params *iot.UpdateCertificateInput, optFns ...func(*iot.Options)) (*iot.UpdateCertificateOutput, error)
	DisableTopicRule(ctx context.Context, params *iot.DisableTopicRuleInput, optFns ...func(*iot.Options)) (*iot.DisableTopicRuleOutput, error)
	AttachPolicy(ctx context.Context, params *iot.AttachPolicyInput, optFns ...func(*iot.Options)) (*iot.AttachPolicyOutput, error)
}

// SSMAPI is the SSM subset the kill switch uses.
type SSMAPI interface {
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	PutParameter(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

// App holds the clients and configuration.
type App struct {
	iot IoTAPI
	ssm SSMAPI
	cfg Config
	now func() time.Time
}

// alarmMessage is the part of a CloudWatch alarm notification the kill switch
// reads.
type alarmMessage struct {
	AlarmName      string `json:"AlarmName"`
	NewStateValue  string `json:"NewStateValue"`
	NewStateReason string `json:"NewStateReason"`
}

// classify maps one SNS message to a scope and a reason. Only allow-listed
// alarms entering ALARM and allow-listed budgets trip anything; everything
// else (OK transitions, unknown alarms, other text) is ignored.
func (a *App) classify(message string) (Scope, string) {
	var alarm alarmMessage
	if err := json.Unmarshal([]byte(message), &alarm); err == nil && alarm.AlarmName != "" {
		scope, known := a.cfg.AlarmScopes[alarm.AlarmName]
		switch {
		case !known:
			slog.Warn("Ignoring an alarm that is not allow-listed", "alarm", alarm.AlarmName)
			return ScopeNone, ""
		case alarm.NewStateValue != "ALARM":
			return ScopeNone, ""
		}
		return scope, "alarm " + alarm.AlarmName
	}

	// AWS Budgets sends plain text that names the budget. The budget names are
	// distinct, and none contains another, so matching the name is exact.
	best, reason := ScopeNone, ""
	for name, scope := range a.cfg.BudgetScopes {
		if strings.Contains(message, name) && scope > best {
			best, reason = scope, "budget "+name
		}
	}
	if reason == "" {
		slog.Warn("Ignoring a message that is neither an allow-listed alarm nor budget")
	}
	return best, reason
}

// GuardState is what the state parameter holds.
type GuardState struct {
	Tripped bool     `json:"tripped"`
	Scope   string   `json:"scope,omitempty"`
	Since   string   `json:"since,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
}

// readState returns the stored guard state ({} when missing or unreadable).
func (a *App) readState(ctx context.Context) (GuardState, error) {
	var state GuardState
	out, err := a.ssm.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(a.cfg.StateParameter)})
	if err != nil {
		var missing *ssmtypes.ParameterNotFound
		if errors.As(err, &missing) {
			return state, nil
		}
		return state, fmt.Errorf("reading guard state: %w", err)
	}
	if v := aws.ToString(out.Parameter.Value); v != "" {
		if jerr := json.Unmarshal([]byte(v), &state); jerr != nil {
			slog.Warn("Guard state is not valid JSON; overwriting it", "value", v)
			return GuardState{}, nil
		}
	}
	return state, nil
}

// recordTrip widens the stored state to scope and adds reason. It returns the
// scope to enforce: the widest one tripped so far, so a later, narrower
// notification never relaxes an earlier trip.
//
// SSM has no compare-and-set, and SNS invokes the kill switch once per
// notification, so two trips can race (read, read, write, write). After
// writing, recordTrip reads the state back and merges again if another trip
// overwrote it with a narrower scope or without this reason. Enforcement never
// depends on the record: each invocation enforces at least its own scope.
func (a *App) recordTrip(ctx context.Context, scope Scope, reason string) (Scope, error) {
	entry := fmt.Sprintf("%s %s (%s)", a.now().UTC().Format(time.RFC3339), reason, scope)
	enforce := scope
	for attempt := 0; attempt < 3; attempt++ {
		state, err := a.readState(ctx)
		if err != nil {
			return enforce, err
		}
		if attempt > 0 && state.Tripped && containsString(state.Reasons, entry) {
			if prev, perr := parseScope(state.Scope); perr == nil && prev >= enforce {
				return enforce, nil // our trip survived the race
			}
		}
		if enforce, err = a.writeTrip(ctx, state, enforce, entry); err != nil {
			return enforce, err
		}
	}
	return enforce, nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// writeTrip merges entry into state at scope (or wider) and stores it.
func (a *App) writeTrip(ctx context.Context, state GuardState, scope Scope, entry string) (Scope, error) {
	enforce := scope
	if state.Tripped {
		if prev, perr := parseScope(state.Scope); perr == nil && prev > enforce {
			enforce = prev
		}
	} else {
		state.Since = a.now().UTC().Format(time.RFC3339)
		state.Reasons = nil
	}
	state.Tripped = true
	state.Scope = enforce.String()
	if !containsString(state.Reasons, entry) {
		state.Reasons = append(state.Reasons, entry)
	}
	if len(state.Reasons) > 20 {
		state.Reasons = state.Reasons[len(state.Reasons)-20:]
	}

	body, _ := json.Marshal(state)
	_, err := a.ssm.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(a.cfg.StateParameter),
		Value:     aws.String(string(body)),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		return enforce, fmt.Errorf("writing guard state: %w", err)
	}
	return enforce, nil
}

// enforce applies every action of scope. It tries all of them even if one
// fails, and returns the failures together.
func (a *App) enforce(ctx context.Context, scope Scope) error {
	var errs []error

	if scope >= ScopeProvisioning {
		_, err := a.iot.UpdateCertificate(ctx, &iot.UpdateCertificateInput{
			CertificateId: aws.String(a.cfg.ClaimCertID),
			NewStatus:     iottypes.CertificateStatusInactive,
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("deactivating the claim certificate: %w", err))
		} else {
			slog.Info("Claim certificate INACTIVE")
		}
	}

	if scope >= ScopeTraffic {
		for _, rule := range a.cfg.KillableRules {
			_, err := a.iot.DisableTopicRule(ctx, &iot.DisableTopicRuleInput{RuleName: aws.String(rule)})
			if err != nil {
				errs = append(errs, fmt.Errorf("disabling rule %s: %w", rule, err))
				continue
			}
			slog.Info("Rule disabled", "rule", rule)
		}
	}

	if scope >= ScopeFleet {
		for _, group := range a.cfg.FleetGroupARNs {
			_, err := a.iot.AttachPolicy(ctx, &iot.AttachPolicyInput{
				PolicyName: aws.String(a.cfg.DenyPolicy),
				Target:     aws.String(group),
			})
			var exists *iottypes.ResourceAlreadyExistsException
			if err != nil && !errors.As(err, &exists) {
				errs = append(errs, fmt.Errorf("attaching %s to %s: %w", a.cfg.DenyPolicy, group, err))
				continue
			}
			slog.Warn("Fleet group cut off with the deny-all policy", "group", group)
		}
	}
	return errors.Join(errs...)
}

// Handler processes the SNS records. A failure is returned so Lambda retries
// the asynchronous invocation; every action is idempotent, so a retry only
// finishes what failed.
func (a *App) Handler(ctx context.Context, event events.SNSEvent) error {
	var errs []error
	for _, record := range event.Records {
		scope, reason := a.classify(record.SNS.Message)
		if scope == ScopeNone {
			continue
		}
		slog.Warn("Guard tripped", "scope", scope.String(), "reason", reason)

		enforced, err := a.recordTrip(ctx, scope, reason)
		if err != nil {
			// Act anyway: stopping the cost matters more than the record.
			errs = append(errs, err)
		}
		if err := a.enforce(ctx, enforced); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// sortedKeys is for stable log output.
func sortedKeys(m map[string]Scope) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		slog.Error("Invalid configuration", "error", err)
		panic(err)
	}
	slog.Info("Kill switch configured", "alarms", sortedKeys(cfg.AlarmScopes), "budgets", sortedKeys(cfg.BudgetScopes))

	awsCfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		panic(fmt.Sprintf("unable to load SDK config: %v", err))
	}
	app := &App{
		iot: iot.NewFromConfig(awsCfg),
		ssm: ssm.NewFromConfig(awsCfg),
		cfg: cfg,
		now: time.Now,
	}
	lambda.Start(app.Handler)
}
