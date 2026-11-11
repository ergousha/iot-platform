// Command ota_controller is the platform's release pipeline and claim
// lifecycle, replacing the ota_trigger Lambda (platform plan, Phase 3).
//
// It runs on three triggers:
//
//   - every 15 minutes (EventBridge Scheduler, {"action":"tick"}): the source
//     of truth. A dropped S3 event or a failed invocation only delays the
//     next step;
//   - the S3 ObjectCreated event of releases/<p>/<X.Y.Z>/manifest.sig, the
//     last object a release uploads: a tick of that product, right away;
//   - owner overrides: `aws lambda invoke` (scripts/ota.sh) or the AWS_IAM
//     Function URL (the portal, Phase 4).
//
// Per product, a tick verifies new releases against the product's signing
// keys, runs the newest through a canary job and a soak gate, promotes it to
// the fleet, halts on canary failures and excludes single failing fleet
// devices, and emails the owner at each step (SNS). Its state is in the fleet
// thing group's attributes. Account-wide, it arms the claim only while an
// enrolment window is open, rotates it after site windows, and (hourly)
// deletes stale certificates and reports releases that never reached S3.
//
// Nothing happens while the kill switch has tripped.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	"github.com/aws/aws-sdk-go-v2/service/iotdataplane"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// event is what any trigger sends, decoded loosely to tell them apart.
type event struct {
	Records []struct {
		EventSource string `json:"eventSource"`
		S3          struct {
			Object struct {
				Key string `json:"key"`
			} `json:"object"`
		} `json:"s3"`
	} `json:"Records"`
	RequestContext *struct {
		HTTP *struct {
			Method string `json:"method"`
		} `json:"http"`
	} `json:"requestContext"`
	Body            string `json:"body"`
	IsBase64Encoded bool   `json:"isBase64Encoded"`
	Override
}

// Result is the answer to an override or a tick.
type Result struct {
	OK     bool     `json:"ok"`
	Error  string   `json:"error,omitempty"`
	Plan   string   `json:"plan,omitempty"`
	Log    []string `json:"log,omitempty"`
	Status any      `json:"status,omitempty"`
}

// Handle dispatches one invocation. Asynchronous triggers (the schedule, S3)
// get an error back on failure, so Lambda retries and then reports to the
// on-failure destination; overrides get a Result.
func (a *App) Handle(ctx context.Context, raw json.RawMessage) (any, error) {
	var ev event
	if err := json.Unmarshal(raw, &ev); err != nil {
		return nil, fmt.Errorf("unreadable event: %w", err)
	}
	switch {
	case len(ev.Records) > 0:
		products := map[string]bool{}
		for _, r := range ev.Records {
			if r.EventSource != "aws:s3" {
				continue
			}
			parts := strings.Split(r.S3.Object.Key, "/")
			if len(parts) == 4 && parts[0] == "releases" && parts[3] == "manifest.sig" {
				if _, ok := a.cfg.Products[parts[1]]; ok {
					products[parts[1]] = true
				}
			}
		}
		if len(products) == 0 {
			slog.Warn("S3 event for no product's manifest.sig", "event", string(raw))
			return Result{OK: true}, nil
		}
		return a.tick(ctx, products, false)

	case ev.RequestContext != nil && ev.RequestContext.HTTP != nil:
		return a.functionURL(ctx, ev), nil

	case ev.Action == "tick":
		return a.tick(ctx, nil, a.now().Minute() < 15)

	case ev.Action != "":
		return a.override(ctx, ev.Override), nil
	}
	return nil, errors.New("unrecognised event")
}

// functionURL answers a Function URL request. AWS_IAM auth has already
// checked the caller's signature and lambda:InvokeFunctionUrl.
func (a *App) functionURL(ctx context.Context, ev event) events.LambdaFunctionURLResponse {
	respond := func(code int, r Result) events.LambdaFunctionURLResponse {
		b, _ := json.Marshal(r)
		return events.LambdaFunctionURLResponse{StatusCode: code, Body: string(b), Headers: map[string]string{"Content-Type": "application/json"}}
	}
	if ev.RequestContext.HTTP.Method != http.MethodPost {
		return respond(http.StatusMethodNotAllowed, Result{Error: "POST only"})
	}
	body := []byte(ev.Body)
	if ev.IsBase64Encoded {
		var err error
		if body, err = base64.StdEncoding.DecodeString(ev.Body); err != nil {
			return respond(http.StatusBadRequest, Result{Error: "body is not base64"})
		}
	}
	var o Override
	if err := json.Unmarshal(body, &o); err != nil || o.Action == "" || o.Action == "tick" {
		return respond(http.StatusBadRequest, Result{Error: "body must be an override: {\"action\":...,\"product\":...}"})
	}
	r := a.override(ctx, o)
	if !r.OK {
		return respond(http.StatusBadRequest, r)
	}
	return respond(http.StatusOK, r)
}

// tick reconciles the given products (nil: all) and, on the scheduled tick,
// the claim. Hourly ticks also check GitHub and clean certificates.
func (a *App) tick(ctx context.Context, only map[string]bool, hourly bool) (Result, error) {
	g, err := a.loadGlobal(ctx)
	if err != nil {
		return Result{}, err
	}
	guard, gerr := a.guard(ctx)
	var errs []error
	if gerr != nil {
		errs = append(errs, gerr)
	}
	if only == nil {
		if err := a.claimTick(ctx, g.records, guard.Tripped); err != nil {
			errs = append(errs, fmt.Errorf("claim: %w", err))
		}
	}
	if guard.Tripped {
		slog.Warn("Guard tripped: no rollout", "scope", guard.Scope)
		return Result{OK: true, Log: []string{"guard tripped (" + guard.Scope + "): nothing rolled out"}}, errors.Join(errs...)
	}

	var log []string
	for _, id := range a.productIDs() {
		if only != nil && !only[id] {
			continue
		}
		p := a.cfg.Products[id]
		s, meta, err := a.snapshot(ctx, p, g, loadOptions{orphans: hourly})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		plan := planTick(s)
		for _, l := range plan.Log {
			log = append(log, id+": "+l)
		}
		if len(plan.Actions) > 0 {
			slog.Info("Plan", "product", id, "plan", plan.String(), "log", plan.Log)
		}
		if err := a.execute(ctx, s, meta, plan); err != nil {
			errs = append(errs, err)
		}
	}
	if hourly {
		if err := a.certHygiene(ctx, g.presence); err != nil {
			errs = append(errs, fmt.Errorf("certificate hygiene: %w", err))
		}
	}
	return Result{OK: len(errs) == 0, Log: log}, errors.Join(errs...)
}

func (a *App) productIDs() []string {
	ids := make([]string, 0, len(a.cfg.Products))
	for id := range a.cfg.Products {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// override runs one owner command.
func (a *App) override(ctx context.Context, o Override) Result {
	fail := func(err error) Result {
		slog.Error("Override failed", "action", o.Action, "product", o.Product, "error", err)
		return Result{Error: err.Error()}
	}
	slog.Info("Override", "override", o)

	switch o.Action {
	case "tick":
		r, err := a.tick(ctx, nil, false)
		if err != nil {
			r.Error = err.Error()
		}
		return r
	case "rotate-claim":
		guard, err := a.guard(ctx)
		if err != nil || guard.Tripped {
			return fail(fmt.Errorf("refusing while the guard is tripped or unreadable (%v)", err))
		}
		if err := a.rotateClaim(ctx, "requested by the owner"); err != nil {
			return fail(err)
		}
		return Result{OK: true, Log: []string{"claim rotated"}}
	}

	p, ok := a.cfg.Products[o.Product]
	if !ok {
		return fail(fmt.Errorf("unknown product %q", o.Product))
	}
	if o.createsJobs() {
		guard, err := a.guard(ctx)
		if err != nil || guard.Tripped {
			return fail(fmt.Errorf("refusing %s while the guard is tripped or unreadable (%v)", o.Action, err))
		}
	}
	g, err := a.loadGlobal(ctx)
	if err != nil {
		return fail(err)
	}
	s, meta, err := a.snapshot(ctx, p, g, loadOptions{allVersions: true, shadows: true})
	if err != nil {
		return fail(err)
	}
	if o.Action == "status" {
		return Result{OK: true, Status: status(s)}
	}
	plan, err := planOverride(s, o)
	if err != nil {
		return fail(err)
	}
	if err := a.execute(ctx, s, meta, plan); err != nil {
		return fail(err)
	}
	return Result{OK: true, Plan: plan.String(), Log: plan.Log}
}

// status is a product's state for the owner (scripts/ota.sh status).
func status(s *Snapshot) map[string]any {
	var releases, active []string
	for _, r := range s.Releases {
		releases = append(releases, r.Version.String()+" ("+r.KeyID+")")
	}
	for _, j := range s.Jobs {
		if j.active() {
			active = append(active, j.RawID)
		}
	}
	devices := map[string]any{}
	for t, d := range s.Fleet {
		dev := map[string]any{"online": d.Online, "canary": s.Canary[t]}
		if d.Shadow != nil {
			dev["fw"], dev["boot_reason"], dev["boot_count"], dev["key_id"] = d.Shadow.FW, d.Shadow.BootReason, d.Shadow.BootCount, d.Shadow.KeyIDs
		}
		devices[t] = dev
	}
	var excluded []string
	for t := range s.Excluded {
		excluded = append(excluded, t)
	}
	sort.Strings(excluded)
	return map[string]any{
		"product": s.Product.ID, "state": s.State.attributes(),
		"verified_releases": releases, "refused_releases": s.Bad,
		"active_jobs": active, "devices": devices, "excluded": excluded,
	}
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		slog.Error("Invalid configuration", "error", err)
		panic(err)
	}
	awsCfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		panic(fmt.Sprintf("unable to load SDK config: %v", err))
	}
	app := &App{
		cfg: cfg,
		iot: iot.NewFromConfig(awsCfg),
		shadow: iotdataplane.NewFromConfig(awsCfg, func(o *iotdataplane.Options) {
			o.BaseEndpoint = aws.String("https://" + cfg.IoTDataEndpoint)
		}),
		s3:   s3.NewFromConfig(awsCfg),
		ssm:  ssm.NewFromConfig(awsCfg),
		ddb:  dynamodb.NewFromConfig(awsCfg),
		sns:  sns.NewFromConfig(awsCfg),
		http: &http.Client{Timeout: 5 * time.Second},
		now:  time.Now,
	}
	lambda.Start(app.Handle)
}
