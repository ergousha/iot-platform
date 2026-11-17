package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/pricingplanmanager"
	ppmtypes "github.com/aws/aws-sdk-go-v2/service/pricingplanmanager/types"
)

type fakePlans struct {
	subs  []ppmtypes.SubscriptionSummary
	calls int
}

func (f *fakePlans) ListSubscriptions(context.Context, *pricingplanmanager.ListSubscriptionsInput, ...func(*pricingplanmanager.Options)) (*pricingplanmanager.ListSubscriptionsOutput, error) {
	f.calls++
	return &pricingplanmanager.ListSubscriptionsOutput{SubscriptionSummaries: f.subs}, nil
}

const (
	firmwareDist = "arn:aws:cloudfront::1:distribution/EFIRMWARE"
	portalDist   = "arn:aws:cloudfront::1:distribution/EPORTAL"
)

func freeSub(dist string) ppmtypes.SubscriptionSummary {
	return ppmtypes.SubscriptionSummary{
		PlanFamily: aws.String("CloudFront"), PlanTier: aws.String("FREE"), Status: ppmtypes.StatusActive,
		ResourceArns: []string{dist, "arn:aws:wafv2:us-east-1:1:global/webacl/CreatedByCloudFront-x/1"},
	}
}

func TestPricingPlanProblems(t *testing.T) {
	dists := map[string]string{"firmware": firmwareDist, "portal": portalDist}
	if p := pricingPlanProblems(dists, []ppmtypes.SubscriptionSummary{freeSub(firmwareDist), freeSub(portalDist)}); len(p) != 0 {
		t.Fatalf("both on Free: %v", p)
	}

	paid := freeSub(portalDist)
	paid.PlanTier = aws.String("PRO")
	failed := freeSub(firmwareDist)
	failed.Status = ppmtypes.StatusFailed
	for _, tc := range []struct {
		name string
		subs []ppmtypes.SubscriptionSummary
		want []string // one per problem, in order
	}{
		{"pay-as-you-go", []ppmtypes.SubscriptionSummary{freeSub(firmwareDist)}, []string{"portal (" + portalDist + ") is on no flat-rate plan"}},
		{"paid tier", []ppmtypes.SubscriptionSummary{freeSub(firmwareDist), paid}, []string{"portal is on the CloudFront PRO plan"}},
		{"not active", []ppmtypes.SubscriptionSummary{failed, freeSub(portalDist)}, []string{"firmware: its FREE plan is FAILED"}},
		{"no web ACL", []ppmtypes.SubscriptionSummary{freeSub(firmwareDist), {
			PlanFamily: aws.String("CloudFront"), PlanTier: aws.String("FREE"), Status: ppmtypes.StatusActive, ResourceArns: []string{portalDist},
		}}, []string{"portal: its Free plan covers no WAF web ACL"}},
		{"cancellation scheduled", []ppmtypes.SubscriptionSummary{func() ppmtypes.SubscriptionSummary {
			s := freeSub(firmwareDist)
			s.ScheduledChange = &ppmtypes.ScheduledChange{ChangeType: ppmtypes.ScheduledChangeTypeCancellation, EffectiveDate: aws.Time(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))}
			return s
		}(), freeSub(portalDist)}, []string{"firmware: a cancellation of its Free plan is scheduled for 2026-12-01"}},
		{"none at all", nil, []string{"firmware (", "portal ("}},
	} {
		got := pricingPlanProblems(dists, tc.subs)
		if len(got) != len(tc.want) {
			t.Errorf("%s: %v", tc.name, got)
			continue
		}
		for i, w := range tc.want {
			if !strings.HasPrefix(got[i], w) {
				t.Errorf("%s: problem %d = %q, want prefix %q", tc.name, i, got[i], w)
			}
		}
	}
}

// One email per set of problems; none while they stay the same; a fix
// re-arms the check.
func TestCheckPricingPlansEmailsOnce(t *testing.T) {
	ctx := context.Background()
	a, _, _, _, snsf, _ := testApp()
	plans := &fakePlans{subs: []ppmtypes.SubscriptionSummary{freeSub(firmwareDist)}}
	a.plans = plans
	a.cfg.Distributions = map[string]string{"firmware": firmwareDist, "portal": portalDist}

	for range 2 {
		if err := a.checkPricingPlans(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(snsf.subjects) != 1 || !strings.Contains(snsf.subjects[0], "not on the Free plan") {
		t.Fatalf("emails %v", snsf.subjects)
	}

	plans.subs = append(plans.subs, freeSub(portalDist)) // fixed
	if err := a.checkPricingPlans(ctx); err != nil || len(snsf.subjects) != 1 {
		t.Fatalf("after the fix: %v %v", err, snsf.subjects)
	}
	plans.subs = plans.subs[:1] // off the plan again
	if err := a.checkPricingPlans(ctx); err != nil || len(snsf.subjects) != 2 {
		t.Fatalf("again: %v %v", err, snsf.subjects)
	}

	a.cfg.Distributions = nil // nothing to check: no call
	before := plans.calls
	if err := a.checkPricingPlans(ctx); err != nil || plans.calls != before {
		t.Fatalf("no distributions: %v, %d calls", err, plans.calls-before)
	}
}
