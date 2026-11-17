package main

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/pricingplanmanager"
	ppmtypes "github.com/aws/aws-sdk-go-v2/service/pricingplanmanager/types"
)

// PricingPlanAPI lists the account's flat-rate pricing plan subscriptions.
type PricingPlanAPI interface {
	ListSubscriptions(context.Context, *pricingplanmanager.ListSubscriptionsInput, ...func(*pricingplanmanager.Options)) (*pricingplanmanager.ListSubscriptionsOutput, error)
}

// pricingPlanProblems names every CloudFront distribution that is not safely
// on the Free flat-rate plan: in no subscription (pay-as-you-go), in one that
// is not ACTIVE, on a paid tier (a monthly fee), without its WAF web ACL, or
// with a cancellation or downgrade scheduled. Sorted, so the same problems
// give the same text.
func pricingPlanProblems(distributions map[string]string, subs []ppmtypes.SubscriptionSummary) []string {
	var problems []string
	for name, arn := range distributions {
		i := slices.IndexFunc(subs, func(s ppmtypes.SubscriptionSummary) bool {
			return slices.Contains(s.ResourceArns, arn)
		})
		if i < 0 {
			problems = append(problems, fmt.Sprintf("%s (%s) is on no flat-rate plan: pay-as-you-go, billed per request and GB", name, arn))
			continue
		}
		s := subs[i]
		tier := aws.ToString(s.PlanTier)
		hasACL := slices.ContainsFunc(s.ResourceArns, func(r string) bool { return strings.Contains(r, ":wafv2:") })
		switch {
		case s.Status != ppmtypes.StatusActive:
			problems = append(problems, fmt.Sprintf("%s: its %s plan is %s (%s)", name, tier, s.Status, aws.ToString(s.StatusReason)))
		case aws.ToString(s.PlanFamily) != "CloudFront" || tier != "FREE":
			problems = append(problems, fmt.Sprintf("%s is on the %s %s plan, not Free: a monthly fee", name, aws.ToString(s.PlanFamily), tier))
		case !hasACL:
			problems = append(problems, fmt.Sprintf("%s: its Free plan covers no WAF web ACL", name))
		case s.ScheduledChange != nil:
			problems = append(problems, fmt.Sprintf("%s: a %s of its Free plan is scheduled for %s",
				name, strings.ToLower(string(s.ScheduledChange.ChangeType)), aws.ToTime(s.ScheduledChange.EffectiveDate).Format("2006-01-02")))
		}
	}
	sort.Strings(problems)
	return problems
}

// checkPricingPlans (hourly) emails the owner when a CloudFront distribution
// is not safely on the Free flat-rate plan, which is what keeps a download
// flood from billing anything (the kill switch does not touch CloudFront). It
// emails once per set of problems, and again only when they change; a fix
// re-arms it.
func (a *App) checkPricingPlans(ctx context.Context) error {
	if len(a.cfg.Distributions) == 0 {
		return nil
	}
	var subs []ppmtypes.SubscriptionSummary
	p := pricingplanmanager.NewListSubscriptionsPaginator(a.plans, &pricingplanmanager.ListSubscriptionsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("listing pricing plan subscriptions: %w", err)
		}
		subs = append(subs, page.SubscriptionSummaries...)
	}
	problems := pricingPlanProblems(a.cfg.Distributions, subs)
	key := strings.Join(problems, "\n")

	st, err := a.claimState(ctx)
	if err != nil {
		return err
	}
	if st.PricingPlan == key {
		return nil
	}
	if key != "" {
		body := "CloudFront distributions not safely on the Free flat-rate plan:\n\n" + key +
			"\n\nOff the plan, CloudFront bills per request and GB past the always-free allowance, and the kill switch does not " +
			"disable CloudFront. Put the distribution back on the Free plan (CloudFront console > the distribution > Pricing plan, " +
			"or terraform apply in iot-platform, which manages the subscriptions), or move firmware downloads to GitHub Releases " +
			"(firmware_download_url_template)."
		if err := a.notify(ctx, "CloudFront is not on the Free plan", body); err != nil {
			return err
		}
	}
	st.PricingPlan = key
	return a.saveClaimState(ctx, st)
}
