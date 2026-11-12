package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

var productIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]{1,15}$`)

// Group is an IoT thing group.
type Group struct {
	Name string
	ARN  string
}

// ProductConfig is one product's deployment, from the PRODUCTS variable.
type ProductConfig struct {
	ID string
	// Fleet is the CONTINUOUS fleet job's target; it holds the OTA state
	// attributes. Canary is its child group. Excluded is outside the
	// hierarchy: things moved there get no fleet job.
	Fleet, Canary, Excluded Group
	// Repository is owner/name on GitHub (download URL template, reconcile).
	Repository string
	// SoakHours is the default soak; the fleet attribute soak_hours wins.
	SoakHours int
	// Legacy: registry records without a product attribute are this product's.
	Legacy bool
}

// Config is the Lambda's environment. Terraform holds every default; a
// missing or malformed value means a broken deployment, and the Lambda
// refuses to start.
type Config struct {
	Region  string
	Account string
	Bucket  string

	Products map[string]ProductConfig

	// DownloadURLTemplate is the image URL put into job documents, with
	// {product}, {version} and {repository} placeholders. The CloudFront
	// distribution by default; GitHub Release assets as the fallback.
	DownloadURLTemplate string

	RegistryTable string
	PresenceTable string

	GuardStateParameter string
	// SigningKeysParameter has a {product} placeholder.
	SigningKeysParameter string

	ClaimPolicy         string
	ClaimCertParameter  string
	ClaimKeyParameter   string
	ClaimStateParameter string

	TopicARN        string
	IoTDataEndpoint string

	// The guard, for the owner's guard-reset and quarantine overrides.
	// DenyPolicy is the kill switch's deny-all policy; it stays on the
	// quarantine group. RestoreRules are the rules a reset re-enables: the
	// ones Terraform configures as enabled.
	Quarantine   Group
	DenyPolicy   string
	RestoreRules []string

	// ViewerRoles are IAM role names whose Function URL callers may only
	// read (the portal's viewer role).
	ViewerRoles []string

	RolloutBaseRatePerMinute int32
	RolloutIncrementFactor   float64
	RolloutSucceededThings   int32
	RolloutMaxPerMinute      int32
	InProgressTimeoutMinutes int64
}

type productJSON struct {
	FleetGroupARN    string `json:"fleet_group_arn"`
	CanaryGroupARN   string `json:"canary_group_arn"`
	ExcludedGroupARN string `json:"excluded_group_arn"`
	Repository       string `json:"repository"`
	SoakHours        int    `json:"soak_hours"`
	Legacy           bool   `json:"legacy"`
}

type envParser struct {
	getenv func(string) string
	errs   []error
}

func (p *envParser) required(name string) string {
	v := p.getenv(name)
	if v == "" {
		p.errs = append(p.errs, fmt.Errorf("%s is not set", name))
	}
	return v
}

func (p *envParser) integer(name string, lo, hi int64) int64 {
	v := p.required(name)
	if v == "" {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < lo || n > hi {
		p.errs = append(p.errs, fmt.Errorf("%s=%q: must be an integer from %d to %d", name, v, lo, hi))
	}
	return n
}

// stringList reads a JSON list of strings; it must be set, and may be [].
func (p *envParser) stringList(name string) []string {
	v := p.required(name)
	if v == "" {
		return nil
	}
	var list []string
	if err := json.Unmarshal([]byte(v), &list); err != nil {
		p.errs = append(p.errs, fmt.Errorf("%s=%q: must be a JSON list of strings", name, v))
	}
	return list
}

func groupFromARN(value string) (Group, bool) {
	a, err := arn.Parse(value)
	name, found := strings.CutPrefix(a.Resource, "thinggroup/")
	if err != nil || a.Service != "iot" || !found || name == "" {
		return Group{}, false
	}
	return Group{Name: name, ARN: value}, true
}

func loadConfig(getenv func(string) string) (Config, error) {
	p := &envParser{getenv: getenv}
	c := Config{
		Region:               p.required("AWS_REGION"),
		Account:              p.required("ACCOUNT_ID"),
		Bucket:               p.required("FIRMWARE_BUCKET"),
		DownloadURLTemplate:  p.required("DOWNLOAD_URL_TEMPLATE"),
		RegistryTable:        p.required("REGISTRY_TABLE"),
		PresenceTable:        p.required("PRESENCE_TABLE"),
		GuardStateParameter:  p.required("GUARD_STATE_PARAMETER"),
		SigningKeysParameter: p.required("SIGNING_KEYS_PARAMETER"),
		ClaimPolicy:          p.required("CLAIM_POLICY"),
		ClaimCertParameter:   p.required("CLAIM_CERT_PARAMETER"),
		ClaimKeyParameter:    p.required("CLAIM_KEY_PARAMETER"),
		ClaimStateParameter:  p.required("CLAIM_STATE_PARAMETER"),
		TopicARN:             p.required("NOTIFY_TOPIC_ARN"),
		IoTDataEndpoint:      p.required("IOT_DATA_ENDPOINT"),
	}
	if q := p.required("QUARANTINE_GROUP_ARN"); q != "" {
		var ok bool
		if c.Quarantine, ok = groupFromARN(q); !ok {
			p.errs = append(p.errs, fmt.Errorf("QUARANTINE_GROUP_ARN=%q: not a thing group ARN", q))
		}
	}
	c.DenyPolicy = p.required("DENY_POLICY")
	c.RestoreRules = p.stringList("RESTORE_RULES")
	c.ViewerRoles = p.stringList("VIEWER_ROLES")
	if c.DownloadURLTemplate != "" && (!strings.HasPrefix(c.DownloadURLTemplate, "https://") || !strings.Contains(c.DownloadURLTemplate, "{version}")) {
		p.errs = append(p.errs, fmt.Errorf("DOWNLOAD_URL_TEMPLATE=%q: must be an https URL with a {version} placeholder", c.DownloadURLTemplate))
	}
	if c.SigningKeysParameter != "" && !strings.Contains(c.SigningKeysParameter, "{product}") {
		p.errs = append(p.errs, errors.New("SIGNING_KEYS_PARAMETER needs a {product} placeholder"))
	}

	c.RolloutBaseRatePerMinute = int32(p.integer("OTA_ROLLOUT_BASE_RATE_PER_MINUTE", 1, 1000))
	c.RolloutSucceededThings = int32(p.integer("OTA_ROLLOUT_SUCCEEDED_THINGS", 1, math.MaxInt32))
	c.RolloutMaxPerMinute = int32(p.integer("OTA_ROLLOUT_MAX_PER_MINUTE", 1, math.MaxInt32))
	c.InProgressTimeoutMinutes = p.integer("OTA_IN_PROGRESS_TIMEOUT_MINUTES", 1, 10080)
	if v := p.required("OTA_ROLLOUT_INCREMENT_FACTOR"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || !regexp.MustCompile(`^[0-9]+(\.[0-9])?$`).MatchString(v) || f < 1.1 || f > 5 {
			p.errs = append(p.errs, fmt.Errorf("OTA_ROLLOUT_INCREMENT_FACTOR=%q: must be from 1.1 to 5 with at most one decimal", v))
		}
		c.RolloutIncrementFactor = f
	}
	if c.RolloutBaseRatePerMinute > c.RolloutMaxPerMinute && c.RolloutMaxPerMinute > 0 {
		p.errs = append(p.errs, errors.New("OTA_ROLLOUT_BASE_RATE_PER_MINUTE must not exceed OTA_ROLLOUT_MAX_PER_MINUTE"))
	}

	if raw := p.required("PRODUCTS"); raw != "" {
		var products map[string]productJSON
		if err := json.Unmarshal([]byte(raw), &products); err != nil || len(products) == 0 {
			p.errs = append(p.errs, errors.New("PRODUCTS must be a non-empty JSON object"))
		}
		c.Products = map[string]ProductConfig{}
		legacy := 0
		for id, pj := range products {
			fleet, ok1 := groupFromARN(pj.FleetGroupARN)
			canary, ok2 := groupFromARN(pj.CanaryGroupARN)
			excluded, ok3 := groupFromARN(pj.ExcludedGroupARN)
			switch {
			case !productIDPattern.MatchString(id):
				p.errs = append(p.errs, fmt.Errorf("PRODUCTS: %q is not a product id", id))
			case !ok1 || !ok2 || !ok3:
				p.errs = append(p.errs, fmt.Errorf("PRODUCTS[%s]: fleet, canary and excluded group ARNs are required", id))
			case !regexp.MustCompile(`^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$`).MatchString(pj.Repository):
				p.errs = append(p.errs, fmt.Errorf("PRODUCTS[%s]: repository must be owner/name", id))
			case pj.SoakHours < 0 || pj.SoakHours > 168:
				p.errs = append(p.errs, fmt.Errorf("PRODUCTS[%s]: soak_hours must be 0-168", id))
			}
			if pj.Legacy {
				legacy++
			}
			c.Products[id] = ProductConfig{
				ID: id, Fleet: fleet, Canary: canary, Excluded: excluded,
				Repository: pj.Repository, SoakHours: pj.SoakHours, Legacy: pj.Legacy,
			}
		}
		if legacy > 1 {
			p.errs = append(p.errs, errors.New("PRODUCTS: at most one product may be legacy"))
		}
	}
	return c, errors.Join(p.errs...)
}

// downloadURL is the image URL of a release.
func (c Config) downloadURL(p ProductConfig, v Version) string {
	return strings.NewReplacer("{product}", p.ID, "{version}", v.String(), "{repository}", p.Repository).
		Replace(c.DownloadURLTemplate)
}

func (c Config) thingARN(thing string) string {
	return fmt.Sprintf("arn:aws:iot:%s:%s:thing/%s", c.Region, c.Account, thing)
}

func (c Config) signingKeysParameter(product string) string {
	return strings.ReplaceAll(c.SigningKeysParameter, "{product}", product)
}
