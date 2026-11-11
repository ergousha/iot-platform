package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Job kinds, the letter in the job id.
const (
	KindCanary = "c" // SNAPSHOT job on the product's canary group
	KindFleet  = "f" // CONTINUOUS job on the product's fleet group
	KindTarget = "t" // SNAPSHOT job on one thing (the `target` override)
)

const maxJobIDLength = 64

// JobID is a parsed OTA job id:
//
//	ota-<product>-<X_Y_Z>-c[-rN]
//	ota-<product>-<X_Y_Z>-f[-rN]
//	ota-<product>-<X_Y_Z>-t-<thing>[-rN]
//
// Deterministic, so a retried or concurrent invocation that creates the same
// job gets ResourceAlreadyExists, which counts as success. A rerun (or a
// version fleet-rolled again after a rollback) takes the next free -rN.
//
// Legacy ids, `ota-<product>-<anything>-<unix ms>` from the old ota_trigger
// Lambda, are recognised only so they can be cancelled.
type JobID struct {
	Product string
	Version Version
	Kind    string
	Thing   string // KindTarget only
	Rerun   int    // 0: none
	Legacy  bool
}

var (
	modernRest = regexp.MustCompile(`^([0-9]+_[0-9]+_[0-9]+)-(c|f|t-([A-Za-z0-9_:]+?))(?:-r([1-9][0-9]{0,2}))?$`)
	legacyRest = regexp.MustCompile(`-[0-9]{10,}$`)
)

func (j JobID) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "ota-%s-%s-%s", j.Product, j.Version.Slug(), j.Kind)
	if j.Kind == KindTarget {
		b.WriteString("-" + j.Thing)
	}
	if j.Rerun > 0 {
		fmt.Fprintf(&b, "-r%d", j.Rerun)
	}
	return b.String()
}

// Valid reports whether the id fits AWS IoT's limits.
func (j JobID) Valid() bool {
	s := j.String()
	return len(s) <= maxJobIDLength && regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(s)
}

// ParseJobID parses an id of one of the given products. ok is false for
// anything else (not an OTA job, another product, unparseable).
func ParseJobID(id string, products map[string]ProductConfig) (JobID, bool) {
	rest, found := strings.CutPrefix(id, "ota-")
	if !found {
		return JobID{}, false
	}
	product, rest, found := strings.Cut(rest, "-")
	if _, known := products[product]; !found || !known {
		return JobID{}, false
	}
	if m := modernRest.FindStringSubmatch(rest); m != nil {
		v, err := ParseVersion(strings.ReplaceAll(m[1], "_", "."))
		if err != nil {
			return JobID{}, false
		}
		j := JobID{Product: product, Version: v, Kind: m[2]}
		if strings.HasPrefix(m[2], "t-") {
			j.Kind, j.Thing = KindTarget, m[3]
		}
		if m[4] != "" {
			j.Rerun, _ = strconv.Atoi(m[4])
		}
		return j, true
	}
	if legacyRest.MatchString(rest) {
		return JobID{Product: product, Legacy: true}, true
	}
	return JobID{}, false
}

// nextFree returns base with the lowest rerun number whose id is not in used.
func nextFree(base JobID, used map[string]bool) JobID {
	for n := base.Rerun; ; n++ {
		base.Rerun = n
		if !used[base.String()] {
			return base
		}
	}
}
