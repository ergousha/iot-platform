package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Version is a bare semver X.Y.Z, the only form a release may take.
type Version struct {
	Major, Minor, Patch int
}

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)

// ParseVersion accepts `X.Y.Z`, with an optional leading `v` or `firmware_v`
// (tags and legacy file names). No pre-release or build suffix: the device
// compares bare versions too.
func ParseVersion(s string) (Version, error) {
	bare := strings.TrimPrefix(strings.TrimPrefix(s, "firmware_"), "v")
	m := versionPattern.FindStringSubmatch(bare)
	if m == nil {
		return Version{}, fmt.Errorf("%q is not a bare X.Y.Z version", s)
	}
	n := func(i int) int { v, _ := strconv.Atoi(m[i]); return v }
	return Version{n(1), n(2), n(3)}, nil
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Slug is the version as it appears in job ids: X_Y_Z.
func (v Version) Slug() string { return fmt.Sprintf("%d_%d_%d", v.Major, v.Minor, v.Patch) }

// IsZero is the "no version" value.
func (v Version) IsZero() bool { return v == Version{} }

// Compare returns -1, 0 or 1.
func (v Version) Compare(o Version) int {
	for _, d := range [][2]int{{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch}} {
		switch {
		case d[0] < d[1]:
			return -1
		case d[0] > d[1]:
			return 1
		}
	}
	return 0
}

func (v Version) Less(o Version) bool { return v.Compare(o) < 0 }

// optionalVersion parses a fleet attribute that may be empty.
func optionalVersion(s string) (Version, bool) {
	if s == "" {
		return Version{}, false
	}
	v, err := ParseVersion(s)
	return v, err == nil
}
