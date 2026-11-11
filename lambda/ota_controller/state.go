package main

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// OTA modes, the fleet attribute ota_mode. Only the owner sets it.
const (
	ModeAuto   = "auto"   // canary, soak, promote without a click
	ModeHold   = "hold"   // canary and soak; "ready to promote" email instead of promoting
	ModeFrozen = "frozen" // the controller leaves the product alone
)

// Fleet group attribute names.
const (
	attrMode          = "ota_mode"
	attrSoakHours     = "soak_hours"
	attrFleetVersion  = "fleet_version"
	attrHaltedVersion = "halted_version"
	attrHaltedReason  = "halted_reason"
	attrNotified      = "notified"
)

// Thing group attribute values allow only these characters, up to 800.
var attrUnsafe = regexp.MustCompile(`[^a-zA-Z0-9_.,@/:#-]`)

const (
	maxAttrLen      = 800
	maxNotifiedKeys = 40
)

func attrSafe(s string) string {
	s = attrUnsafe.ReplaceAllString(s, "_")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// FleetState is a product's OTA state, kept in the attributes of its fleet
// thing group, where the owner (CLI, portal) can read and set it. Terraform
// ignores the attributes, so an apply never resets them.
type FleetState struct {
	Mode          string
	SoakHours     int
	FleetVersion  Version // zero: none yet
	HaltedVersion Version // zero: none
	HaltedReason  string
	// Notified holds the keys of one-off emails already sent, oldest first,
	// so a condition that lasts many ticks emails once.
	Notified []string
}

// stateFromAttributes reads the attributes; a missing or unreadable value
// takes its default (auto, the product's soak).
func stateFromAttributes(attrs map[string]string, defaultSoak int) FleetState {
	s := FleetState{Mode: ModeAuto, SoakHours: defaultSoak}
	switch m := attrs[attrMode]; m {
	case ModeAuto, ModeHold, ModeFrozen:
		s.Mode = m
	}
	if n, err := strconv.Atoi(attrs[attrSoakHours]); err == nil && n >= 0 && n <= 168 {
		s.SoakHours = n
	}
	s.FleetVersion, _ = optionalVersion(attrs[attrFleetVersion])
	s.HaltedVersion, _ = optionalVersion(attrs[attrHaltedVersion])
	s.HaltedReason = attrs[attrHaltedReason]
	if n := attrs[attrNotified]; n != "" {
		s.Notified = strings.Split(n, ",")
	}
	return s
}

// attributes is the payload to merge into the group. An empty value deletes
// the attribute.
func (s FleetState) attributes() map[string]string {
	v := func(x Version) string {
		if x.IsZero() {
			return ""
		}
		return x.String()
	}
	notified := s.Notified
	if len(notified) > maxNotifiedKeys {
		notified = notified[len(notified)-maxNotifiedKeys:]
	}
	joined := strings.Join(notified, ",")
	for len(joined) > maxAttrLen {
		notified = notified[1:]
		joined = strings.Join(notified, ",")
	}
	return map[string]string{
		attrMode:          s.Mode,
		attrSoakHours:     strconv.Itoa(s.SoakHours),
		attrFleetVersion:  v(s.FleetVersion),
		attrHaltedVersion: v(s.HaltedVersion),
		attrHaltedReason:  attrSafe(s.HaltedReason),
		attrNotified:      joined,
	}
}

func (s FleetState) notified(key string) bool {
	for _, k := range s.Notified {
		if k == key {
			return true
		}
	}
	return false
}

// Shadow is what the controller reads from a device's `platform` shadow.
type Shadow struct {
	FW         string
	BootReason string
	BootCount  int
	KeyIDs     []string
	ReportedAt time.Time // when `fw` was last reported
}

// Device is a thing of the product's fleet hierarchy.
type Device struct {
	Thing  string
	Online bool
	// ConnectedAt is the start of the current (or last) session.
	ConnectedAt time.Time
	// Principal is the certificate id of the last connection.
	Principal string
	Shadow    *Shadow // nil: no platform shadow (or not loaded)
}

// isCrash mirrors device-core shadow::is_crash.
func isCrash(bootReason string) bool {
	switch bootReason {
	case "panic", "int_wdt", "task_wdt", "wdt", "cpu_lockup":
		return true
	}
	return false
}

// Execution statuses.
const (
	ExecQueued     = "QUEUED"
	ExecInProgress = "IN_PROGRESS"
	ExecSucceeded  = "SUCCEEDED"
	ExecFailed     = "FAILED"
	ExecTimedOut   = "TIMED_OUT"
	ExecRejected   = "REJECTED"
)

// Job statuses.
const (
	JobInProgress = "IN_PROGRESS"
	JobCanceled   = "CANCELED"
	JobCompleted  = "COMPLETED"
)

// Exec is one thing's execution of a job.
type Exec struct {
	Thing         string
	Status        string
	Reason        string // statusDetails.reason, loaded for failures only
	QueuedAt      time.Time
	LastUpdatedAt time.Time
}

func (e Exec) failed() bool {
	return e.Status == ExecFailed || e.Status == ExecTimedOut || e.Status == ExecRejected
}

func (e Exec) pending() bool { return e.Status == ExecQueued || e.Status == ExecInProgress }

// failureReason is the contract's reason code, or the status for a failure
// that carries none.
func (e Exec) failureReason() string {
	if e.Reason != "" {
		return e.Reason
	}
	if e.Status == ExecTimedOut {
		return "timeout"
	}
	return strings.ToLower(e.Status)
}

// Job is an OTA job of the product.
type Job struct {
	ID        JobID
	RawID     string
	Status    string
	CreatedAt time.Time
	// Execs is loaded only for the jobs the planner looks into: the newest
	// canary job of the desired version and the active fleet job.
	Execs []Exec
}

func (j *Job) active() bool { return j.Status == JobInProgress }

// Release is a verified release: its manifest verified against the
// product's signing keys and binds the product and the version of its key.
type Release struct {
	Version  Version
	Manifest string
	Sig      string
	KeyID    string
}

// BadRelease is a version directory whose manifest failed verification.
type BadRelease struct {
	Version string
	Reason  string
}

// Snapshot is everything the planner decides from, for one product.
type Snapshot struct {
	Product ProductConfig
	Now     time.Time
	State   FleetState

	Releases []Release // verified, ascending
	Bad      []BadRelease

	Jobs []*Job // every job of the product, any status

	// Fleet holds every thing of the fleet hierarchy (the fleet group and its
	// canary child), with presence and, when needed, the platform shadow.
	Fleet    map[string]*Device
	Canary   map[string]bool // members of the canary group
	Excluded map[string]bool // members of the excluded group
	// Preferred are things whose registry record says canary=true.
	Preferred []string

	// Orphans are versions released on GitHub over an hour ago that never
	// reached S3 (loaded hourly).
	Orphans []string

	ThingARN func(thing string) string
}
