package main

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func ver(s string) Version {
	v, err := ParseVersion(s)
	if err != nil {
		panic(err)
	}
	return v
}

func rel(s string) Release {
	return Release{Version: ver(s), Manifest: `{"m":"` + s + `"}`, Sig: "sig-" + s, KeyID: "vaktus-a"}
}

var vaktus = ProductConfig{
	ID:         "vaktus",
	Fleet:      Group{Name: "esp32-ztp-vaktus-fleet", ARN: "arn:aws:iot:eu-central-1:1:thinggroup/esp32-ztp-vaktus-fleet"},
	Canary:     Group{Name: "esp32-ztp-vaktus-canary", ARN: "arn:aws:iot:eu-central-1:1:thinggroup/esp32-ztp-vaktus-canary"},
	Excluded:   Group{Name: "esp32-ztp-vaktus-excluded", ARN: "arn:aws:iot:eu-central-1:1:thinggroup/esp32-ztp-vaktus-excluded"},
	Repository: "ergousha/esp32-display-vaktus-salat-rust",
	SoakHours:  24,
}

// shadowOn: a device that runs fw, booted once since the update, accepts
// the vaktus-a key and reported at `at`.
func shadowOn(fw string, at time.Time) *Shadow {
	return &Shadow{FW: fw, BootReason: "sw", BootCount: 1, KeyIDs: []string{"vaktus-a", "vaktus-b"}, ReportedAt: at}
}

// fixture: fleet at 0.9.1 with canary C1 and fleet devices F1, F2, all
// online since t0-48h, all running 0.9.1 with the signing keys.
func fixture() *Snapshot {
	s := &Snapshot{
		Product: vaktus, Now: t0,
		State:    FleetState{Mode: ModeAuto, SoakHours: 24, FleetVersion: ver("0.9.1")},
		Releases: []Release{rel("0.9.1")},
		Fleet:    map[string]*Device{},
		Canary:   map[string]bool{"C1": true},
		Excluded: map[string]bool{},
		ThingARN: func(t string) string { return "arn:aws:iot:eu-central-1:1:thing/" + t },
	}
	for _, t := range []string{"C1", "F1", "F2"} {
		s.Fleet[t] = &Device{Thing: t, Online: true, ConnectedAt: t0.Add(-48 * time.Hour), Shadow: shadowOn("0.9.1", t0.Add(-47*time.Hour))}
	}
	s.Jobs = []*Job{{ID: JobID{Product: "vaktus", Version: ver("0.9.1"), Kind: KindFleet}, RawID: "ota-vaktus-0_9_1-f", Status: JobInProgress, CreatedAt: t0.Add(-72 * time.Hour),
		Execs: []Exec{{Thing: "C1", Status: ExecSucceeded}, {Thing: "F1", Status: ExecSucceeded}, {Thing: "F2", Status: ExecSucceeded}}}}
	s.State.Notified = []string{"done:0.9.1"}
	return s
}

func addJob(s *Snapshot, id string, status string, created time.Time, execs ...Exec) *Job {
	jid, ok := ParseJobID(id, map[string]ProductConfig{"vaktus": vaktus})
	if !ok {
		panic(id)
	}
	j := &Job{ID: jid, RawID: id, Status: status, CreatedAt: created, Execs: execs}
	s.Jobs = append(s.Jobs, j)
	return j
}

func kinds(p Plan, k ActionKind) []Action {
	var out []Action
	for _, a := range p.Actions {
		if a.Kind == k {
			out = append(out, a)
		}
	}
	return out
}

func created(p Plan) []string {
	var out []string
	for _, a := range kinds(p, ActCreateJob) {
		out = append(out, a.Job.ID.String())
	}
	return out
}

func cancelled(p Plan) []string {
	var out []string
	for _, a := range kinds(p, ActCancelJob) {
		out = append(out, a.JobID)
	}
	return out
}

func subjects(p Plan) string {
	var out []string
	for _, a := range kinds(p, ActNotify) {
		out = append(out, a.Subject)
	}
	return strings.Join(out, " | ")
}

func eq(t *testing.T, what string, got, want []string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s: got %v, want %v", what, got, want)
	}
}

func TestIdleFleetDoesNothing(t *testing.T) {
	p := planTick(fixture())
	if len(p.Actions) != 0 {
		t.Fatalf("idle fleet: %s", p)
	}
}

func TestNewReleaseStartsASignedCanaryJob(t *testing.T) {
	s := fixture()
	s.Releases = append(s.Releases, rel("0.9.2"))
	p := planTick(s)
	eq(t, "created", created(p), []string{"ota-vaktus-0_9_2-c"})
	j := kinds(p, ActCreateJob)[0].Job
	if !j.Signed || j.Continuous || j.Downgrade || j.Targets[0] != vaktus.Canary.ARN {
		t.Errorf("canary job %+v", j)
	}
}

func TestCanaryWithoutTheKeyGetsAnUnsignedJob(t *testing.T) {
	s := fixture()
	s.Releases = append(s.Releases, rel("0.9.2"))
	s.Fleet["C1"].Shadow.KeyIDs = nil // Phase 2 firmware: empty keyring
	j := kinds(planTick(s), ActCreateJob)[0].Job
	if j.Signed {
		t.Error("a canary without the key would refuse a signed job (reason sig)")
	}
}

// Exit criterion 1: a fix reaches the canary, then the fleet, without a click.
func TestSoakedCanaryIsPromoted(t *testing.T) {
	s := fixture()
	s.Releases = append(s.Releases, rel("0.9.2"))
	done := t0.Add(-25 * time.Hour)
	addJob(s, "ota-vaktus-0_9_2-c", JobCompleted, done.Add(-time.Hour), Exec{Thing: "C1", Status: ExecSucceeded, LastUpdatedAt: done})
	s.Fleet["C1"].Shadow = shadowOn("0.9.2", done.Add(time.Minute))
	s.Fleet["C1"].ConnectedAt = done.Add(-time.Minute)

	p := planTick(s)
	eq(t, "created", created(p), []string{"ota-vaktus-0_9_2-f"})
	eq(t, "cancelled", cancelled(p), []string{"ota-vaktus-0_9_1-f"})
	j := kinds(p, ActCreateJob)[0].Job
	if !j.Continuous || j.Targets[0] != vaktus.Fleet.ARN || !j.Signed {
		t.Errorf("fleet job %+v", j)
	}
	if p.State.FleetVersion != ver("0.9.2") {
		t.Errorf("fleet_version %s", p.State.FleetVersion)
	}
	// The new fleet job exists before the old one is cancelled.
	var order []ActionKind
	for _, a := range p.Actions {
		order = append(order, a.Kind)
	}
	if order[0] != ActCreateJob || order[1] != ActCancelJob || order[len(order)-1] != ActSaveState {
		t.Errorf("order %s", p)
	}
	if !strings.Contains(subjects(p), "promoted 0.9.2") {
		t.Errorf("subjects %s", subjects(p))
	}
}

func TestSoakNotElapsedWaits(t *testing.T) {
	s := fixture()
	s.Releases = append(s.Releases, rel("0.9.2"))
	done := t0.Add(-2 * time.Hour)
	addJob(s, "ota-vaktus-0_9_2-c", JobCompleted, done, Exec{Thing: "C1", Status: ExecSucceeded, LastUpdatedAt: done})
	s.Fleet["C1"].Shadow = shadowOn("0.9.2", done.Add(time.Minute))
	if p := planTick(s); len(p.Actions) != 0 {
		t.Fatalf("soaking: %s", p)
	}

	// A reconnect after completion restarts the soak.
	s.Now = t0.Add(23 * time.Hour)
	s.Fleet["C1"].ConnectedAt = t0
	if p := planTick(s); len(p.Actions) != 0 {
		t.Fatalf("soak should restart at the reconnect: %s", p)
	}
	s.Now = t0.Add(25 * time.Hour)
	if p := planTick(s); len(created(p)) != 1 {
		t.Fatalf("soak over: %s", p)
	}
}

func TestOfflineOrUnreportedCanaryBlocksTheGate(t *testing.T) {
	s := fixture()
	s.Releases = append(s.Releases, rel("0.9.2"))
	done := t0.Add(-30 * time.Hour)
	addJob(s, "ota-vaktus-0_9_2-c", JobCompleted, done, Exec{Thing: "C1", Status: ExecSucceeded, LastUpdatedAt: done})

	s.Fleet["C1"].Shadow = shadowOn("0.9.1", done.Add(-time.Hour)) // no report since the update
	if p := planTick(s); len(created(p)) != 0 {
		t.Fatalf("unreported: %s", p)
	}
	s.Fleet["C1"].Shadow = shadowOn("0.9.2", done.Add(time.Minute))
	s.Fleet["C1"].Online = false
	if p := planTick(s); len(created(p)) != 0 {
		t.Fatalf("offline: %s", p)
	}
}

// Exit criterion 3: a panic-after-CONNACK image halts at the soak gate; a
// newer fix clears the halt.
func TestPanicAfterConnackHaltsAndANewerFixClearsIt(t *testing.T) {
	s := fixture()
	s.Releases = append(s.Releases, rel("0.9.2"))
	done := t0.Add(-30 * time.Hour)
	addJob(s, "ota-vaktus-0_9_2-c", JobCompleted, done, Exec{Thing: "C1", Status: ExecSucceeded, LastUpdatedAt: done})
	s.Fleet["C1"].Shadow = &Shadow{FW: "0.9.2", BootReason: "panic", BootCount: 2, KeyIDs: []string{"vaktus-a"}, ReportedAt: done.Add(time.Minute)}

	p := planTick(s)
	if p.State.HaltedVersion != ver("0.9.2") || p.State.HaltedReason != "canary:C1:crash-panic" {
		t.Fatalf("halt: %+v %s", p.State, p)
	}
	if len(created(p)) != 0 || !strings.Contains(subjects(p), "0.9.2 halted") {
		t.Fatalf("plan %s / %s", p, subjects(p))
	}

	// Next tick: halted, quiet.
	s.State = p.State
	if p := planTick(s); len(p.Actions) != 0 {
		t.Fatalf("halted tick: %s", p)
	}

	// 0.9.3 arrives: the halt clears and its canary starts.
	s.Releases = append(s.Releases, rel("0.9.3"))
	p = planTick(s)
	if !p.State.HaltedVersion.IsZero() {
		t.Errorf("halt not cleared: %+v", p.State)
	}
	eq(t, "created", created(p), []string{"ota-vaktus-0_9_3-c"})
}

func TestTerminalCanaryFailureHalts(t *testing.T) {
	s := fixture()
	s.Releases = append(s.Releases, rel("0.9.2"))
	addJob(s, "ota-vaktus-0_9_2-c", JobInProgress, t0.Add(-time.Hour), Exec{Thing: "C1", Status: ExecFailed, Reason: "rollback"})
	p := planTick(s)
	eq(t, "cancelled", cancelled(p), []string{"ota-vaktus-0_9_2-c"})
	if p.State.HaltedVersion != ver("0.9.2") || p.State.HaltedReason != "canary:C1:rollback" {
		t.Fatalf("state %+v", p.State)
	}
}

func TestDownloadFailureGetsOneRerun(t *testing.T) {
	s := fixture()
	s.Releases = append(s.Releases, rel("0.9.2"))
	addJob(s, "ota-vaktus-0_9_2-c", JobInProgress, t0.Add(-time.Hour), Exec{Thing: "C1", Status: ExecFailed, Reason: "download"})
	p := planTick(s)
	eq(t, "created", created(p), []string{"ota-vaktus-0_9_2-c-r1"})
	eq(t, "cancelled", cancelled(p), []string{"ota-vaktus-0_9_2-c"})
	if !p.State.HaltedVersion.IsZero() {
		t.Fatal("first download failure halted")
	}

	// The rerun fails to download too: halt.
	s.State = p.State
	s.Jobs[1].Status = JobCanceled
	addJob(s, "ota-vaktus-0_9_2-c-r1", JobInProgress, t0, Exec{Thing: "C1", Status: ExecFailed, Reason: "download"})
	p = planTick(s)
	if p.State.HaltedVersion != ver("0.9.2") || len(created(p)) != 0 {
		t.Fatalf("second download failure: %+v %s", p.State, p)
	}
}

// Exit criterion 5: an unplugged canary is substituted.
func TestUnpluggedCanaryIsSubstituted(t *testing.T) {
	s := fixture()
	s.Releases = append(s.Releases, rel("0.9.2"))
	s.Fleet["C1"].Online = false
	addJob(s, "ota-vaktus-0_9_2-c", JobInProgress, t0.Add(-3*time.Hour), Exec{Thing: "C1", Status: ExecQueued, QueuedAt: t0.Add(-3 * time.Hour)})
	p := planTick(s)

	var moves []string
	for _, a := range kinds(p, ActMove) {
		moves = append(moves, a.Thing+"+"+strings.Join(a.Add, "+"))
	}
	eq(t, "moves", moves, []string{"C1+esp32-ztp-vaktus-fleet", "F1+esp32-ztp-vaktus-canary"})
	if ce := kinds(p, ActCancelExecution); len(ce) != 1 || ce[0].Thing != "C1" {
		t.Errorf("execution cancel %v", ce)
	}
	eq(t, "cancelled", cancelled(p), []string{"ota-vaktus-0_9_2-c"})
	eq(t, "created", created(p), []string{"ota-vaktus-0_9_2-c-r1"})

	// Queued for less than two hours: wait.
	s = fixture()
	s.Releases = append(s.Releases, rel("0.9.2"))
	addJob(s, "ota-vaktus-0_9_2-c", JobInProgress, t0.Add(-time.Hour), Exec{Thing: "C1", Status: ExecQueued, QueuedAt: t0.Add(-time.Hour)})
	if p := planTick(s); len(p.Actions) != 0 {
		t.Fatalf("queued 1 h: %s", p)
	}
}

func TestNoOnlineCanaryPicksOneOrWaits(t *testing.T) {
	s := fixture()
	s.Releases = append(s.Releases, rel("0.9.2"))
	s.Canary = map[string]bool{}
	s.Preferred = []string{"F2"}
	p := planTick(s)
	if m := kinds(p, ActMove); len(m) != 1 || m[0].Thing != "F2" {
		t.Fatalf("preferred canary not placed: %s", p)
	}
	eq(t, "created", created(p), []string{"ota-vaktus-0_9_2-c"})

	// Nobody online: one email, no job.
	s = fixture()
	s.Releases = append(s.Releases, rel("0.9.2"))
	for _, d := range s.Fleet {
		d.Online = false
	}
	p = planTick(s)
	if len(created(p)) != 0 || !strings.Contains(subjects(p), "waits for a canary") {
		t.Fatalf("no one online: %s", p)
	}
	s.State = p.State
	if p := planTick(s); len(kinds(p, ActNotify)) != 0 {
		t.Fatalf("emailed twice: %s", subjects(p))
	}
}

func TestSingleDeviceProductGoesStraightToTheFleet(t *testing.T) {
	s := fixture()
	s.Releases = append(s.Releases, rel("0.9.2"))
	delete(s.Fleet, "F1")
	delete(s.Fleet, "F2")
	p := planTick(s)
	eq(t, "created", created(p), []string{"ota-vaktus-0_9_2-f"})
}

func TestHoldAsksInsteadOfPromoting(t *testing.T) {
	s := fixture()
	s.State.Mode = ModeHold
	s.Releases = append(s.Releases, rel("0.9.2"))
	done := t0.Add(-25 * time.Hour)
	addJob(s, "ota-vaktus-0_9_2-c", JobCompleted, done, Exec{Thing: "C1", Status: ExecSucceeded, LastUpdatedAt: done})
	s.Fleet["C1"].Shadow = shadowOn("0.9.2", done.Add(time.Minute))
	p := planTick(s)
	if len(created(p)) != 0 || !strings.Contains(subjects(p), "ready to promote") {
		t.Fatalf("hold: %s", p)
	}
	s.State = p.State
	if p := planTick(s); len(p.Actions) != 0 {
		t.Fatalf("second hold tick: %s", p)
	}
}

func TestFrozenDoesNothing(t *testing.T) {
	s := fixture()
	s.State.Mode = ModeFrozen
	s.Releases = append(s.Releases, rel("0.9.2"))
	addJob(s, "ota-vaktus-firmware_v0-9-0-1730000000000", JobInProgress, t0)
	if p := planTick(s); len(p.Actions) != 0 {
		t.Fatalf("frozen: %s", p)
	}
}

func TestReleaseMidSoakSupersedesTheCanary(t *testing.T) {
	s := fixture()
	s.Releases = append(s.Releases, rel("0.9.2"), rel("0.9.3"))
	addJob(s, "ota-vaktus-0_9_2-c", JobInProgress, t0.Add(-time.Hour), Exec{Thing: "C1", Status: ExecInProgress})
	p := planTick(s)
	eq(t, "cancelled", cancelled(p), []string{"ota-vaktus-0_9_2-c"})
	eq(t, "created", created(p), []string{"ota-vaktus-0_9_3-c"})
	if !p.State.HaltedVersion.IsZero() {
		t.Error("supersession is not a halt")
	}
}

func TestFleetFailures(t *testing.T) {
	// One failure among successes: excluded.
	s := fixture()
	s.Jobs[0].Execs[2] = Exec{Thing: "F2", Status: ExecFailed, Reason: "verify"}
	p := planTick(s)
	m := kinds(p, ActMove)
	if len(m) != 1 || m[0].Thing != "F2" || m[0].Add[0] != vaktus.Excluded.Name || strings.Join(m[0].Remove, ",") != vaktus.Fleet.Name {
		t.Fatalf("exclusion: %s", p)
	}
	if len(cancelled(p)) != 0 || !p.State.HaltedVersion.IsZero() {
		t.Fatalf("one failure halted: %s", p)
	}

	// Two failures: the job is cancelled and the version halted.
	s = fixture()
	s.Jobs[0].Execs[1] = Exec{Thing: "F1", Status: ExecTimedOut}
	s.Jobs[0].Execs[2] = Exec{Thing: "F2", Status: ExecFailed, Reason: "boot"}
	p = planTick(s)
	eq(t, "cancelled", cancelled(p), []string{"ota-vaktus-0_9_1-f"})
	if p.State.HaltedVersion != ver("0.9.1") {
		t.Fatalf("two failures: %+v", p.State)
	}
}

func TestDoneIsEmailedOnce(t *testing.T) {
	s := fixture()
	s.State.Notified = nil
	p := planTick(s)
	if subjects(p) != "[vaktus] fleet on 0.9.1" {
		t.Fatalf("done: %q", subjects(p))
	}
	s.State = p.State
	if p := planTick(s); len(p.Actions) != 0 {
		t.Fatalf("done twice: %s", p)
	}
}

func TestLegacyJobsAreCancelled(t *testing.T) {
	s := fixture()
	addJob(s, "ota-vaktus-firmware_v0-9-0-1730000000000", JobInProgress, t0.Add(-time.Hour*500))
	addJob(s, "ota-vaktus-firmware_v0-8-0-1720000000000", JobCanceled, t0.Add(-time.Hour*900))
	eq(t, "cancelled", cancelled(planTick(s)), []string{"ota-vaktus-firmware_v0-9-0-1730000000000"})
}

// Exit criterion 4 (the planner's half): a refused release is reported once.
func TestRefusedReleasesAreReportedOnce(t *testing.T) {
	s := fixture()
	s.Bad = []BadRelease{{Version: "0.9.2", Reason: "the manifest is for version 0.9.0"}, {Version: "0.9.0", Reason: "old"}}
	p := planTick(s)
	if subjects(p) != "[vaktus] release 0.9.2 refused" || len(created(p)) != 0 {
		t.Fatalf("bad: %s", subjects(p))
	}
	s.State = p.State
	if p := planTick(s); len(p.Actions) != 0 {
		t.Fatalf("twice: %s", p)
	}
}

func TestOrphanReleaseIsReportedOnce(t *testing.T) {
	s := fixture()
	s.Orphans = []string{"0.9.2"}
	p := planTick(s)
	if !strings.Contains(subjects(p), "0.9.2 never reached S3") {
		t.Fatalf("orphan: %s", subjects(p))
	}
}

func TestOverrides(t *testing.T) {
	// rollback: a downgrade fleet job, the bad version halted, the product on hold.
	s := fixture()
	s.Releases = []Release{rel("0.9.0"), rel("0.9.1")}
	p, err := planOverride(s, Override{Action: "rollback", Product: "vaktus", Version: "0.9.0"})
	if err != nil {
		t.Fatal(err)
	}
	j := kinds(p, ActCreateJob)[0].Job
	if j.ID.String() != "ota-vaktus-0_9_0-f" || !j.Downgrade || !j.Continuous {
		t.Errorf("rollback job %+v", j)
	}
	eq(t, "cancelled", cancelled(p), []string{"ota-vaktus-0_9_1-f"})
	if p.State.FleetVersion != ver("0.9.0") || p.State.HaltedVersion != ver("0.9.1") || p.State.Mode != ModeHold {
		t.Errorf("rollback state %+v", p.State)
	}
	if _, err := planOverride(s, Override{Action: "rollback", Version: "0.9.5"}); err == nil {
		t.Error("rollback to an unverified version")
	}
	if _, err := planOverride(s, Override{Action: "rollback", Version: "0.9.1"}); err == nil {
		t.Error("rollback to the fleet version")
	}

	// promote: skips the soak gate, never downgrades.
	s = fixture()
	s.Releases = append(s.Releases, rel("0.9.2"))
	p, err = planOverride(s, Override{Action: "promote", Product: "vaktus"})
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "promote", created(p), []string{"ota-vaktus-0_9_2-f"})
	if _, err := planOverride(s, Override{Action: "promote", Version: "0.9.1"}); err == nil {
		t.Error("promote of the fleet version")
	}

	// rerun: clears the halt, next rerun number.
	s = fixture()
	s.Releases = append(s.Releases, rel("0.9.2"))
	s.State.HaltedVersion, s.State.HaltedReason = ver("0.9.2"), "canary:C1:boot"
	s.State.Notified = append(s.State.Notified, "halt:0.9.2", "blocked:0.9.2:C1")
	addJob(s, "ota-vaktus-0_9_2-c", JobCanceled, t0)
	p, err = planOverride(s, Override{Action: "rerun", Product: "vaktus"})
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "rerun", created(p), []string{"ota-vaktus-0_9_2-c-r1"})
	if !p.State.HaltedVersion.IsZero() || p.State.notified("halt:0.9.2") || p.State.notified("blocked:0.9.2:C1") {
		t.Errorf("rerun state %+v", p.State)
	}

	// target: an excluded device comes back with its own job.
	s = fixture()
	delete(s.Fleet, "F2")
	s.Excluded["F2"] = true
	p, err = planOverride(s, Override{Action: "target", Product: "vaktus", Thing: "F2"})
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "target", created(p), []string{"ota-vaktus-0_9_1-t-F2"})
	if m := kinds(p, ActMove); len(m) != 1 || m[0].Remove[0] != vaktus.Excluded.Name {
		t.Errorf("target move %s", p)
	}
	if _, err := planOverride(s, Override{Action: "target", Thing: "NOPE"}); err == nil {
		t.Error("target of a foreign thing")
	}

	// hold / resume / freeze only set the mode.
	for action, mode := range map[string]string{"hold": ModeHold, "resume": ModeAuto, "freeze": ModeFrozen} {
		p, err := planOverride(fixture(), Override{Action: action, Product: "vaktus"})
		if err != nil || p.State.Mode != mode || len(p.Actions) != 1 {
			t.Errorf("%s: %v %+v %s", action, err, p.State, p)
		}
	}
	if _, err := planOverride(fixture(), Override{Action: "explode"}); err == nil {
		t.Error("unknown action accepted")
	}
}

func TestStateAttributesRoundTrip(t *testing.T) {
	st := FleetState{Mode: ModeHold, SoakHours: 6, FleetVersion: ver("1.2.3"), HaltedVersion: ver("1.2.4"),
		HaltedReason: "canary:C1:crash panic!", Notified: []string{"a", "b"}}
	attrs := st.attributes()
	if attrs[attrHaltedReason] != "canary:C1:crash_panic_" {
		t.Errorf("unsafe characters kept: %q", attrs[attrHaltedReason])
	}
	back := stateFromAttributes(attrs, 24)
	if back.Mode != ModeHold || back.SoakHours != 6 || back.FleetVersion != st.FleetVersion || back.HaltedVersion != st.HaltedVersion || len(back.Notified) != 2 {
		t.Errorf("round trip %+v", back)
	}
	def := stateFromAttributes(map[string]string{attrMode: "bogus"}, 24)
	if def.Mode != ModeAuto || def.SoakHours != 24 || !def.FleetVersion.IsZero() {
		t.Errorf("defaults %+v", def)
	}
	// The notified list stays within the attribute limit.
	var many []string
	for i := 0; i < 200; i++ {
		many = append(many, "blocked:10.10.10:ABCDEF012345")
	}
	if n := len((FleetState{Notified: many}).attributes()[attrNotified]); n > maxAttrLen {
		t.Errorf("notified is %d characters", n)
	}
}
