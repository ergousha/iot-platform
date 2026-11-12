package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	// queuedLimit: a canary execution QUEUED this long (the canary is
	// unplugged) is cancelled and the canary substituted.
	queuedLimit = 2 * time.Hour
	// canaryLifetime: a canary job with no success after this is cancelled.
	canaryLifetime = 48 * time.Hour
)

// ActionKind is what the executor does for one Action.
type ActionKind int

const (
	ActCreateJob ActionKind = iota
	ActCancelJob
	ActCancelExecution
	ActMove
	ActNotify
	ActSaveState
)

// NewJob is a job to create.
type NewJob struct {
	ID         JobID
	Release    Release
	Targets    []string // ARNs
	Continuous bool
	Signed     bool // carry the manifest, signature and key id
	Downgrade  bool
}

// Action is one step of a plan, executed in order.
type Action struct {
	Kind ActionKind

	Job *NewJob // ActCreateJob

	JobID   string // ActCancelJob, ActCancelExecution
	Comment string // ActCancelJob

	Thing  string   // ActCancelExecution, ActMove
	Add    []string // ActMove: group names
	Remove []string // ActMove: group names

	Subject string // ActNotify
	Body    string // ActNotify
}

// Plan is the planner's output: actions, then the state to save.
type Plan struct {
	Actions []Action
	State   FleetState
	Log     []string
}

func (p Plan) String() string {
	var b strings.Builder
	for _, a := range p.Actions {
		switch a.Kind {
		case ActCreateJob:
			fmt.Fprintf(&b, "create %s signed=%t downgrade=%t; ", a.Job.ID, a.Job.Signed, a.Job.Downgrade)
		case ActCancelJob:
			fmt.Fprintf(&b, "cancel %s; ", a.JobID)
		case ActCancelExecution:
			fmt.Fprintf(&b, "cancel %s on %s; ", a.JobID, a.Thing)
		case ActMove:
			fmt.Fprintf(&b, "move %s +%v -%v; ", a.Thing, a.Add, a.Remove)
		case ActNotify:
			fmt.Fprintf(&b, "notify %q; ", a.Subject)
		case ActSaveState:
			b.WriteString("save; ")
		}
	}
	return strings.TrimSuffix(b.String(), "; ")
}

type planner struct {
	s       *Snapshot
	state   FleetState
	actions []Action
	log     []string
	dirty   bool
	// used is every job id of the product, so new ids never collide.
	used map[string]bool
	// moved tracks this plan's group moves (thing -> in canary).
	canary map[string]bool
}

func newPlanner(s *Snapshot) *planner {
	pl := &planner{s: s, state: s.State, used: map[string]bool{}, canary: map[string]bool{}}
	pl.state.Notified = append([]string(nil), s.State.Notified...)
	for _, j := range s.Jobs {
		pl.used[j.RawID] = true
	}
	for t := range s.Canary {
		pl.canary[t] = true
	}
	return pl
}

func (pl *planner) logf(format string, args ...any) {
	pl.log = append(pl.log, fmt.Sprintf(format, args...))
}

func (pl *planner) finish() Plan {
	if pl.dirty {
		pl.actions = append(pl.actions, Action{Kind: ActSaveState})
	}
	return Plan{Actions: pl.actions, State: pl.state, Log: pl.log}
}

// notify emails the owner.
func (pl *planner) notify(subject, body string) {
	pl.actions = append(pl.actions, Action{
		Kind:    ActNotify,
		Subject: fmt.Sprintf("[%s] %s", pl.s.Product.ID, subject),
		Body:    body,
	})
}

// notifyOnce emails once per key, for conditions that last many ticks.
func (pl *planner) notifyOnce(key, subject, body string) {
	key = attrSafe(key)
	if pl.state.notified(key) {
		return
	}
	pl.state.Notified = append(pl.state.Notified, key)
	pl.dirty = true
	pl.notify(subject, body)
}

func (pl *planner) cancelJob(j *Job, comment string) {
	if !j.active() {
		return
	}
	pl.actions = append(pl.actions, Action{Kind: ActCancelJob, JobID: j.RawID, Comment: comment})
	j.Status = JobCanceled
}

func (pl *planner) move(thing string, add, remove []string) {
	pl.actions = append(pl.actions, Action{Kind: ActMove, Thing: thing, Add: add, Remove: remove})
}

func (pl *planner) toCanary(thing string) {
	p := pl.s.Product
	pl.move(thing, []string{p.Canary.Name}, []string{p.Fleet.Name})
	pl.canary[thing] = true
}

func (pl *planner) toFleet(thing string) {
	p := pl.s.Product
	pl.move(thing, []string{p.Fleet.Name}, []string{p.Canary.Name})
	delete(pl.canary, thing)
}

func (pl *planner) create(j NewJob) {
	pl.used[j.ID.String()] = true
	pl.actions = append(pl.actions, Action{Kind: ActCreateJob, Job: &j})
}

// jobs of a kind and version, newest (highest rerun) first.
func (pl *planner) jobsOf(kind string, v Version) []*Job {
	var out []*Job
	for _, j := range pl.s.Jobs {
		if !j.ID.Legacy && j.ID.Kind == kind && j.ID.Version == v {
			out = append(out, j)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID.Rerun > out[b].ID.Rerun })
	return out
}

func (pl *planner) latest(kind string, v Version) *Job {
	if js := pl.jobsOf(kind, v); len(js) > 0 {
		return js[0]
	}
	return nil
}

func (pl *planner) release(v Version) *Release {
	for i := range pl.s.Releases {
		if pl.s.Releases[i].Version == v {
			return &pl.s.Releases[i]
		}
	}
	return nil
}

// signedFor reports whether every device in things accepts the release's
// signing key (its platform shadow lists the key id). Units running firmware
// without that key would refuse a signed job (reason sig), so they get the
// v1 document until every unit has the key; the controller has verified the
// signature either way. A `signed-only` mode ends the transition.
func (pl *planner) signedFor(r *Release, things []string) bool {
	if len(things) == 0 {
		return false
	}
	for _, t := range things {
		d := pl.s.Fleet[t]
		if d == nil || d.Shadow == nil || !contains(d.Shadow.KeyIDs, r.KeyID) {
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (pl *planner) canaryThings() []string {
	var out []string
	for t := range pl.canary {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func (pl *planner) fleetThings() []string {
	var out []string
	for t := range pl.s.Fleet {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func (pl *planner) online(thing string) bool {
	d := pl.s.Fleet[thing]
	return d != nil && d.Online
}

// halt stops version v: halted_version, the reason, one email.
func (pl *planner) halt(v Version, reason, detail string) {
	pl.state.HaltedVersion = v
	pl.state.HaltedReason = reason
	pl.dirty = true
	pl.notifyOnce("halt:"+v.String(), fmt.Sprintf("%s halted (%s)", v, reason),
		fmt.Sprintf("Release %s of %s is halted: %s\n\n%s\n\nA newer release clears the halt automatically; "+
			"`scripts/ota.sh rerun %s` retries this one.", v, pl.s.Product.ID, reason, detail, pl.s.Product.ID))
	pl.logf("halted %s: %s", v, reason)
}

// planTick is one reconciliation of one product.
func planTick(s *Snapshot) Plan {
	pl := newPlanner(s)
	if pl.state.Mode == ModeFrozen {
		pl.logf("frozen: nothing to do")
		return pl.finish()
	}
	pl.cancelLegacy()
	pl.reportBad()
	pl.reportOrphans()
	desired := pl.desired()
	pl.cancelStaleCanaries(desired)
	pl.placePreferredCanaries()
	pl.watchFleet()
	if desired != nil && desired.Version != pl.state.HaltedVersion {
		pl.advance(desired)
	}
	return pl.finish()
}

// cancelLegacy cancels the old ota_trigger jobs: their presigned URLs died
// with the presign role, and the controller's jobs replace them.
func (pl *planner) cancelLegacy() {
	for _, j := range pl.s.Jobs {
		if j.ID.Legacy && j.active() {
			pl.cancelJob(j, "Legacy job (presigned S3 URL); replaced by the OTA controller")
			pl.logf("cancelled legacy job %s", j.RawID)
		}
	}
}

func (pl *planner) reportBad() {
	for _, b := range pl.s.Bad {
		v, err := ParseVersion(b.Version)
		if err == nil && !pl.state.FleetVersion.Less(v) {
			continue // not newer than the fleet: old news
		}
		pl.notifyOnce("bad:"+b.Version, fmt.Sprintf("release %s refused", b.Version),
			fmt.Sprintf("releases/%s/%s/ was not verified and will not be rolled out:\n\n%s",
				pl.s.Product.ID, b.Version, b.Reason))
	}
}

func (pl *planner) reportOrphans() {
	for _, v := range pl.s.Orphans {
		pl.notifyOnce("orphan:"+v, fmt.Sprintf("release %s never reached S3", v),
			fmt.Sprintf("GitHub has release v%s of %s, but releases/%s/%s/manifest.sig is not in S3: "+
				"its publish job failed after the tag. Re-run that workflow run's failed jobs, or merge a new fix.",
				v, pl.s.Product.Repository, pl.s.Product.ID, v))
	}
}

// desired is the highest verified version above the fleet's that is not
// halted. A version above the halted one clears the halt.
func (pl *planner) desired() *Release {
	var d *Release
	for i := range pl.s.Releases {
		r := &pl.s.Releases[i]
		if pl.state.FleetVersion.Less(r.Version) && r.Version != pl.state.HaltedVersion {
			if d == nil || d.Version.Less(r.Version) {
				d = r
			}
		}
	}
	h := pl.state.HaltedVersion
	if d != nil && !h.IsZero() && h.Less(d.Version) {
		pl.logf("%s clears the halt of %s", d.Version, h)
		pl.state.HaltedVersion, pl.state.HaltedReason = Version{}, ""
		pl.dirty = true
	}
	return d
}

// cancelStaleCanaries keeps one canary job in flight: the newest of the
// desired version. A version arriving mid-soak supersedes the old one; that
// is not a halt.
func (pl *planner) cancelStaleCanaries(d *Release) {
	var keep *Job
	if d != nil {
		keep = pl.latest(KindCanary, d.Version)
	}
	for _, j := range pl.s.Jobs {
		if j.ID.Legacy || j.ID.Kind != KindCanary || !j.active() || j == keep {
			continue
		}
		comment := "Superseded"
		if d != nil {
			comment = "Superseded by " + d.Version.String()
		}
		pl.cancelJob(j, comment)
		pl.logf("cancelled superseded canary job %s", j.RawID)
	}
}

// placePreferredCanaries moves the things whose registry record says
// canary=true into the canary group.
func (pl *planner) placePreferredCanaries() {
	for _, t := range pl.s.Preferred {
		if _, inFleet := pl.s.Fleet[t]; inFleet && !pl.canary[t] && !pl.s.Excluded[t] {
			pl.toCanary(t)
			pl.logf("moved preferred canary %s into the canary group", t)
		}
	}
}

// pickCanary picks an online fleet device that is not a canary: a preferred
// one first, else the lowest thing name.
func (pl *planner) pickCanary(avoid string) string {
	ok := func(t string) bool { return t != avoid && !pl.canary[t] && pl.online(t) }
	for _, t := range pl.s.Preferred {
		if _, inFleet := pl.s.Fleet[t]; inFleet && ok(t) {
			return t
		}
	}
	for _, t := range pl.fleetThings() {
		if ok(t) {
			return t
		}
	}
	return ""
}

// watchFleet follows the active fleet job of the fleet version: one failed
// thing among successes is excluded, two or more halt the release.
func (pl *planner) watchFleet() {
	fv := pl.state.FleetVersion
	if fv.IsZero() {
		return
	}
	fj := pl.latest(KindFleet, fv)
	// Older fleet jobs still active (an interrupted promotion) go now.
	for _, j := range pl.s.Jobs {
		if !j.ID.Legacy && j.ID.Kind == KindFleet && j.active() && j != fj {
			pl.cancelJob(j, "Superseded by fleet version "+fv.String())
		}
	}
	if fj == nil || !fj.active() {
		return
	}
	var failed []Exec
	succeeded, pending := 0, 0
	for _, e := range fj.Execs {
		switch {
		case e.failed():
			failed = append(failed, e)
		case e.Status == ExecSucceeded:
			succeeded++
		case e.pending():
			pending++
		}
	}
	describe := func(es []Exec) string {
		var parts []string
		for _, e := range es {
			parts = append(parts, fmt.Sprintf("%s: %s (%s)", e.Thing, e.Status, e.failureReason()))
		}
		return strings.Join(parts, "\n")
	}
	switch {
	case len(failed) >= 2:
		pl.cancelJob(fj, "Halted: "+fmt.Sprint(len(failed))+" devices failed")
		pl.halt(fv, fmt.Sprintf("fleet:%d-failed", len(failed)), describe(failed))
	case len(failed) == 1 && succeeded >= 1:
		e := failed[0]
		if pl.s.Excluded[e.Thing] {
			return
		}
		p := pl.s.Product
		from := p.Fleet.Name
		if pl.canary[e.Thing] {
			from = p.Canary.Name
		}
		pl.move(e.Thing, []string{p.Excluded.Name}, []string{from})
		delete(pl.canary, e.Thing)
		pl.notifyOnce("exclude:"+fv.String()+":"+e.Thing, fmt.Sprintf("%s excluded from %s", e.Thing, fv),
			fmt.Sprintf("%s failed the fleet job %s while others succeeded:\n\n%s\n\n"+
				"It was moved to %s and gets no fleet job. `scripts/ota.sh target %s %s` brings it back.",
				e.Thing, fj.RawID, describe(failed), p.Excluded.Name, p.ID, e.Thing))
	case len(failed) == 1 && pending == 0:
		pl.cancelJob(fj, "Halted: the only device failed")
		pl.halt(fv, fmt.Sprintf("fleet:%s:%s", failed[0].Thing, failed[0].failureReason()), describe(failed))
	case len(failed) == 0 && pending == 0 && succeeded >= 1:
		pl.notifyOnce("done:"+fv.String(), fmt.Sprintf("fleet on %s", fv),
			fmt.Sprintf("Every device of %s reported %s (%d executions of %s).", pl.s.Product.ID, fv, succeeded, fj.RawID))
	}
}

// advance moves the desired release through canary, soak and promotion.
func (pl *planner) advance(d *Release) {
	if len(pl.s.Fleet) <= 1 {
		pl.logf("single-device product: straight to the fleet job")
		pl.promote(d)
		return
	}
	cj := pl.latest(KindCanary, d.Version)
	switch {
	case cj == nil:
		pl.startCanary(d, 0)
	case cj.Status == JobCanceled:
		pl.notifyOnce("stopped:"+d.Version.String(), fmt.Sprintf("%s canary stopped", d.Version),
			fmt.Sprintf("The canary job %s was cancelled. `scripts/ota.sh rerun %s` starts it again; "+
				"a newer release replaces it.", cj.RawID, pl.s.Product.ID))
	default:
		pl.evaluateCanary(d, cj)
	}
}

// startCanary creates the canary job (rerun 0) or its next rerun.
func (pl *planner) startCanary(d *Release, rerun int) {
	online := false
	for _, t := range pl.canaryThings() {
		online = online || pl.online(t)
	}
	if !online {
		pick := pl.pickCanary("")
		if pick == "" {
			pl.notifyOnce("wait:"+d.Version.String(), fmt.Sprintf("%s waits for a canary", d.Version),
				fmt.Sprintf("No canary of %s is online, and no other fleet device is either. "+
					"The release starts when one comes back.", pl.s.Product.ID))
			return
		}
		pl.toCanary(pick)
		pl.notifyOnce("picked:"+d.Version.String()+":"+pick, fmt.Sprintf("%s is the canary for %s", pick, d.Version),
			fmt.Sprintf("No canary of %s was online; %s was moved into %s.", pl.s.Product.ID, pick, pl.s.Product.Canary.Name))
	}
	id := nextFree(JobID{Product: pl.s.Product.ID, Version: d.Version, Kind: KindCanary, Rerun: rerun}, pl.used)
	pl.create(NewJob{
		ID: id, Release: *d, Targets: []string{pl.s.Product.Canary.ARN},
		Signed: pl.signedFor(d, pl.canaryThings()),
	})
	pl.logf("created canary job %s", id)
}

func (pl *planner) evaluateCanary(d *Release, cj *Job) {
	v := d.Version
	execs := append([]Exec(nil), cj.Execs...)
	sort.Slice(execs, func(a, b int) bool { return execs[a].Thing < execs[b].Thing })

	// A terminal failure halts; a download failure gets one rerun first.
	for _, e := range execs {
		if !e.failed() {
			continue
		}
		reason := e.failureReason()
		if reason == "download" && !pl.state.notified("rerun:"+v.String()) {
			pl.cancelJob(cj, "Download failed on "+e.Thing+"; rerun")
			pl.notifyOnce("rerun:"+v.String(), fmt.Sprintf("%s canary download failed; rerun", v),
				fmt.Sprintf("%s could not download %s (%s). The canary job runs once more.", e.Thing, v, cj.RawID))
			pl.startCanary(d, cj.ID.Rerun+1)
			return
		}
		pl.cancelJob(cj, "Halted: "+e.Thing+" "+reason)
		pl.halt(v, fmt.Sprintf("canary:%s:%s", e.Thing, reason),
			fmt.Sprintf("%s reported %s (%s) for %s.", e.Thing, e.Status, reason, cj.RawID))
		return
	}

	// An unplugged canary is substituted.
	for _, e := range execs {
		if e.Status != ExecQueued || pl.s.Now.Sub(e.QueuedAt) < queuedLimit || !cj.active() {
			continue
		}
		sub := pl.pickCanary(e.Thing)
		if sub == "" {
			pl.notifyOnce("wait:"+v.String(), fmt.Sprintf("%s waits for a canary", v),
				fmt.Sprintf("%s has not taken %s for over %s, and no other fleet device is online to replace it.",
					e.Thing, cj.RawID, queuedLimit))
			continue
		}
		pl.actions = append(pl.actions, Action{Kind: ActCancelExecution, JobID: cj.RawID, Thing: e.Thing})
		pl.toFleet(e.Thing)
		pl.toCanary(sub)
		pl.cancelJob(cj, "Canary "+e.Thing+" substituted by "+sub)
		pl.notify(fmt.Sprintf("canary %s substituted by %s", e.Thing, sub),
			fmt.Sprintf("%s stayed QUEUED in %s for over %s (offline?). It went back to the fleet group; %s is the canary now.",
				e.Thing, cj.RawID, queuedLimit, sub))
		pl.startCanary(d, cj.ID.Rerun+1)
		return
	}

	succeeded := 0
	var completion time.Time
	for _, e := range execs {
		if e.Status == ExecSucceeded {
			succeeded++
			if e.LastUpdatedAt.After(completion) {
				completion = e.LastUpdatedAt
			}
		}
	}
	if succeeded == 0 {
		if cj.active() && pl.s.Now.Sub(cj.CreatedAt) > canaryLifetime {
			pl.cancelJob(cj, "No canary succeeded within 48 h")
			pl.notifyOnce("stopped:"+v.String(), fmt.Sprintf("%s canary expired", v),
				fmt.Sprintf("No canary succeeded %s within %s. `scripts/ota.sh rerun %s` starts it again.",
					cj.RawID, canaryLifetime, pl.s.Product.ID))
		}
		return
	}

	// The soak gate.
	ready := true
	soakStart := completion
	for _, e := range execs {
		if e.Status != ExecSucceeded {
			if e.pending() {
				ready = false
			}
			continue // CANCELED, REMOVED: a substituted canary
		}
		dev := pl.s.Fleet[e.Thing]
		if dev == nil {
			continue // left the fleet (excluded, deleted)
		}
		sh := dev.Shadow
		if sh != nil && sh.FW == v.String() && isCrash(sh.BootReason) {
			pl.halt(v, fmt.Sprintf("canary:%s:crash-%s", e.Thing, sh.BootReason),
				fmt.Sprintf("%s runs %s and last restarted because of %s (boot %d since the update).",
					e.Thing, v, sh.BootReason, sh.BootCount))
			return
		}
		switch {
		case sh == nil || sh.ReportedAt.Before(e.LastUpdatedAt):
			ready = false // no report since the update yet
			continue
		case sh.FW != v.String():
			ready = false
			pl.notifyOnce("blocked:"+v.String()+":"+e.Thing, fmt.Sprintf("%s soak blocked on %s", v, e.Thing),
				fmt.Sprintf("%s succeeded %s but reports fw %s. `scripts/ota.sh promote %s` overrides the soak gate.",
					e.Thing, cj.RawID, sh.FW, pl.s.Product.ID))
			continue
		case sh.BootCount != 1:
			ready = false
			pl.notifyOnce("blocked:"+v.String()+":"+e.Thing, fmt.Sprintf("%s soak blocked on %s", v, e.Thing),
				fmt.Sprintf("%s restarted since the update (boot %d, reason %s). Not a crash, so the release is not halted; "+
					"`scripts/ota.sh promote %s` overrides the soak gate.", e.Thing, sh.BootCount, sh.BootReason, pl.s.Product.ID))
			continue
		case !dev.Online:
			ready = false
			continue
		}
		if dev.ConnectedAt.After(soakStart) {
			soakStart = dev.ConnectedAt // a reconnect without a reboot restarts the soak
		}
	}
	if !ready {
		return
	}
	soak := time.Duration(pl.state.SoakHours) * time.Hour
	if left := soak - pl.s.Now.Sub(soakStart); left > 0 {
		pl.logf("%s soaking, %s left", v, left.Round(time.Minute))
		return
	}
	pl.promote(d)
}

// promote creates the fleet job of d (auto) or asks the owner (hold).
func (pl *planner) promote(d *Release) {
	if pl.state.Mode == ModeHold {
		pl.notifyOnce("ready:"+d.Version.String(), fmt.Sprintf("%s ready to promote", d.Version),
			fmt.Sprintf("%s passed its canary and soak. The product is on hold: `scripts/ota.sh promote %s` rolls it out.",
				d.Version, pl.s.Product.ID))
		return
	}
	pl.rollOut(d, false)
	pl.notify(fmt.Sprintf("promoted %s", d.Version),
		fmt.Sprintf("%s is rolling out to the %s fleet (%s).", d.Version, pl.s.Product.ID, pl.s.Product.Fleet.Name))
}

// rollOut creates (or keeps) the fleet job of r, makes it the fleet version
// and only then cancels the previous fleet job, which kept converging
// stragglers until now.
func (pl *planner) rollOut(r *Release, downgrade bool) {
	fj := pl.latest(KindFleet, r.Version)
	if fj == nil || !fj.active() || downgrade {
		id := nextFree(JobID{Product: pl.s.Product.ID, Version: r.Version, Kind: KindFleet}, pl.used)
		pl.create(NewJob{
			ID: id, Release: *r, Targets: []string{pl.s.Product.Fleet.ARN}, Continuous: true,
			Signed: pl.signedFor(r, pl.fleetThings()), Downgrade: downgrade,
		})
		pl.logf("created fleet job %s", id)
		fj = nil
	}
	pl.state.FleetVersion = r.Version
	pl.dirty = true
	for _, j := range pl.s.Jobs {
		if !j.ID.Legacy && j.ID.Kind == KindFleet && j.active() && j != fj {
			pl.cancelJob(j, "Superseded by fleet version "+r.Version.String())
		}
	}
}
