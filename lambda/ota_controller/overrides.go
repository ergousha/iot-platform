package main

import (
	"errors"
	"fmt"
	"strings"
)

// Override is an owner command: from scripts/ota.sh (direct invoke) or the
// AWS_IAM Function URL (the portal). Through the URL, the portal's viewer
// role may only send status.
type Override struct {
	Action  string `json:"action"`
	Product string `json:"product"`
	Version string `json:"version,omitempty"`
	Thing   string `json:"thing,omitempty"`
	// Confirm repeats the thing name for decommission.
	Confirm string `json:"confirm,omitempty"`

	// by names a Function URL caller (set by the handler, never decoded).
	by string
}

// createsJobs: refused while the guard is tripped.
func (o Override) createsJobs() bool {
	switch o.Action {
	case "promote", "rerun", "rollback", "target", "resume":
		return true
	}
	return false
}

// planOverride plans one override against a snapshot of its product. Only
// verified releases are ever rolled out, and only rollback sets downgrade.
func planOverride(s *Snapshot, o Override) (Plan, error) {
	pl := newPlanner(s)
	fv := pl.state.FleetVersion
	verified := func() (*Release, error) {
		if o.Version == "" {
			return nil, errors.New("version is required")
		}
		v, err := ParseVersion(o.Version)
		if err != nil {
			return nil, err
		}
		r := pl.release(v)
		if r == nil {
			return nil, fmt.Errorf("%s is not a verified release of %s", v, s.Product.ID)
		}
		return r, nil
	}
	setMode := func(m string) {
		pl.state.Mode = m
		pl.dirty = true
		pl.logf("ota_mode %s", m)
	}

	switch o.Action {
	case "hold":
		setMode(ModeHold)
	case "resume":
		setMode(ModeAuto)
	case "freeze":
		setMode(ModeFrozen)

	case "promote":
		if o.Version == "" {
			d := pl.desired()
			if d == nil {
				return Plan{}, fmt.Errorf("%s has no verified release above the fleet version %s", s.Product.ID, fv)
			}
			o.Version = d.Version.String()
		}
		r, err := verified()
		if err != nil {
			return Plan{}, err
		}
		if !fv.Less(r.Version) {
			return Plan{}, fmt.Errorf("%s is not above the fleet version %s; use rollback", r.Version, fv)
		}
		pl.clearHalt(r.Version)
		pl.rollOut(r, false)
		pl.notify(fmt.Sprintf("promoted %s (owner)", r.Version),
			fmt.Sprintf("The owner promoted %s to the %s fleet.", r.Version, s.Product.ID))

	case "rerun":
		if o.Version == "" {
			switch d := pl.desired(); {
			case !pl.state.HaltedVersion.IsZero():
				o.Version = pl.state.HaltedVersion.String()
			case d != nil:
				o.Version = d.Version.String()
			default:
				return Plan{}, fmt.Errorf("%s has nothing to rerun", s.Product.ID)
			}
		}
		r, err := verified()
		if err != nil {
			return Plan{}, err
		}
		if !fv.Less(r.Version) {
			return Plan{}, fmt.Errorf("%s is not above the fleet version %s", r.Version, fv)
		}
		pl.clearHalt(r.Version)
		pl.forget(r.Version)
		if len(s.Fleet) <= 1 {
			pl.rollOut(r, false)
			break
		}
		rerun := 0
		for _, j := range pl.jobsOf(KindCanary, r.Version) {
			pl.cancelJob(j, "Rerun by the owner")
			if j.ID.Rerun+1 > rerun {
				rerun = j.ID.Rerun + 1
			}
		}
		pl.startCanary(r, rerun)

	case "rollback":
		r, err := verified()
		if err != nil {
			return Plan{}, err
		}
		if fv.IsZero() || !r.Version.Less(fv) {
			return Plan{}, fmt.Errorf("rollback needs a version below the fleet version %s", fv)
		}
		for _, j := range s.Jobs {
			if j.ID.Kind == KindCanary {
				pl.cancelJob(j, "Rollback to "+r.Version.String())
			}
		}
		pl.rollOut(r, true)
		pl.state.HaltedVersion, pl.state.HaltedReason = fv, "rollback"
		pl.state.Mode = ModeHold
		pl.notify(fmt.Sprintf("rolled back to %s", r.Version),
			fmt.Sprintf("The owner rolled %s back from %s to %s (downgrade). %s is halted and the product is on hold: "+
				"no release is promoted until `scripts/ota.sh resume %s`.", s.Product.ID, fv, r.Version, fv, s.Product.ID))

	case "target":
		if o.Thing == "" {
			return Plan{}, errors.New("thing is required")
		}
		_, inFleet := s.Fleet[o.Thing]
		if !inFleet && !s.Excluded[o.Thing] {
			return Plan{}, fmt.Errorf("%s is not a %s device", o.Thing, s.Product.ID)
		}
		if o.Version == "" {
			o.Version = fv.String()
		}
		r, err := verified()
		if err != nil {
			return Plan{}, err
		}
		if s.Excluded[o.Thing] {
			pl.move(o.Thing, []string{s.Product.Fleet.Name}, []string{s.Product.Excluded.Name})
		}
		id := nextFree(JobID{Product: s.Product.ID, Version: r.Version, Kind: KindTarget, Thing: o.Thing}, pl.used)
		if !id.Valid() {
			return Plan{}, fmt.Errorf("job id %s is too long", id)
		}
		pl.create(NewJob{
			ID: id, Release: *r, Targets: []string{s.ThingARN(o.Thing)},
			Downgrade: r.Version.Less(fv),
		})

	default:
		return Plan{}, fmt.Errorf("unknown action %q", o.Action)
	}
	return pl.finish(), nil
}

func (pl *planner) clearHalt(v Version) {
	if pl.state.HaltedVersion == v {
		pl.state.HaltedVersion, pl.state.HaltedReason = Version{}, ""
		pl.dirty = true
	}
}

// forget drops the one-off emails about v, so a rerun reports afresh.
func (pl *planner) forget(v Version) {
	var keep []string
	for _, k := range pl.state.Notified {
		if !strings.HasSuffix(k, ":"+v.String()) && !strings.Contains(k, ":"+v.String()+":") {
			keep = append(keep, k)
		}
	}
	pl.state.Notified = keep
	pl.dirty = true
}
