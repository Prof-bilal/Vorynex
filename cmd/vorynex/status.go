package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vorynex/vorynex/engine/audit"
	"github.com/vorynex/vorynex/engine/enforce/live"
	"github.com/vorynex/vorynex/engine/enforce/spawntime"
	"github.com/vorynex/vorynex/engine/policy"
	"github.com/vorynex/vorynex/engine/profiler"
	"github.com/vorynex/vorynex/engine/state"
	"github.com/vorynex/vorynex/engine/telemetry"
)

type policyStatus struct {
	Path           string `json:"path"`
	SHA256         string `json:"sha256,omitempty"`
	Version        int    `json:"version,omitempty"`
	Read           int    `json:"read"`
	Write          int    `json:"write"`
	Deny           int    `json:"deny"`
	ExecAllow      int    `json:"exec_allow"`
	ExecDeny       int    `json:"exec_deny"`
	NetworkAllow   int    `json:"network_allow"`
	ProtectSecrets bool   `json:"protect_secrets"`
	Error          string `json:"error,omitempty"`
}

type capabilityStatus struct {
	LandlockABI int      `json:"landlock_abi"`
	Tier0       bool     `json:"tier0"`
	Tier1       bool     `json:"tier1"`
	Reasons     []string `json:"reasons,omitempty"`
}

type eventStatus struct {
	Scanned   int `json:"scanned"`
	Contained int `json:"contained"`
	WouldDeny int `json:"would_deny"`
}

type telemetrySummary struct {
	Buffered int    `json:"buffered"`
	Pending  int    `json:"pending"`
	Cursor   uint64 `json:"cursor"`
	Endpoint string `json:"endpoint,omitempty"`
}

type rolloutState struct {
	Revision    int    `json:"revision"`
	Mode        string `json:"mode"`
	PolicyBytes int    `json:"policy_bytes"`
}

type statusReport struct {
	HostID       string           `json:"host_id"`
	Workload     string           `json:"workload,omitempty"`
	Mode         string           `json:"mode"`
	ModeRecorded bool             `json:"mode_recorded"`
	ControlPlane string           `json:"control_plane,omitempty"`
	Policy       *policyStatus    `json:"policy,omitempty"`
	Capabilities capabilityStatus `json:"capabilities"`
	Events       eventStatus      `json:"events"`
	Telemetry    telemetrySummary `json:"telemetry"`
	Rollout      *rolloutState    `json:"rollout,omitempty"`
	UpdatedAt    time.Time        `json:"updated_at,omitempty"`
}

// runStatus reports what this host is doing right now, from local state only.
// It works with the control plane unreachable.
func runStatus(args []string) error {
	jsonOut := false
	for _, a := range args {
		switch a {
		case "--json":
			jsonOut = true
		default:
			return fmt.Errorf("unknown flag %q (want --json)", a)
		}
	}

	rep := buildStatus()
	if jsonOut {
		b, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	printStatus(rep)
	return nil
}

func buildStatus() statusReport {
	dir := telemetry.DefaultDir()
	hostID, _ := telemetry.LoadOrCreateHostID(dir)
	st := state.Load()

	mode := st.Mode
	if mode == "" {
		mode = state.ModeObserve
	}

	abi := spawntime.LandlockABI()
	caps := live.Detect()
	rep := statusReport{
		HostID:       hostID,
		Workload:     st.Workload,
		Mode:         string(mode),
		ModeRecorded: st.Mode != "",
		ControlPlane: st.ControlPlane,
		UpdatedAt:    st.UpdatedAt,
		Capabilities: capabilityStatus{LandlockABI: abi, Tier0: abi > 0, Tier1: caps.Available, Reasons: caps.Reasons},
	}

	if st.PolicyPath != "" {
		if p, err := policy.Load(st.PolicyPath); err == nil {
			rep.Policy = &policyStatus{
				Path:           st.PolicyPath,
				SHA256:         st.PolicySHA256,
				Version:        p.Version,
				Read:           len(p.Filesystem.Read),
				Write:          len(p.Filesystem.Write),
				Deny:           len(p.Filesystem.Deny),
				ExecAllow:      len(p.Process.Exec.Allow),
				ExecDeny:       len(p.Process.Exec.Deny),
				NetworkAllow:   len(p.Network.Allow),
				ProtectSecrets: p.Filesystem.ProtectSecrets,
			}
		} else {
			rep.Policy = &policyStatus{Path: st.PolicyPath, SHA256: st.PolicySHA256, Error: err.Error()}
		}
	}

	events, buffered := localEvents()
	contained, wouldDeny := 0, 0
	for _, e := range events {
		if isContainedEvent(e) {
			contained++
			continue
		}
		if _, _, dangerous, _ := profiler.Classify(e); dangerous && e.Allowed {
			wouldDeny++
		}
	}
	rep.Events = eventStatus{Scanned: len(events), Contained: contained, WouldDeny: wouldDeny}

	cursor := telemetry.LoadCursor(dir)
	pending := 0
	if sp, err := telemetry.OpenSpool(telemetry.DefaultSpoolPath(), 0); err == nil {
		if recs, err := sp.ReadAfter(cursor); err == nil {
			pending = len(recs)
		}
	}
	rep.Telemetry = telemetrySummary{Buffered: buffered, Pending: pending, Cursor: cursor, Endpoint: st.ControlPlane}

	if d := telemetry.LoadDesired(dir); d.Revision > 0 || d.Mode != "" {
		rep.Rollout = &rolloutState{Revision: d.Revision, Mode: d.Mode, PolicyBytes: len(d.Policy)}
	}
	return rep
}

// localEvents returns every locally buffered event (spool first, newest trace
// as a fallback) plus the spool size.
func localEvents() ([]audit.Event, int) {
	if _, err := os.Stat(telemetry.DefaultSpoolPath()); err == nil {
		if sp, err := telemetry.OpenSpool(telemetry.DefaultSpoolPath(), 0); err == nil {
			if recs, err := sp.ReadAfter(0); err == nil {
				out := make([]audit.Event, 0, len(recs))
				for _, r := range recs {
					if !r.Gap {
						out = append(out, r.Event)
					}
				}
				return out, len(recs)
			}
		}
	}
	if p, err := audit.LatestTracePath(); err == nil {
		if f, err := os.Open(p); err == nil {
			defer f.Close()
			if evs, err := audit.ReadEvents(f); err == nil {
				return evs, len(evs)
			}
		}
	}
	return nil, 0
}

func isContainedEvent(e audit.Event) bool {
	if e.Allowed {
		return false
	}
	return strings.Contains(e.Reason, "EACCES") || strings.Contains(e.Reason, "EPERM")
}

func printStatus(rep statusReport) {
	fmt.Printf("Vorynex status — %s\n", rep.HostID)
	if rep.Workload != "" {
		fmt.Printf("  workload        %s\n", rep.Workload)
	}
	modeNote := " — recorded locally"
	if !rep.ModeRecorded {
		modeNote = " — not recorded yet; run `vorynex connect`"
	}
	fmt.Printf("  mode            %s%s\n", rep.Mode, modeNote)

	if rep.Policy == nil {
		fmt.Println("  policy          none — run `vorynex policy generate`, then `vorynex protect`")
	} else if rep.Policy.Error != "" {
		fmt.Printf("  policy          %s (unreadable: %s)\n", rep.Policy.Path, rep.Policy.Error)
	} else {
		fmt.Printf("  policy          %s · v%d · read %d · write %d · deny %d · exec +%d/-%d · net %d · secrets %s\n",
			rep.Policy.Path, rep.Policy.Version, rep.Policy.Read, rep.Policy.Write, rep.Policy.Deny,
			rep.Policy.ExecAllow, rep.Policy.ExecDeny, rep.Policy.NetworkAllow,
			onOff(rep.Policy.ProtectSecrets))
	}

	if rep.Capabilities.Tier0 {
		fmt.Printf("  tier 0          landlock ABI %d\n", rep.Capabilities.LandlockABI)
	} else {
		fmt.Println("  tier 0          unavailable (no Landlock)")
	}
	if rep.Capabilities.Tier1 {
		fmt.Println("  tier 1          available (eBPF-LSM)")
	} else {
		reason := "unavailable"
		if len(rep.Capabilities.Reasons) > 0 {
			reason = rep.Capabilities.Reasons[0]
		}
		fmt.Printf("  tier 1          unavailable (%s)\n", reason)
	}

	fmt.Printf("  events          scanned %d · contained %d · would-deny %d\n",
		rep.Events.Scanned, rep.Events.Contained, rep.Events.WouldDeny)
	fmt.Printf("  telemetry       buffered %d · pending %d · cursor %d\n",
		rep.Telemetry.Buffered, rep.Telemetry.Pending, rep.Telemetry.Cursor)
	if rep.Telemetry.Endpoint != "" {
		fmt.Printf("  control plane   %s\n", rep.Telemetry.Endpoint)
	}
	if rep.Rollout != nil {
		fmt.Printf("  rollout         revision %d · mode %s · policy %d bytes\n",
			rep.Rollout.Revision, rep.Rollout.Mode, rep.Rollout.PolicyBytes)
	}

	fmt.Println()
	if rep.Mode == string(state.ModeObserve) {
		fmt.Println("next: review what Protect would block, then `vorynex protect --from <events.jsonl>`")
	} else {
		fmt.Println("next: `vorynex protect --off` restores observe")
	}
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
