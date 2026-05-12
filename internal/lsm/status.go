package lsm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// StatusOptions controls what RunStatus emits.
type StatusOptions struct {
	// JSON requests machine-readable output instead of text.
	JSON bool
}

// StatusResult is the machine-readable summary returned by RunStatus.
type StatusResult struct {
	// OK is true when preflight passes AND lsm.conf is enabled AND
	// every enabled policy is in a healthy state (preflight passes,
	// pinned state matches the configured policy set).
	OK bool

	// PreflightOK mirrors Preflight.OK.
	PreflightOK bool

	// Enabled is the global cfm-lsm enable flag from lsm.conf.
	Enabled bool

	// Source describes where lsm.conf was loaded from.
	Source string

	// ConfError, if non-empty, is a config-load error rendered as text.
	// The status command remains usable even when the file is malformed
	// — the operator needs to see the error to know what to fix.
	ConfError string

	// Pinned is the live attach state read from /sys/fs/bpf/cfm/.
	// Pinned.Exists is true when cfm-lsm has been activated via
	// `cfm lsm enable`.
	Pinned PinnedState
}

// statusJSON is the wire format for `cfm lsm status --json`.
type statusJSON struct {
	OK          bool                  `json:"ok"`
	PreflightOK bool                  `json:"preflight_ok"`
	Enabled     bool                  `json:"enabled"`
	Source      string                `json:"source"`
	ConfError   string                `json:"conf_error,omitempty"`
	Pinned      pinnedJSON            `json:"pinned"`
	Preflight   []preflightJSONCheck  `json:"preflight"`
	Policies    []policyJSON          `json:"policies"`
}

type pinnedJSON struct {
	PinDir     string   `json:"pin_dir"`
	Exists     bool     `json:"exists"`
	MapPresent bool     `json:"map_present"`
	Links      []string `json:"links"`
}

type preflightJSONCheck struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Detail      string `json:"detail,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

type policyJSON struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Hook        string `json:"hook"`
	Mode        string `json:"mode"`
	Runtime     string `json:"runtime"`
}

// RunStatus prints the cfm-lsm preflight and per-policy status to w.
// Read-only: never attaches programs, never writes config. Reads the
// live pinned state from /sys/fs/bpf/cfm/ if it exists so the report
// reflects what is actually attached right now.
func RunStatus(w io.Writer, opts StatusOptions) StatusResult {
	conf, confErr := loadStatusConf()
	pf := RunPreflight()

	res := StatusResult{
		PreflightOK: pf.OK,
		Enabled:     conf.Enabled,
		Source:      conf.Source,
		Pinned:      InspectPinned(DefaultPinDir),
	}
	if confErr != nil {
		res.ConfError = fmt.Sprintf("lsm config read failed: %v", confErr)
	}
	// "OK" means: preflight passed AND lsm.conf has enabled=true AND
	// at least one policy is pinned (live attach state matches the
	// operator's intent).
	res.OK = pf.OK && conf.Enabled && res.ConfError == "" && res.Pinned.Exists && len(res.Pinned.Links) > 0

	if opts.JSON {
		emitJSON(w, pf, conf, res)
		return res
	}
	emitText(w, pf, conf, res)
	return res
}

func loadStatusConf() (*Conf, error) {
	conf, err := LoadConf(false)
	if err == nil {
		return conf, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		c := DefaultConf()
		c.Source = "(default — no " + ConfPath + ")"
		return c, nil
	}
	c := DefaultConf()
	c.Source = "(default — read error)"
	return c, err
}

func emitText(w io.Writer, pf Preflight, conf *Conf, res StatusResult) {
	fmt.Fprintln(w, "===== CFM lsm STATUS =====")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[Config]")
	fmt.Fprintf(w, "  source:  %s\n", conf.Source)
	fmt.Fprintf(w, "  enabled: %t\n", conf.Enabled)
	if res.ConfError != "" {
		fmt.Fprintf(w, "  error:   %s\n", res.ConfError)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[Kernel preflight]")
	if pf.OK {
		fmt.Fprintln(w, "  result: PASS — host can load BPF LSM programs")
	} else {
		fmt.Fprintln(w, "  result: FAIL — host cannot load BPF LSM programs until the failing checks are fixed")
	}
	fmt.Fprintln(w)
	for _, c := range pf.Checks {
		fmt.Fprintf(w, "  [%s] %s\n", c.Status, c.Name)
		fmt.Fprintf(w, "       %s\n", c.Description)
		if c.Detail != "" {
			fmt.Fprintf(w, "       detail:      %s\n", c.Detail)
		}
		if c.Remediation != "" {
			fmt.Fprintf(w, "       remediation: %s\n", c.Remediation)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[Pinned BPF state]")
	if !res.Pinned.Exists {
		fmt.Fprintf(w, "  %s: not present (cfm-lsm has not been enabled)\n", res.Pinned.PinDir)
	} else {
		fmt.Fprintf(w, "  pin dir:    %s\n", res.Pinned.PinDir)
		fmt.Fprintf(w, "  ringbuf:    %s\n", presentLabel(res.Pinned.MapPresent))
		if len(res.Pinned.Links) == 0 {
			fmt.Fprintln(w, "  links:      (none) — pinned directory exists but holds no policy links")
		} else {
			fmt.Fprintln(w, "  links:")
			for _, id := range res.Pinned.Links {
				fmt.Fprintf(w, "    %s\n", id)
			}
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[Policies]")
	for _, p := range AllPolicies() {
		mode := conf.ModeFor(p.ID)
		runtime := describeRuntime(pf, conf, res.Pinned, mode, p.ID)
		fmt.Fprintf(w, "  %s  mode=%s  runtime=%s\n", p.ID, mode, runtime)
		fmt.Fprintf(w, "    %s — hook %s\n", p.Title, p.Hook)
	}
	fmt.Fprintln(w)
	switch {
	case !res.Pinned.Exists && conf.Enabled && pf.OK:
		fmt.Fprintln(w, "Note: lsm.conf has enabled=true and preflight passes, but no BPF programs")
		fmt.Fprintln(w, "      are currently attached. Run `cfm lsm enable` to activate.")
	case res.Pinned.Exists && !conf.Enabled:
		fmt.Fprintln(w, "Note: BPF programs are attached at the kernel level (pinned) but")
		fmt.Fprintf(w, "      %s has enabled=false. This is a config/runtime mismatch — either run\n", ConfPath)
		fmt.Fprintln(w, "      `cfm lsm disable` to detach, or flip enabled=true in lsm.conf.")
	case res.Pinned.Exists:
		fmt.Fprintln(w, "Note: cfm-lsm is active. The pinned attachments survive cfm daemon")
		fmt.Fprintln(w, "      restarts and crashes. Run `cfm lsm disable` to detach.")
	}
}

func presentLabel(present bool) string {
	if present {
		return "pinned"
	}
	return "absent"
}

func emitJSON(w io.Writer, pf Preflight, conf *Conf, res StatusResult) {
	out := statusJSON{
		OK:          res.OK,
		PreflightOK: pf.OK,
		Enabled:     conf.Enabled,
		Source:      conf.Source,
		ConfError:   res.ConfError,
		Pinned: pinnedJSON{
			PinDir:     res.Pinned.PinDir,
			Exists:     res.Pinned.Exists,
			MapPresent: res.Pinned.MapPresent,
		},
	}
	for _, id := range res.Pinned.Links {
		out.Pinned.Links = append(out.Pinned.Links, string(id))
	}
	for _, c := range pf.Checks {
		out.Preflight = append(out.Preflight, preflightJSONCheck{
			Name:        c.Name,
			Description: c.Description,
			Status:      c.Status.String(),
			Detail:      c.Detail,
			Remediation: c.Remediation,
		})
	}
	for _, p := range AllPolicies() {
		mode := conf.ModeFor(p.ID)
		out.Policies = append(out.Policies, policyJSON{
			ID:      string(p.ID),
			Title:   p.Title,
			Hook:    p.Hook,
			Mode:    mode.String(),
			Runtime: describeRuntime(pf, conf, res.Pinned, mode, p.ID),
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

// describeRuntime is the human-readable verdict for one policy. It
// reports the live pinned state when available, falling back to
// "would-attach" predictions when the policy is not currently pinned.
func describeRuntime(pf Preflight, conf *Conf, pinned PinnedState, mode Mode, id PolicyID) string {
	// Live state first — what is actually attached right now beats
	// any prediction.
	if pinned.Exists {
		for _, linkID := range pinned.Links {
			if linkID == id {
				return "attached (pinned, " + mode.String() + ")"
			}
		}
	}
	if !conf.Enabled {
		return "skip (cfm-lsm disabled in lsm.conf)"
	}
	if !pf.OK {
		return "skip (preflight FAIL)"
	}
	if mode == ModeDisabled {
		return "skip (policy disabled)"
	}
	if pinned.Exists {
		return "would-attach (run `cfm lsm disable` then `cfm lsm enable` to add this policy to the pin set)"
	}
	return "would-attach (run `cfm lsm enable` to activate)"
}
