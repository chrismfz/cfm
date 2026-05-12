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
	// every enabled policy is in a healthy state. For the scaffolding
	// slice, "healthy" effectively means "would attach if BPF were
	// wired up" — no actual attach has happened yet.
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
}

// statusJSON is the wire format for `cfm lsm status --json`.
type statusJSON struct {
	OK          bool                  `json:"ok"`
	PreflightOK bool                  `json:"preflight_ok"`
	Enabled     bool                  `json:"enabled"`
	Source      string                `json:"source"`
	ConfError   string                `json:"conf_error,omitempty"`
	Preflight   []preflightJSONCheck  `json:"preflight"`
	Policies    []policyJSON          `json:"policies"`
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
// Read-only: never attaches programs, never writes config.
func RunStatus(w io.Writer, opts StatusOptions) StatusResult {
	conf, confErr := loadStatusConf()
	pf := RunPreflight()

	res := StatusResult{
		PreflightOK: pf.OK,
		Enabled:     conf.Enabled,
		Source:      conf.Source,
	}
	if confErr != nil {
		res.ConfError = fmt.Sprintf("lsm config read failed: %v", confErr)
	}
	// "OK" for the scaffolding slice means: preflight passed AND the
	// operator has enabled cfm-lsm. The BPF backend not being wired
	// up is reflected in the per-policy runtime column.
	res.OK = pf.OK && conf.Enabled && res.ConfError == ""

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

	fmt.Fprintln(w, "[Policies]")
	for _, p := range AllPolicies() {
		mode := conf.ModeFor(p.ID)
		runtime := describeRuntime(pf, conf, mode)
		fmt.Fprintf(w, "  %s  mode=%s  runtime=%s\n", p.ID, mode, runtime)
		fmt.Fprintf(w, "    %s — hook %s\n", p.Title, p.Hook)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Note: BPF programs are not yet implemented. This release ships the")
	fmt.Fprintln(w, "      preflight, config, and CLI scaffolding only — runtime column")
	fmt.Fprintln(w, "      reflects whether each policy WOULD attach once BPF code lands.")
}

func emitJSON(w io.Writer, pf Preflight, conf *Conf, res StatusResult) {
	out := statusJSON{
		OK:          res.OK,
		PreflightOK: pf.OK,
		Enabled:     conf.Enabled,
		Source:      conf.Source,
		ConfError:   res.ConfError,
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
			Runtime: describeRuntime(pf, conf, mode),
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

// describeRuntime is the human-readable verdict for one policy. Until
// the BPF backend lands, "would-attach" / "would-skip" is the strongest
// claim we can make.
func describeRuntime(pf Preflight, conf *Conf, mode Mode) string {
	if !conf.Enabled {
		return "skip (cfm-lsm disabled in lsm.conf)"
	}
	if !pf.OK {
		return "skip (preflight FAIL)"
	}
	if mode == ModeDisabled {
		return "skip (policy disabled)"
	}
	return "would-attach (BPF backend not yet implemented)"
}
