package mcpserver

import (
	"encoding/json"
	"fmt"
)

// evalMailRuntime maps the mail_runtime saturation snapshot
// (/api/v1/mail/runtime) into whats_wrong findings. Threshold policy lives in
// the mailruntime package (Saturation classification); this layer only turns an
// already-classified resource into a ranked finding:
//
//   - critical → a critical finding (the pool is at/over its cap),
//   - warn     → a warning finding (approaching the cap, "saturating"),
//   - ok / unknown → NO finding. An unresolved cap is unknown, not a problem;
//     surfacing it here would be noise (it stays visible via the mail_runtime
//     tool itself and via `sources` when the whole section can't be read).
//
// This is the SMTP/spamd blind spot from docs/whats-wrong-rootcause.md §5a: a
// server "up" on every mail daemon yet wedged because spamd is saturated and
// inbound SMTP sessions have hit smtp_accept_max.
func evalMailRuntime(body json.RawMessage) []finding {
	var p struct {
		Snapshot struct {
			SMTP  mailRuntimeResource `json:"smtp"`
			Spamd mailRuntimeResource `json:"spamd"`
		} `json:"snapshot"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return nil
	}
	var fs []finding
	if f, ok := mailRuntimeFinding("SMTP connection", p.Snapshot.SMTP,
		"new inbound mail is refused and submission (587) can go unavailable"); ok {
		fs = append(fs, f)
	}
	if f, ok := mailRuntimeFinding("spamd scanner", p.Snapshot.Spamd,
		"SMTP sessions pile up waiting for a free scanner child"); ok {
		fs = append(fs, f)
	}
	return fs
}

type mailRuntimeResource struct {
	Util struct {
		Current int     `json:"current"`
		Max     int     `json:"max"`
		Pct     float64 `json:"pct"`
		Known   bool    `json:"known"`
	} `json:"util"`
	Sat string `json:"sat"`
}

// mailRuntimeFinding builds a ranked finding from one saturated resource, or
// (finding{}, false) for ok/unknown. `what` names the pool, `consequence` is the
// one-line operator impact. warn/critical both imply a resolved cap (the
// classifier only returns them when Known), so Util.Max is non-zero here.
func mailRuntimeFinding(what string, r mailRuntimeResource, consequence string) (finding, bool) {
	var sev, phase string
	switch r.Sat {
	case "critical":
		sev, phase = sevCritical, "at/over the cap"
	case "warn":
		sev, phase = sevWarning, "approaching the cap"
	default:
		return finding{}, false // ok / unknown → not a finding
	}
	return finding{
		Severity: sev,
		Category: "mail",
		Title:    what + " pool " + r.Sat,
		Detail: fmt.Sprintf("%s pool at %d/%d (%.0f%%, %s); %s.",
			what, r.Util.Current, r.Util.Max, r.Util.Pct, phase, consequence),
		Tool: "mail_runtime",
	}, true
}
