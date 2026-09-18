package mcpserver

// detectors_config.go — read-only MCP tool over GET /api/v1/detectors/config:
// the parsed detectors.conf WITH VALUES (every section's keys, not just their
// presence). This is the "what is my config actually set to?" read that the
// other detector tools can't give: config_drift reports presence + stock-vs-live
// diffs but not the live values, detectors_status reports runtime activity, and
// detectors_srcresolve reports only the source-relevant keys.
//
// SECURITY — why this tool is NOT a plain dispatchJSON passthrough:
// /api/v1/detectors/config is admin-only and backs the cfm-admin config editor,
// so it returns detectors.conf VERBATIM — including the two live secrets that
// live in that file: CHALLENGE_TOKEN (the browser-challenge HMAC signing secret)
// and OPENRESTY_TOKEN (the edge↔daemon socket-API bearer). Returning those over
// the read-only MCP surface would break the boundary the whole MCP design rests
// on ("an MCP leak is not an admin leak", MCP.md §3): an MCP-token holder could
// forge challenge-clearance cookies or call the socket API. So this tool:
//   (1) unmarshals into a WHITELIST of fields — raw_lines[] and examples[] (both
//       of which echo secret values verbatim) are structurally dropped, never
//       re-emitted; and
//   (2) redacts the value of any key whose NAME looks like a secret
//       (secretkeys.IsSecret — shared with the CLI debug-bundle sanitiser so the
//       two can't drift), keeping a small allowlist for the one known non-secret
//       false positive (the TOKEN_IP auth-burst threshold), which operators do
//       want to audit here.
// It fails CLOSED: a non-2xx response or a body that will not parse returns an
// error, never the raw bytes.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"cfm/internal/secretkeys"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// dcSection mirrors detectorscfg.AdminSection MINUS raw_lines: the raw config
// lines echo secret values verbatim and are not needed to audit knob values, so
// they are dropped by simply not being a field here.
type dcSection struct {
	Name    string            `json:"name"`
	Kind    string            `json:"kind"`
	Enabled bool              `json:"enabled"`
	Keys    map[string]string `json:"keys"`
}

// dcConfig mirrors detectorscfg.AdminConfig MINUS examples[] (comment-derived
// templates, also a verbatim-value vector and noise for an audit).
type dcConfig struct {
	Global   map[string]string `json:"global"`
	Core     []dcSection       `json:"core"`
	Leniency []dcSection       `json:"leniency"`
	Advanced []dcSection       `json:"advanced"`
}

type dcResponse struct {
	Config       dcConfig `json:"config"`
	Path         string   `json:"path"`
	Exists       bool     `json:"exists"`
	OverlayFiles []string `json:"overlay_files"`
	RedactedKeys []string `json:"redacted_keys,omitempty"`
	Note         string   `json:"note"`
}

const dcRedactSentinel = "[redacted]"

const dcNote = "Values are the BASE /etc/cfm/detectors.conf (what the editor edits); " +
	"overlay files under /etc/cfm/detectors.d/ are listed by name in overlay_files " +
	"but their overriding values are NOT merged here — cross-check config_drift. " +
	"Secret-valued keys (e.g. CHALLENGE_TOKEN, OPENRESTY_TOKEN) are shown as " +
	"\"[redacted]\"; their presence still confirms they are set."

// dcShowAnyway keeps a secret-name-shaped key visible because it is a known
// non-secret an operator wants to audit here. Compared upper-cased.
var dcShowAnyway = map[string]bool{
	"TOKEN_IP": true, // auth-burst threshold count, not a credential
}

// redactSecretMap redacts secret-valued keys in a section/global keys map in
// place and appends the redacted key names to acc.
func redactSecretMap(keys map[string]string, acc map[string]bool) {
	for k, v := range keys {
		if v == "" {
			continue
		}
		if dcShowAnyway[strings.ToUpper(strings.TrimSpace(k))] {
			continue
		}
		if secretkeys.IsSecret(k) {
			keys[k] = dcRedactSentinel
			acc[k] = true
		}
	}
}

func registerDetectorsConfig(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "detectors_config",
		Description: "The parsed detectors.conf for this node WITH VALUES — the 'what is every knob actually set to?' read. Returns config.global plus config.core / config.leniency / config.advanced (each section: name, kind, enabled, and a keys map of the literal configured VALUES — MODE, DRY_RUN, BLOCK durations, thresholds like a challenge_cookie_discard MIN_SOLVES or a solver-farm HUMANITY_MIN_OBS/MINORITY_PCT), the resolved file path, exists, and overlay_files. Use it to confirm an exact value ('did HUMANITY_MIN_OBS land at 100?'), and to catch a knob left in monitor/observe/dryrun instead of block/enforce across a config that has grown large — neither config_drift (presence + stock-vs-live diffs, no live values) nor detectors_status (runtime activity) nor detectors_srcresolve (source keys only) can show this. Secret-valued keys (CHALLENGE_TOKEN, OPENRESTY_TOKEN, anything secret-name-shaped) are returned as \"[redacted]\" — their presence still confirms they are set; redacted_keys lists them. Caveat — BASE FILE ONLY: the values are the base /etc/cfm/detectors.conf (what the editor edits); overlays under /etc/cfm/detectors.d/*.conf are listed by name in overlay_files but their overriding values are NOT merged in here, so when overlay_files is non-empty a knob may be overridden by an overlay — cross-check with config_drift (which reads overlay section/key presence) and, for what actually took effect, the behavioural reads (detectors_status, detection_history, challenge_events). Pairs with config_drift (missing shipped features), detector_coverage (daemon-vs-detector gaps) and detectors_srcresolve (log-source resolution).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		const path = "/api/v1/detectors/config"
		status, body, err := d.Dispatch(ctx, path, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("dispatch %s: %w", path, err)
		}
		if status < 200 || status >= 300 {
			return nil, nil, fmt.Errorf("%s returned HTTP %d: %s", path, status, strings.TrimSpace(string(body)))
		}
		// Fail CLOSED: if the body will not parse into the whitelist shape we
		// cannot prove it is secret-free, so never fall back to raw bytes.
		var resp dcResponse
		dec := json.NewDecoder(strings.NewReader(string(body)))
		if err := dec.Decode(&resp); err != nil {
			return nil, nil, fmt.Errorf("%s: parse for redaction failed: %w", path, err)
		}
		redacted := map[string]bool{}
		redactSecretMap(resp.Config.Global, redacted)
		for _, group := range [][]dcSection{resp.Config.Core, resp.Config.Leniency, resp.Config.Advanced} {
			for i := range group {
				redactSecretMap(group[i].Keys, redacted)
			}
		}
		if len(redacted) > 0 {
			resp.RedactedKeys = make([]string, 0, len(redacted))
			for k := range redacted {
				resp.RedactedKeys = append(resp.RedactedKeys, k)
			}
			sort.Strings(resp.RedactedKeys)
		}
		resp.Note = dcNote
		out, err := marshal(resp)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: marshal failed: %w", path, err)
		}
		return textResult(out), nil, nil
	})
}
