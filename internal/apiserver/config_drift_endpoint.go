package apiserver

// config_drift_endpoint.go — GET /api/v1/system/config-drift (read-only,
// admin-only). Backs the MCP config_drift tool: compares the STOCK reference
// configs the package ships (/usr/share/cfm/configs/) against the LIVE
// /etc/cfm/ files, so an operator sees which features a release added that
// never reached their conffile (upgrades seed /etc/cfm once and never touch it
// again). detectors.conf is diffed section-by-section and key-by-key with the
// same parser the daemon's manager uses (internal/detconf.ReadSectionsFile),
// excluding the optional default-on cfm_endpoints/api_abuse family whose
// absence from a live conffile is not runtime drift;
// cfm.conf is checked for stock-documented keys absent from the live text
// entirely. Values are informational only — live values legitimately differ
// per host.
//
// Host-wide config state → admin-only by construction, same family as the
// other /api/v1/system/* reads.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"cfm/internal/config"
	"cfm/internal/configdrift"
	"cfm/internal/detconf"
	webdet "cfm/internal/webdetector"
)

// stockConfigCandidates returns the paths to try for a reference config, in
// resolution order: the packaged tree first, then flat legacy layouts, then
// the in-repo tree (dev checkouts).
func stockConfigCandidates(name string) []string {
	return []string{
		filepath.Join("/usr/share/cfm/configs", name),
		filepath.Join("/usr/share/cfm", name),
		filepath.Join("configs", name),
	}
}

func firstExisting(paths []string) string {
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

// liveConfigDir mirrors cli.ResolveConfigDir minimally (env override → /etc/cfm)
// without importing internal/cli (heavy dep graph).
func liveConfigDir() string {
	if d := os.Getenv("CFM_CONFIG_DIR"); d != "" {
		return d
	}
	return "/etc/cfm"
}

func handleSystemConfigDrift(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}

	cfgDir := liveConfigDir()
	resp := map[string]any{
		"ok":       true,
		"schema":   "system.config_drift.v1",
		"live_dir": cfgDir,
	}

	// ── detectors.conf ────────────────────────────────────────────────────────
	det := map[string]any{"name": "detectors.conf"}
	stockPath := firstExisting(stockConfigCandidates("detectors.conf"))
	livePath := filepath.Join(cfgDir, "detectors.conf")
	det["stock_path"] = stockPath
	det["live_path"] = livePath
	switch {
	case stockPath == "":
		det["stock_found"] = false
		det["note"] = "stock reference not found on this host (dev checkout? package without configs tree?)"
	case !fileReadable(livePath):
		det["stock_found"] = true
		det["live_found"] = false
	default:
		det["stock_found"] = true
		det["live_found"] = true
		stockSec, errStock := detconf.ReadSectionsFile(stockPath)
		liveSec, errLive := detconf.ReadSectionsFile(livePath)
		switch {
		case errStock != nil:
			det["error"] = "parse stock: " + errStock.Error()
		case errLive != nil:
			det["error"] = "parse live: " + errLive.Error()
		default:
			rep := diffDetectorsConfig(stockSec, liveSec)
			det["report"] = rep
			det["summary"] = map[string]any{
				"missing_sections": len(rep.MissingSections),
				"missing_keys":     len(rep.MissingKeys),
				"value_diffs":      rep.ValueDiffs,
			}
		}
	}
	resp["detectors_conf"] = det

	// ── cfm.conf ──────────────────────────────────────────────────────────────
	cf := map[string]any{"name": "cfm.conf"}
	cfmStock := firstExisting(stockConfigCandidates("cfm.conf"))
	cfmLive := filepath.Join(cfgDir, "cfm.conf")
	cf["stock_path"] = cfmStock
	cf["live_path"] = cfmLive
	switch {
	case cfmStock == "":
		cf["stock_found"] = false
	default:
		sb, errS := os.ReadFile(cfmStock)
		lb, errL := os.ReadFile(cfmLive)
		cf["stock_found"] = errS == nil
		cf["live_found"] = errL == nil
		if errS == nil && errL == nil {
			rep := configdrift.DiffFlat(string(sb), string(lb), config.IsKnownKey)
			cf["report"] = rep
		}
	}
	resp["cfm_conf"] = cf

	_ = json.NewEncoder(w).Encode(resp)
}

func diffDetectorsConfig(stock, live detconf.Sections) configdrift.DetectorsReport {
	return configdrift.DiffDetectorsSectionsIgnoring(stock, live, func(section string) bool {
		base := strings.TrimSuffix(strings.TrimSpace(section), ".leniency")
		typ, _ := detconf.SplitTypeInstance(base)
		return typ == "cfm_endpoints" || typ == "api_abuse"
	})
}

func fileReadable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}
