package apiserver

// detector_coverage_endpoint.go — GET /api/v1/detectors/coverage (read-only,
// admin-only via adminOnlyHandler). Backs the MCP detector_coverage tool.
//
// Cross-references three signals the UI/CLI keep separate today:
//
//  1. the registered detector catalogue (internal/detectors/meta — the
//     universe of detector TYPES the binary can run),
//  2. the live detectors.conf state per section (detectorstatus snapshot:
//     Configured / Enabled / Active / SourceProbeOK),
//  3. whether the watched DAEMON actually exists on this host, probed via
//     svcstat over a curated type→units affinity table (below).
//
// The point is verdicts that respect host reality: a detector whose daemon is
// absent is "absent" (informational — the cfm-admin inventory used to present
// these as complaints), while "daemon RUNNING but detector unconfigured /
// ENABLED=0" is a genuine coverage GAP worth surfacing, and "enabled but
// daemon absent" is DORMANT (the detector will idle or fail its source probe).

import (
	"net/http"
	"sort"
	"strings"

	"cfm/internal/detectors/meta"
	"cfm/internal/detectorstatus"
	"cfm/internal/svcstat"
)

// detectorUnits maps each registered detector type to the systemd units whose
// presence indicates the watched daemon exists. Curated by hand from each
// register file's default source (JOURNAL_UNIT defaults, log-path candidates,
// ftpd's probe list); mirrors internal/svcstat.DefaultUnits naming where they
// overlap. Unit names are passed to svcstat.Status, which appends ".service".
// Types absent from this map are event-driven (no daemon concept).
var detectorUnits = map[string][]string{
	"ssh_auth":         {"sshd", "ssh"},
	"exim_queues":      {"exim"},
	"exim_security":    {"exim"},
	"exim_relays":      {"exim"},
	"postfix_queues":   {"postfix"},
	"postfix_security": {"postfix"},
	"postfix_relays":   {"postfix"},
	"dovecot_auth":     {"dovecot"},
	"ftpd":             {"vsftpd", "pure-ftpd", "proftpd"},
	"mysql":            {"mysqld", "mysql", "mariadb"},
	"mysql_governor":   {"mysqld", "mysql", "mariadb"},
	"cpanel":           {"cpanel", "cpsrvd"},
	"modsec":           {"httpd", "apache2", "lsws", "nginx", "angie"},
	"proxmox_auth":     {"pvedaemon", "pveproxy"},
	"webdetector":      {"angie", "openresty", "nginx", "httpd", "apache2", "lsws"},
}

func handleDetectorsCoverage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	snap := detectorstatus.GetSnapshot()

	unitSet := map[string]bool{}
	for _, units := range detectorUnits {
		for _, u := range units {
			unitSet[u] = true
		}
	}
	unitList := make([]string, 0, len(unitSet))
	for u := range unitSet {
		unitList = append(unitList, u)
	}
	sort.Strings(unitList)

	// Explicit queries keep not-found rows (svcstat only elides them for the
	// default set), and never hard-fails: a non-systemd host comes back empty.
	svcs, _ := svcstat.Status(r.Context(), unitList)
	svcByUnit := make(map[string]svcstat.Service, len(svcs))
	for _, s := range svcs {
		svcByUnit[normalizeUnitKey(s.Unit)] = s
	}

	rows := buildCoverageRows(meta.Catalog(), snap.Sections, svcByUnit)
	summary := summarizeCoverage(rows)

	writeNotifierJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"schema":   "detectors.coverage.v1",
		"summary":  summary,
		"types":    rows,
		"sections": snap.Sections, // full runtime detail incl. last-error/diagnostics
	})
}

type coverageUnit struct {
	Unit    string `json:"unit"`
	Found   bool   `json:"found"`                   // unit exists on this host (LoadState != not-found)
	Active  bool   `json:"active"`                  // ActiveState == active
	Enabled string `json:"enabled_state,omitempty"` // UnitFileState (enabled/disabled/static/…)
}

type coverageSection struct {
	Section       string `json:"section"`
	Configured    bool   `json:"configured"`
	Enabled       bool   `json:"enabled"`
	Active        bool   `json:"active"`
	SourceProbeOK bool   `json:"source_probe_ok"`
}

type coverageType struct {
	Type        string            `json:"type"`
	Title       string            `json:"title,omitempty"`
	DaemonAware bool              `json:"daemon_aware"`
	Verdict     string            `json:"verdict"` // ok | gap | disabled | dormant | absent | na
	Note        string            `json:"note,omitempty"`
	Units       []coverageUnit    `json:"units,omitempty"`
	Sections    []coverageSection `json:"sections,omitempty"`
}

type coverageSummary struct {
	TypesTotal int `json:"types_total"`
	OK         int `json:"ok"`
	Gaps       int `json:"gaps"`
	Disabled   int `json:"disabled"`
	Dormant    int `json:"dormant"`
	Absent     int `json:"absent"`
	EventOnly  int `json:"event_driven"`
}

// normalizeUnitKey lowercases and strips a trailing .service so queried names
// match systemctl's resolved Id.
func normalizeUnitKey(u string) string {
	u = strings.ToLower(strings.TrimSpace(u))
	return strings.TrimSuffix(u, ".service")
}

// buildCoverageRows is the pure core (unit-tested): one row per catalog type,
// grouped sections, probed units, and a reality-aware verdict.
func buildCoverageRows(catalog []meta.DetectorMeta, sections []detectorstatus.RuntimeStatus, svcByUnit map[string]svcstat.Service) []coverageType {
	rows := make([]coverageType, 0, len(catalog))
	for _, m := range catalog {
		row := coverageType{Type: m.TypeKey, Title: m.Title}
		units := detectorUnits[m.TypeKey]
		if len(units) == 0 {
			row.Verdict = "na"
			row.Note = "event-driven detector (subscribes to in-process events; no daemon)"
			rows = append(rows, row)
			continue
		}
		row.DaemonAware = true

		var anyConfigured, anyEnabled bool
		for _, s := range sections {
			if !strings.EqualFold(strings.TrimSpace(s.Type), m.TypeKey) &&
				!strings.EqualFold(sectionTypeOf(s.Section), m.TypeKey) {
				continue
			}
			row.Sections = append(row.Sections, coverageSection{
				Section: s.Section, Configured: s.Configured, Enabled: s.Enabled,
				Active: s.Active, SourceProbeOK: s.SourceProbeOK,
			})
			if s.Configured {
				anyConfigured = true
			}
			if s.Enabled {
				anyEnabled = true
			}
		}

		foundAny, activeAny := false, false
		for _, u := range units {
			s, ok := svcByUnit[normalizeUnitKey(u)]
			cu := coverageUnit{Unit: u}
			if ok {
				cu.Found = s.Load != "" && s.Load != "not-found"
				cu.Active = s.Active == "active"
				cu.Enabled = s.Enabled
			}
			if cu.Found {
				foundAny = true
			}
			if cu.Active {
				activeAny = true
			}
			row.Units = append(row.Units, cu)
		}

		switch {
		case activeAny && anyEnabled:
			row.Verdict = "ok"
		case activeAny && !anyConfigured:
			row.Verdict = "gap"
			row.Note = "daemon is running but no [" + m.TypeKey + "] section exists in detectors.conf"
		case activeAny: // configured but every instance ENABLED=0
			row.Verdict = "disabled"
			row.Note = "daemon is running but all its sections carry ENABLED=0"
		case anyEnabled: // not running (installed-stopped or absent) yet enabled somewhere
			row.Verdict = "dormant"
			if foundAny {
				row.Note = "unit installed but not active; enabled section(s) will idle or fail their source probe"
			} else {
				row.Note = "no candidate unit exists on this host; enabled section(s) have nothing to watch"
			}
		default:
			row.Verdict = "absent"
			if !anyConfigured {
				row.Note = "daemon not present and detector not configured (nothing to do)"
			} else {
				row.Note = "daemon not present; remaining sections are ENABLED=0"
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// sectionTypeOf derives the type half of a possibly-instanced section name
// ("exim_security:secondary" → "exim_security") without pulling in the
// detectors package (which would widen apiserver's import graph).
func sectionTypeOf(section string) string {
	parts := strings.FieldsFunc(section, func(r rune) bool { return r == ':' || r == ' ' || r == '\t' })
	if len(parts) == 0 {
		return strings.TrimSpace(section)
	}
	return parts[0]
}

func summarizeCoverage(rows []coverageType) coverageSummary {
	var s coverageSummary
	s.TypesTotal = len(rows)
	for _, r := range rows {
		switch r.Verdict {
		case "ok":
			s.OK++
		case "gap":
			s.Gaps++
		case "disabled":
			s.Disabled++
		case "dormant":
			s.Dormant++
		case "absent":
			s.Absent++
		default:
			s.EventOnly++
		}
	}
	return s
}
