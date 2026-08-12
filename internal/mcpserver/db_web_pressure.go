package mcpserver

// db_web_pressure correlates per-account MySQL pressure with per-vhost web
// request volume to surface "few web hits, high DB pressure" tenants — a
// hosting account grinding its databases while its sites take almost no
// front-end traffic (runaway cron/import, abusive backend script, or a
// compromised account), as opposed to the boring "lots of traffic → lots of
// DB". It composes three read-only endpoints in-process (no caller-controlled
// path), builds the host→owner map from the canonical panelmap reader, and
// folds everything with the pure, unit-tested dbwebcorr leaf.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"cfm/internal/dbwebcorr"
	mysqlpkg "cfm/internal/detectors/mysql"
	"cfm/internal/panelmap"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// isNonTenantDBUser reports whether a MySQL user is not a real hosting tenant
// and should be dropped from the correlation. It defers to the governor's
// authoritative exempt-user set (mysqlpkg.IsExemptUser — root, cpanel*,
// proxysql_monitor, mysql.session, …) rather than a divergent local denylist
// (CLAUDE.md §5), plus a catch-all for the dotted internal MySQL accounts
// (mysql.*, mariadb.*, *.sys) a real cPanel/DA username can never contain.
func isNonTenantDBUser(user string) bool {
	if mysqlpkg.IsExemptUser(user) {
		return true
	}
	return strings.Contains(dbwebcorr.AccountOf(user), ".")
}

type dbWebPressureInput struct {
	Top int `json:"top,omitempty" jsonschema:"how many accounts to return, most-interesting-first (flagged few-hits/high-pressure first); default 25, max 200"`
}

func registerDBWebPressure(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "db_web_pressure",
		Description: "Correlates per-ACCOUNT MySQL pressure with per-vhost web request volume to catch the 'few web hits, high DB pressure' tenant — a hosting account whose databases are busy while its sites take almost no traffic (a runaway cron/import, an abusive backend script, or a compromised account), NOT the boring 'lots of traffic → lots of DB'. Folds DB users (acct_*) and vhosts up to the owning cPanel account and returns accounts most-interesting-first: those flagged few_hits_high_pressure (pressure above a floor AND web hits at/under a ceiling) sort first, then by pressure-per-hit. Each row carries the account's cpu_sec/busy_sec/query_count, web_rps/web_hits, its db_users + vhosts, and the flag. The perf block says whether cpu numbers are real (on many CloudLinux MariaDB builds cpu_sec is 0 and busy_sec is the CPU proxy). Read the `notes` array for caveats: host→owner attribution is cPanel-only (/etc/userdatadomains, /etc/userdomains) so on a non-cPanel host web hits can't be attributed (web_attribution.vhosts_mapped=0), and if no real CPU signal is available (perf_schema/userstat off) pressure can't be measured so nothing flags.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dbWebPressureInput) (*mcp.CallToolResult, any, error) {
		topN := in.Top
		if topN <= 0 {
			topN = 25
		}
		if topN > 200 {
			topN = 200
		}

		cpuBody := section(ctx, d, "/api/v1/mysql/cpu", nil)
		if e := sectionError(cpuBody); e != "" {
			return nil, nil, fmt.Errorf("mysql/cpu: %s", e)
		}
		webBody := section(ctx, d, "/api/v1/webdet/top-short", nil)
		if e := sectionError(webBody); e != "" {
			return nil, nil, fmt.Errorf("webdet/top-short: %s", e)
		}
		// /mysql/top is optional context (per-account connection counts); tolerate
		// its absence rather than failing the whole correlation.
		topBody := section(ctx, d, "/api/v1/mysql/top", nil)

		out := buildDBWebPressure(cpuBody, topBody, webBody, topN)
		b, err := marshal(out)
		if err != nil {
			return nil, nil, err
		}
		return textResult(b), nil, nil
	})
}

// mysqlCPUBody / mysqlTopBody / webShortBody mirror just the fields we consume
// from the three endpoints (shapes shared with mergeMySQLPressure / the webdet
// topShortResponse). Kept local so this tool's parsing is self-contained.
type mysqlCPUBody struct {
	PerfSchemaOK  bool `json:"perf_schema_ok"`
	PerfCPUActive bool `json:"perf_cpu_active"`
	UserstatOK    bool `json:"userstat_ok"`
	UserstatOff   bool `json:"userstat_off"`
	Users         []struct {
		User       string  `json:"user"`
		CPUSec     float64 `json:"cpu_sec"`
		BusySec    float64 `json:"busy_sec"`
		QueryCount int64   `json:"query_count"`
	} `json:"users"`
}

type mysqlTopBody struct {
	// UserStat has no json tags, so the top endpoint emits capitalized keys.
	PerUser []struct {
		User   string `json:"User"`
		Total  int    `json:"Total"`
		Active int    `json:"Active"`
	} `json:"per_user"`
}

type webShortBody struct {
	WindowSec float64 `json:"window_sec"`
	Rows      []struct {
		Host string  `json:"host"`
		RPS  float64 `json:"rps"`
	} `json:"rows"`
}

// buildDBWebPressure is the pure assembler: it maps the three endpoint bodies
// into dbwebcorr inputs, resolves vhost→owner via panelmap, runs the
// correlation, and wraps the result with metadata + caveats. Separated from the
// tool handler so it is unit-testable (panelmap reads files, so tests point its
// path vars at fixtures).
func buildDBWebPressure(cpuBody, topBody, webBody json.RawMessage, topN int) map[string]any {
	var notes []string

	var cpu mysqlCPUBody
	if len(cpuBody) > 0 {
		if err := json.Unmarshal(cpuBody, &cpu); err != nil {
			// A 2xx body we can't decode (the handler already rejects the
			// {"error":…} stub) — surface it instead of a confidently-empty result.
			notes = append(notes, "mysql/cpu: unexpected response shape ("+err.Error()+")")
		}
	}
	var top mysqlTopBody
	_ = json.Unmarshal(topBody, &top) // optional context; tolerate a bad/absent body
	var web webShortBody
	_ = json.Unmarshal(webBody, &web)

	// DB side: CPU/busy/query per user is the pressure signal; fold in
	// connection counts from /top by user. Drop non-tenant system users
	// (governor's authoritative exempt set + dotted internals) up front.
	connByUser := make(map[string][2]int, len(top.PerUser)) // user -> [total, active]
	for _, u := range top.PerUser {
		connByUser[u.User] = [2]int{u.Total, u.Active}
	}
	dbUsers := make([]dbwebcorr.DBUser, 0, len(cpu.Users))
	seen := make(map[string]bool, len(cpu.Users))
	for _, u := range cpu.Users {
		if isNonTenantDBUser(u.User) {
			continue
		}
		row := dbwebcorr.DBUser{
			User: u.User, CPUSec: u.CPUSec, BusySec: u.BusySec, QueryCount: u.QueryCount,
		}
		if c, ok := connByUser[u.User]; ok {
			row.Conns, row.Active = c[0], c[1]
		}
		dbUsers = append(dbUsers, row)
		seen[u.User] = true
	}
	// Users with live connections but no CPU delta this window still belong to
	// their account (context); include them with zero pressure.
	for _, u := range top.PerUser {
		if !seen[u.User] && !isNonTenantDBUser(u.User) {
			dbUsers = append(dbUsers, dbwebcorr.DBUser{User: u.User, Conns: u.Total, Active: u.Active})
		}
	}

	// Web side: vhosts + host→owner map (cPanel).
	vhosts := make([]dbwebcorr.Vhost, 0, len(web.Rows))
	hosts := make([]string, 0, len(web.Rows))
	for _, r := range web.Rows {
		if r.Host == "" {
			continue
		}
		vhosts = append(vhosts, dbwebcorr.Vhost{Host: r.Host, RPS: r.RPS})
		hosts = append(hosts, r.Host)
	}
	hostOwner := panelmap.HostOwners(hosts)

	windowSec := int(web.WindowSec + 0.5)
	if windowSec <= 0 {
		windowSec = 60
	}

	accounts := dbwebcorr.Correlate(dbUsers, vhosts, hostOwner, dbwebcorr.Params{
		WindowSec: windowSec,
		TopN:      topN,
	})

	flagged := 0
	for _, a := range accounts {
		if a.FewHitsHighPressure {
			flagged++
		}
	}

	if len(hosts) > 0 && len(hostOwner) == 0 {
		notes = append(notes, "host→owner attribution empty (non-cPanel host, or /etc/userdomains absent): web hits could not be attributed to accounts, so few_hits_high_pressure flags are unreliable here.")
	}
	// No real CPU signal → pressure is 0 for everyone and nothing can flag.
	// Without this note an empty `flagged` looks like "all clear" when it's
	// really "can't measure" (mysql_pressure falls back to query volume; the
	// correlation deliberately ranks on CPU/busy seconds, so it can't).
	if len(dbUsers) > 0 && !cpu.PerfCPUActive && !cpu.UserstatOK {
		notes = append(notes, "no real CPU signal (perf_schema CPU instruments off AND MariaDB userstat off): cpu_sec/busy_sec read 0, so pressure can't be measured and nothing will be flagged — enable performance_schema statement instruments or `SET GLOBAL userstat=ON`.")
	}

	return map[string]any{
		"window_sec": windowSec,
		"perf": map[string]any{
			"perf_schema_ok": cpu.PerfSchemaOK, "perf_cpu_active": cpu.PerfCPUActive,
			"userstat_ok": cpu.UserstatOK, "userstat_off": cpu.UserstatOff,
		},
		"web_attribution": map[string]any{
			"vhosts_seen": len(hosts), "vhosts_mapped": len(hostOwner),
		},
		"accounts_returned": len(accounts),
		"flagged":           flagged,
		"notes":             notes,
		"accounts":          accounts,
	}
}
