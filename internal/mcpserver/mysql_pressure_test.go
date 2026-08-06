package mcpserver

import (
	"encoding/json"
	"testing"
)

func TestMergeMySQLPressure(t *testing.T) {
	// top: UserStat has no json tags → capitalized keys.
	topBody := json.RawMessage(`{
		"ts":"2026-08-06T12:00:00Z","flavor":"10.11-MariaDB","mode":"monitor",
		"conn_pct":42.5,"total":85,"max":200,
		"per_user":[
			{"User":"acct_a","Total":40,"Active":30,"Sleeping":10,"Locked":0,"MaxSleepSec":5},
			{"User":"acct_b","Total":3,"Active":1,"Sleeping":2,"Locked":0,"MaxSleepSec":0}
		]
	}`)
	cpuBody := json.RawMessage(`{
		"perf_schema_ok":true,"perf_cpu_active":true,"userstat_ok":false,"userstat_off":false,
		"users":[
			{"user":"acct_b","cpu_sec":9.9,"query_count":5000,"avg_query_msec":2.0},
			{"user":"acct_c","cpu_sec":3.0,"query_count":100,"avg_query_msec":30.0}
		]
	}`)

	res := mergeMySQLPressure(topBody, cpuBody, 25)

	conn := res["conn"].(map[string]any)
	if conn["used"] != 85 || conn["max"] != 200 {
		t.Fatalf("conn summary wrong: %+v", conn)
	}
	perf := res["perf"].(map[string]any)
	if perf["perf_cpu_active"] != true {
		t.Fatalf("perf availability lost: %+v", perf)
	}

	rows := res["top_users"].([]mysqlUserRow)
	// acct_c appears only in CPU (no live conn row) → must be folded in.
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3 (incl CPU-only acct_c)", len(rows))
	}
	// ranked by active conns first → acct_a (30 active) leads.
	if rows[0].User != "acct_a" || rows[0].Active != 30 {
		t.Fatalf("expected acct_a first, got %+v", rows[0])
	}
	// acct_b merged its CPU delta onto its connection row.
	var b *mysqlUserRow
	for i := range rows {
		if rows[i].User == "acct_b" {
			b = &rows[i]
		}
	}
	if b == nil || b.Conns != 3 || b.CPUSec != 9.9 || b.QueryCount != 5000 {
		t.Fatalf("acct_b merge wrong: %+v", b)
	}
}

func TestMergeMySQLPressure_TopNTruncates(t *testing.T) {
	// 5 users, ask for top 2.
	topBody := json.RawMessage(`{"total":5,"max":100,"per_user":[
		{"User":"u1","Active":5},{"User":"u2","Active":4},{"User":"u3","Active":3},
		{"User":"u4","Active":2},{"User":"u5","Active":1}]}`)
	res := mergeMySQLPressure(topBody, json.RawMessage(`{}`), 2)
	rows := res["top_users"].([]mysqlUserRow)
	if len(rows) != 2 || res["users_truncated"] != true {
		t.Fatalf("truncation failed: rows=%d truncated=%v", len(rows), res["users_truncated"])
	}
	if rows[0].User != "u1" || rows[1].User != "u2" {
		t.Fatalf("wrong top-2 order: %+v", rows)
	}
	if res["users_total"] != 5 {
		t.Fatalf("users_total = %v, want 5", res["users_total"])
	}
}

func TestSectionError(t *testing.T) {
	if got := sectionError(json.RawMessage(`{"error":"HTTP 404"}`)); got != "HTTP 404" {
		t.Fatalf("sectionError = %q, want HTTP 404", got)
	}
	if got := sectionError(json.RawMessage(`{"total":5}`)); got != "" {
		t.Fatalf("sectionError on non-error = %q, want empty", got)
	}
}

func TestMySQLLogTailRouting(t *testing.T) {
	fd := &fakeDispatch{}
	ts := newTestServer(t, fd)
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mysql_log_tail","arguments":{"lines":300,"grep":"deadlock"}}}`)
	if fd.lastPath != "/api/v1/system/mysql-log" {
		t.Errorf("mysql_log_tail routed to %q", fd.lastPath)
	}
	if got := fd.lastQuery.Get("which"); got != "error" {
		t.Errorf("which = %q, want error", got)
	}
	if got := fd.lastQuery.Get("grep"); got != "deadlock" {
		t.Errorf("grep = %q, want deadlock", got)
	}
}

func TestMySQLSlowQueriesRouting(t *testing.T) {
	fd := &fakeDispatch{}
	ts := newTestServer(t, fd)
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mysql_slow_queries","arguments":{"lines":500}}}`)
	if fd.lastPath != "/api/v1/system/mysql-log" {
		t.Errorf("mysql_slow_queries routed to %q", fd.lastPath)
	}
	if got := fd.lastQuery.Get("which"); got != "slow" {
		t.Errorf("which = %q, want slow", got)
	}
}

func TestMySQLPressureRouting(t *testing.T) {
	fd := &fakeDispatch{}
	ts := newTestServer(t, fd)
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mysql_pressure","arguments":{"top":10}}}`)
	// composed tool hits two endpoints; fakeDispatch records the last.
	if fd.lastPath != "/api/v1/mysql/cpu" && fd.lastPath != "/api/v1/mysql/top" {
		t.Errorf("mysql_pressure routed to %q, want a /api/v1/mysql/* endpoint", fd.lastPath)
	}
}
