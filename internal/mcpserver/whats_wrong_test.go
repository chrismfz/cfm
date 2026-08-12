package mcpserver

import (
	"encoding/json"
	"strings"
	"testing"
)

// sec builds a sections map from key→raw-JSON-body pairs.
func sec(kv ...string) map[string]json.RawMessage {
	m := map[string]json.RawMessage{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = json.RawMessage(kv[i+1])
	}
	return m
}

// findBy returns the first finding matching category+severity, or nil.
func findBy(fs []finding, category, severity string) *finding {
	for i := range fs {
		if fs[i].Category == category && fs[i].Severity == severity {
			return &fs[i]
		}
	}
	return nil
}

func countCat(fs []finding, category string) int {
	n := 0
	for _, f := range fs {
		if f.Category == category {
			n++
		}
	}
	return n
}

// A fully-healthy set yields no findings, status ok, and every source marked ok.
func TestWhatsWrong_AllHealthy(t *testing.T) {
	got := evaluateWhatsWrong(sec(
		"health", `{"host":{"load_avg_5":0.5,"cpu_threads":8,"mem_total_bytes":1000,"mem_available_bytes":800,"swap_total_bytes":1000,"swap_used_bytes":10},"disk":{"mounts":[{"mount":"/","used_pct":40,"inode_used_pct":10,"total_inodes":1000}]},"network":{"conntrack_usage_pct":5,"conntrack_max":100000},"runtime":{"frontend_working":"working","edge_status":"active"}}`,
		"services", `{"ok":true,"services":[{"unit":"cfm.service","load":"loaded","active":"active","sub":"running","enabled":"enabled","restarts":0}]}`,
		"mysql", `{"conn_pct":10,"total":10,"max":100,"mode":"monitor"}`,
		"mail_queue", `{"available":true,"report":{"frozen":3,"deferred":2,"total":10}}`,
		"mail_traffic", `{"available":true,"traffic":{"anomalies":[]}}`,
		"anomalies", `{"count":0,"anomalies":[]}`,
	))
	if got.Status != "ok" {
		t.Fatalf("status = %q, want ok; findings=%+v", got.Status, got.Findings)
	}
	if len(got.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(got.Findings), got.Findings)
	}
	for _, k := range []string{"health", "services", "mysql", "mail_queue", "mail_traffic", "anomalies"} {
		if got.Sources[k] != "ok" {
			t.Errorf("sources[%s] = %q, want ok", k, got.Sources[k])
		}
	}
}

// A section-error stub and an unavailable section are recorded in Sources, never
// silently treated as healthy, and never produce a finding.
func TestWhatsWrong_ErroredAndUnavailableSources(t *testing.T) {
	got := evaluateWhatsWrong(sec(
		"mysql", `{"error":"HTTP 404"}`,
		"mail_queue", `{"available":false,"note":"no queue detector enabled"}`,
		"mail_traffic", `{"available":false,"note":"collector not run yet"}`,
		"health", ``, // empty body → error: no response
	))
	if got.Sources["mysql"] != "error: HTTP 404" {
		t.Errorf("mysql source = %q", got.Sources["mysql"])
	}
	if got.Sources["mail_queue"] != "unavailable" {
		t.Errorf("mail_queue source = %q", got.Sources["mail_queue"])
	}
	if got.Sources["mail_traffic"] != "unavailable" {
		t.Errorf("mail_traffic source = %q", got.Sources["mail_traffic"])
	}
	if got.Sources["health"] != "error: no response" {
		t.Errorf("health source = %q", got.Sources["health"])
	}
	if len(got.Findings) != 0 {
		t.Fatalf("errored/unavailable sources must not yield findings, got %+v", got.Findings)
	}
	// No critical/warning ⇒ status ok even though signals were unreadable.
	if got.Status != "ok" {
		t.Errorf("status = %q, want ok", got.Status)
	}
}

// A section absent from the map is simply skipped (no panic, no source entry).
func TestWhatsWrong_MissingSectionSkipped(t *testing.T) {
	got := evaluateWhatsWrong(sec(
		"mysql", `{"conn_pct":10,"total":10,"max":100}`,
	))
	if _, ok := got.Sources["health"]; ok {
		t.Errorf("absent section should not appear in sources")
	}
	if got.Sources["mysql"] != "ok" {
		t.Errorf("mysql source = %q", got.Sources["mysql"])
	}
}

func TestWhatsWrong_Disk(t *testing.T) {
	got := evaluateWhatsWrong(sec("health",
		`{"disk":{"mounts":[
			{"mount":"/","used_pct":96,"inode_used_pct":10,"total_inodes":1000},
			{"mount":"/boot","used_pct":91,"inode_used_pct":10,"total_inodes":1000},
			{"mount":"/var","used_pct":50,"inode_used_pct":97,"total_inodes":1000},
			{"mount":"/tmp","used_pct":50,"inode_used_pct":99,"total_inodes":0}
		]}}`))
	// / → critical (used), /boot → warning (used), /var → critical (inode).
	// /tmp inode 99% but total_inodes=0 ⇒ inode unknown, no inode finding.
	if countCat(got.Findings, "disk") != 3 {
		t.Fatalf("expected 3 disk findings, got %d: %+v", countCat(got.Findings, "disk"), got.Findings)
	}
	if f := findBy(got.Findings, "disk", sevCritical); f == nil || !strings.Contains(f.Detail, "/") {
		t.Errorf("missing critical disk finding: %+v", got.Findings)
	}
}

func TestWhatsWrong_Load(t *testing.T) {
	// 40 / 8 = 5.0 ⇒ warning; skip-on-zero-threads verified separately.
	warn := evalHealth(json.RawMessage(`{"host":{"load_avg_5":40,"cpu_threads":8}}`))
	if f := findBy(warn, "load", sevWarning); f == nil {
		t.Fatalf("expected load warning, got %+v", warn)
	}
	crit := evalHealth(json.RawMessage(`{"host":{"load_avg_5":80,"cpu_threads":8}}`))
	if f := findBy(crit, "load", sevCritical); f == nil {
		t.Fatalf("expected load critical, got %+v", crit)
	}
	// cpu_threads = 0 ⇒ ratio undefined ⇒ no load finding (no divide-by-zero FP).
	none := evalHealth(json.RawMessage(`{"host":{"load_avg_5":999,"cpu_threads":0}}`))
	if f := findBy(none, "load", sevWarning); f != nil {
		t.Fatalf("load must be skipped when cpu_threads=0, got %+v", none)
	}
	if f := findBy(none, "load", sevCritical); f != nil {
		t.Fatalf("load must be skipped when cpu_threads=0, got %+v", none)
	}
}

func TestWhatsWrong_MemoryAndSwap(t *testing.T) {
	// 30/1000 = 3% available ⇒ warning. Swap 600/1000 = 60% ⇒ warning.
	got := evalHealth(json.RawMessage(`{"host":{"mem_total_bytes":1000,"mem_available_bytes":30,"swap_total_bytes":1000,"swap_used_bytes":600}}`))
	if countCat(got, "memory") != 2 {
		t.Fatalf("expected 2 memory findings (low mem + swap), got %d: %+v", countCat(got, "memory"), got)
	}
	// mem_available_bytes = 0 (unknown) ⇒ no low-memory FP.
	noMem := evalHealth(json.RawMessage(`{"host":{"mem_total_bytes":1000,"mem_available_bytes":0}}`))
	if countCat(noMem, "memory") != 0 {
		t.Fatalf("unknown mem_available must not flag, got %+v", noMem)
	}
}

func TestWhatsWrong_Conntrack(t *testing.T) {
	got := evalHealth(json.RawMessage(`{"network":{"conntrack_usage_pct":99,"conntrack_max":100000}}`))
	if f := findBy(got, "network", sevCritical); f == nil {
		t.Fatalf("expected conntrack critical, got %+v", got)
	}
	// max = 0 ⇒ unknown ⇒ skip.
	none := evalHealth(json.RawMessage(`{"network":{"conntrack_usage_pct":99,"conntrack_max":0}}`))
	if countCat(none, "network") != 0 {
		t.Fatalf("conntrack with max=0 must not flag, got %+v", none)
	}
}

func TestWhatsWrong_EdgeFrontend(t *testing.T) {
	down := evalHealth(json.RawMessage(`{"runtime":{"frontend_working":"down","frontend_reason":"no upstream","edge_status":"inactive","edge_reason_code":"unit_dead"}}`))
	if f := findBy(down, "edge", sevCritical); f == nil {
		t.Fatalf("expected edge critical, got %+v", down)
	}
	if n := countCat(down, "edge"); n != 2 { // frontend down + edge inactive
		t.Fatalf("expected 2 edge findings, got %d: %+v", n, down)
	}
	deg := evalHealth(json.RawMessage(`{"runtime":{"frontend_working":"degraded","edge_status":"degraded"}}`))
	if countCat(deg, "edge") != 2 {
		t.Fatalf("expected 2 edge warnings, got %+v", deg)
	}
	for _, f := range deg {
		if f.Severity != sevWarning {
			t.Errorf("degraded edge should be warning, got %+v", f)
		}
	}
	// Unknown/blank enums ⇒ no finding.
	ok := evalHealth(json.RawMessage(`{"runtime":{"frontend_working":"working","edge_status":"unknown"}}`))
	if countCat(ok, "edge") != 0 {
		t.Fatalf("working/unknown must not flag, got %+v", ok)
	}
}

func TestWhatsWrong_Services(t *testing.T) {
	got := evalServices(json.RawMessage(`{"services":[
		{"unit":"a.service","load":"loaded","active":"failed","sub":"failed","enabled":"enabled","restarts":0},
		{"unit":"b.service","load":"loaded","active":"inactive","sub":"dead","enabled":"enabled","restarts":0},
		{"unit":"c.service","load":"loaded","active":"inactive","sub":"dead","enabled":"disabled","restarts":0},
		{"unit":"d.service","load":"loaded","active":"active","sub":"running","enabled":"enabled","restarts":7},
		{"unit":"e.service","load":"not-found","active":"inactive","sub":"dead","enabled":"","restarts":0},
		{"unit":"f.service","load":"masked","active":"inactive","sub":"dead","enabled":"masked","restarts":0}
	]}`), "")
	// a → critical (failed); b → critical (enabled-but-inactive); c → none (disabled+inactive is fine);
	// d → warning (flapping); e,f → skipped (not-found/masked).
	if n := countCat(got, "service"); n != 3 {
		t.Fatalf("expected 3 service findings, got %d: %+v", n, got)
	}
	if f := findBy(got, "service", sevWarning); f == nil || f.Args["units"] != "d.service" {
		t.Errorf("expected flapping warning for d.service with args, got %+v", got)
	}
	crit := 0
	for _, f := range got {
		if f.Category == "service" && f.Severity == sevCritical {
			crit++
		}
	}
	if crit != 2 {
		t.Errorf("expected 2 critical service findings (a,b), got %d: %+v", crit, got)
	}
}

func TestWhatsWrong_EdgeEngineAlternate(t *testing.T) {
	// A node runs Angie; openresty is installed-but-disabled and reports failed.
	body := json.RawMessage(`{"services":[
		{"unit":"angie.service","load":"loaded","active":"active","sub":"running","enabled":"enabled","restarts":0},
		{"unit":"openresty.service","load":"loaded","active":"failed","sub":"failed","enabled":"disabled","restarts":0},
		{"unit":"memcached.service","load":"loaded","active":"failed","sub":"failed","enabled":"enabled","restarts":0}
	]}`)

	// Active edge = angie: the idle openresty must NOT be flagged; the unrelated
	// failed memcached still is (exactly 1 finding).
	got := evalServices(body, "angie")
	for _, f := range got {
		if f.Args != nil && f.Args["units"] == "openresty.service" {
			t.Fatalf("idle alternate openresty must be suppressed when angie is the edge, got %+v", got)
		}
	}
	if n := countCat(got, "service"); n != 1 {
		t.Fatalf("expected exactly 1 service finding (memcached), got %d: %+v", n, got)
	}
	if f := findBy(got, "service", sevCritical); f == nil || f.Args["units"] != "memcached.service" {
		t.Fatalf("unrelated failed memcached must survive suppression, got %+v", got)
	}

	// Fail-safe: when the active edge is NOT a known engine, nothing is
	// suppressed. Cover the collector's unresolved sentinel ("unknown"), the
	// absent-health case (""), and an unexpected value ("mixed") to prove any
	// non-engine string fails safe. A failed openresty must be flagged in all —
	// never mask a real edge-down.
	for _, unresolved := range []string{"", "unknown", "mixed"} {
		sawOR := false
		for _, f := range evalServices(body, unresolved) {
			if f.Args != nil && f.Args["units"] == "openresty.service" {
				sawOR = true
			}
		}
		if !sawOR {
			t.Fatalf("edge_service=%q (unresolved): a failed openresty must still be flagged (fail-safe)", unresolved)
		}
	}

	// The ACTIVE edge failing is never suppressed.
	af := evalServices(json.RawMessage(`{"services":[
		{"unit":"angie.service","load":"loaded","active":"failed","sub":"failed","enabled":"enabled","restarts":0}
	]}`), "angie")
	if f := findBy(af, "service", sevCritical); f == nil || f.Args["units"] != "angie.service" {
		t.Fatalf("active edge angie failing must be flagged critical, got %+v", af)
	}
}

// Drives the FULL evaluateWhatsWrong path: the runtime.edge_service extraction
// (JSON tag + ToLower/TrimSpace) must feed evalServices so the idle alternate
// is suppressed end-to-end. Uses mixed-case " Angie " to pin the normalization.
func TestWhatsWrong_EdgeServiceExtraction(t *testing.T) {
	sections := map[string]json.RawMessage{
		"health": json.RawMessage(`{"runtime":{"edge_service":" Angie ","frontend_working":"working","edge_status":"active"}}`),
		"services": json.RawMessage(`{"services":[
			{"unit":"angie.service","load":"loaded","active":"active","sub":"running","enabled":"enabled","restarts":0},
			{"unit":"openresty.service","load":"loaded","active":"failed","sub":"failed","enabled":"disabled","restarts":0}
		]}`),
	}
	res := evaluateWhatsWrong(sections)
	for _, f := range res.Findings {
		if f.Args != nil && f.Args["units"] == "openresty.service" {
			t.Fatalf("end-to-end: idle openresty must be suppressed via extracted edge_service, got %+v", res.Findings)
		}
	}
	if res.Counts[sevCritical] != 0 {
		t.Fatalf("end-to-end: expected no criticals (angie active, openresty suppressed), got %d: %+v", res.Counts[sevCritical], res.Findings)
	}

	// And the negative: unresolved edge_service ("unknown") must NOT suppress —
	// the failed openresty surfaces as critical end-to-end.
	sections["health"] = json.RawMessage(`{"runtime":{"edge_service":"unknown"}}`)
	res2 := evaluateWhatsWrong(sections)
	sawOR := false
	for _, f := range res2.Findings {
		if f.Args != nil && f.Args["units"] == "openresty.service" {
			sawOR = true
		}
	}
	if !sawOR {
		t.Fatalf("end-to-end: edge_service=unknown must not suppress a failed openresty, got %+v", res2.Findings)
	}
}

func TestWhatsWrong_MySQL(t *testing.T) {
	crit := evalMySQL(json.RawMessage(`{"conn_pct":97,"total":97,"max":100}`))
	if f := findBy(crit, "mysql", sevCritical); f == nil {
		t.Fatalf("expected mysql critical, got %+v", crit)
	}
	warn := evalMySQL(json.RawMessage(`{"conn_pct":88,"total":88,"max":100}`))
	if f := findBy(warn, "mysql", sevWarning); f == nil {
		t.Fatalf("expected mysql warning, got %+v", warn)
	}
	// max=0 ⇒ skip (no divide-by-zero / bogus pct).
	none := evalMySQL(json.RawMessage(`{"conn_pct":99,"total":0,"max":0}`))
	if len(none) != 0 {
		t.Fatalf("mysql with max=0 must not flag, got %+v", none)
	}
}

func TestWhatsWrong_MailQueue(t *testing.T) {
	src := map[string]string{}
	warn := evalMailQueue(json.RawMessage(`{"available":true,"report":{"frozen":150,"deferred":5,"total":200}}`), src)
	if f := findBy(warn, "mail_queue", sevWarning); f == nil {
		t.Fatalf("expected mail_queue warning, got %+v", warn)
	}
	crit := evalMailQueue(json.RawMessage(`{"available":true,"report":{"frozen":1500,"deferred":5,"total":2000}}`), src)
	if f := findBy(crit, "mail_queue", sevCritical); f == nil {
		t.Fatalf("expected mail_queue critical, got %+v", crit)
	}
	// Below threshold (e.g. the 24-frozen backscatter seen live) ⇒ no finding.
	none := evalMailQueue(json.RawMessage(`{"available":true,"report":{"frozen":24,"deferred":5,"total":50}}`), src)
	if len(none) != 0 {
		t.Fatalf("frozen below threshold must not flag, got %+v", none)
	}
}

func TestWhatsWrong_MailTrafficAnomalies(t *testing.T) {
	src := map[string]string{}
	body := `{"available":true,"traffic":{"anomalies":[
		{"addr":"a@x","recent":500,"baseline_per_hour":0,"ratio":0,"kind":"new-sender"},
		{"addr":"b@x","recent":300,"baseline_per_hour":2.5,"ratio":10,"kind":"spike"},
		{"addr":"c@x","recent":1,"ratio":3,"kind":"spike"},
		{"addr":"d@x","recent":1,"ratio":3,"kind":"spike"},
		{"addr":"e@x","recent":1,"ratio":3,"kind":"spike"},
		{"addr":"f@x","recent":1,"ratio":3,"kind":"spike"},
		{"addr":"g@x","recent":1,"ratio":3,"kind":"spike"}
	]}}`
	got := evalMailTraffic(json.RawMessage(body), src)
	// 5 capped individual findings + 1 "more" indicator (7 anomalies, cap 5).
	if len(got) != wwMailAnomalyCap+1 {
		t.Fatalf("expected %d findings (cap + indicator), got %d: %+v", wwMailAnomalyCap+1, len(got), got)
	}
	for _, f := range got {
		if f.Severity != sevWarning || f.Category != "mail" {
			t.Errorf("mail anomaly should be warning/mail, got %+v", f)
		}
	}
	if !strings.Contains(got[0].Detail, "no prior baseline") {
		t.Errorf("new-sender detail wrong: %q", got[0].Detail)
	}
	last := got[len(got)-1]
	if !strings.Contains(last.Title, "more outbound-mail") || !strings.Contains(last.Detail, "2 more") {
		t.Errorf("expected a '2 more' indicator finding, got %+v", last)
	}
	// At/under the cap: no indicator finding.
	small := evalMailTraffic(json.RawMessage(`{"available":true,"traffic":{"anomalies":[{"addr":"a@x","recent":9,"ratio":5,"kind":"spike"}]}}`), src)
	if len(small) != 1 {
		t.Fatalf("expected exactly 1 finding under the cap, got %+v", small)
	}
}

func TestWhatsWrong_APIAnomaliesSeverity(t *testing.T) {
	// count < threshold ⇒ info.
	info := evalAnomalies(json.RawMessage(`{"count":3,"anomalies":[{"reason":"api_fuzz","signal":"path_entropy_or_fuzz","count":3}]}`))
	if f := findBy(info, "abuse", sevInfo); f == nil {
		t.Fatalf("expected abuse info, got %+v", info)
	}
	// count >= threshold ⇒ warning; and status becomes issues.
	warn := evalAnomalies(json.RawMessage(`{"count":25,"anomalies":[{"reason":"api_unauthorized_burst","signal":"unauthorized_burst","count":25}]}`))
	if f := findBy(warn, "abuse", sevWarning); f == nil {
		t.Fatalf("expected abuse warning, got %+v", warn)
	}
	if !strings.Contains(warn[0].Detail, "unauthorized_burst") {
		t.Errorf("expected top signal in detail, got %q", warn[0].Detail)
	}
	// count 0 ⇒ nothing.
	if n := evalAnomalies(json.RawMessage(`{"count":0,"anomalies":[]}`)); len(n) != 0 {
		t.Fatalf("count=0 must not flag, got %+v", n)
	}
}

// Boundary pins: a value just BELOW each threshold must NOT flag, and the exact
// threshold must. These fail if a threshold is loosened (lowered), which is the
// over-flag regression the whole tool is built to avoid.
func TestWhatsWrong_ThresholdBoundaries(t *testing.T) {
	// Disk: 89.999% clear, 90.0% warns.
	if fs := evalHealth(json.RawMessage(`{"disk":{"mounts":[{"mount":"/","used_pct":89.999}]}}`)); countCat(fs, "disk") != 0 {
		t.Errorf("disk 89.999%% should not flag, got %+v", fs)
	}
	if fs := evalHealth(json.RawMessage(`{"disk":{"mounts":[{"mount":"/","used_pct":90.0}]}}`)); findBy(fs, "disk", sevWarning) == nil {
		t.Errorf("disk 90.0%% should warn, got %+v", fs)
	}
	// Load: ratio 3.99 clear, 4.0 warns (cpu_threads=10 ⇒ load 39.9 vs 40).
	if fs := evalHealth(json.RawMessage(`{"host":{"load_avg_5":39.9,"cpu_threads":10}}`)); countCat(fs, "load") != 0 {
		t.Errorf("load ratio 3.99 should not flag, got %+v", fs)
	}
	if fs := evalHealth(json.RawMessage(`{"host":{"load_avg_5":40.0,"cpu_threads":10}}`)); findBy(fs, "load", sevWarning) == nil {
		t.Errorf("load ratio 4.0 should warn, got %+v", fs)
	}
	// MySQL: 84.99% clear, 85.0% warns.
	if fs := evalMySQL(json.RawMessage(`{"conn_pct":84.99,"total":85,"max":100}`)); len(fs) != 0 {
		t.Errorf("mysql 84.99%% should not flag, got %+v", fs)
	}
	if fs := evalMySQL(json.RawMessage(`{"conn_pct":85.0,"total":85,"max":100}`)); findBy(fs, "mysql", sevWarning) == nil {
		t.Errorf("mysql 85.0%% should warn, got %+v", fs)
	}
	// Mail queue: 99 frozen clear, 100 warns.
	src := map[string]string{}
	if fs := evalMailQueue(json.RawMessage(`{"available":true,"report":{"frozen":99}}`), src); len(fs) != 0 {
		t.Errorf("99 frozen should not flag, got %+v", fs)
	}
	if fs := evalMailQueue(json.RawMessage(`{"available":true,"report":{"frozen":100}}`), src); findBy(fs, "mail_queue", sevWarning) == nil {
		t.Errorf("100 frozen should warn, got %+v", fs)
	}
}

// Read-only image filesystems (squashfs/iso9660/erofs) sit at 100% by design and
// must never be flagged — the classic snap/ISO false positive.
func TestWhatsWrong_ReadOnlyFSNotFlagged(t *testing.T) {
	fs := evalHealth(json.RawMessage(`{"disk":{"mounts":[
		{"mount":"/snap/core/1","fs_type":"squashfs","used_pct":100},
		{"mount":"/mnt/iso","fs_type":"iso9660","used_pct":100},
		{"mount":"/mnt/img","fs_type":"erofs","used_pct":100},
		{"mount":"/","fs_type":"ext4","used_pct":40}
	]}}`))
	if countCat(fs, "disk") != 0 {
		t.Fatalf("read-only image FS at 100%% must not flag (and ext4 at 40%% is fine), got %+v", fs)
	}
	// But a real writable FS at 100% still flags.
	full := evalHealth(json.RawMessage(`{"disk":{"mounts":[{"mount":"/","fs_type":"ext4","used_pct":100}]}}`))
	if findBy(full, "disk", sevCritical) == nil {
		t.Fatalf("writable ext4 at 100%% must flag critical, got %+v", full)
	}
}

// Swap occupancy alone (plenty of free RAM) is NOT flagged — only swap heavy-use
// combined with genuinely tight RAM counts as memory pressure.
func TestWhatsWrong_SwapNeedsMemoryPressure(t *testing.T) {
	// 60% swap used but 40% RAM available ⇒ healthy, no finding.
	healthy := evalHealth(json.RawMessage(`{"host":{"mem_total_bytes":1000,"mem_available_bytes":400,"swap_total_bytes":1000,"swap_used_bytes":600}}`))
	if countCat(healthy, "memory") != 0 {
		t.Fatalf("swap occupancy with ample free RAM must not flag, got %+v", healthy)
	}
	// 60% swap AND only 8% RAM available ⇒ real pressure, warn.
	pressured := evalHealth(json.RawMessage(`{"host":{"mem_total_bytes":1000,"mem_available_bytes":80,"swap_total_bytes":1000,"swap_used_bytes":600}}`))
	if findBy(pressured, "memory", sevWarning) == nil {
		t.Fatalf("swap heavy-use with tight RAM must warn, got %+v", pressured)
	}
	// Swap heavy but mem_available unknown (0) ⇒ can't confirm pressure ⇒ no flag.
	unknown := evalHealth(json.RawMessage(`{"host":{"mem_total_bytes":1000,"mem_available_bytes":0,"swap_total_bytes":1000,"swap_used_bytes":900}}`))
	if countCat(unknown, "memory") != 0 {
		t.Fatalf("swap with unknown mem_available must not flag, got %+v", unknown)
	}
}

// A cleanly-completed enabled oneshot (inactive + sub=exited) is not a fault.
func TestWhatsWrong_OneshotNotFlagged(t *testing.T) {
	fs := evalServices(json.RawMessage(`{"services":[
		{"unit":"once.service","load":"loaded","active":"inactive","sub":"exited","enabled":"enabled","restarts":0}
	]}`), "")
	if countCat(fs, "service") != 0 {
		t.Fatalf("clean oneshot (inactive+exited) must not flag, got %+v", fs)
	}
	// But inactive+dead+enabled (a crashed long-running unit) still flags.
	dead := evalServices(json.RawMessage(`{"services":[
		{"unit":"daemon.service","load":"loaded","active":"inactive","sub":"dead","enabled":"enabled","restarts":0}
	]}`), "")
	if findBy(dead, "service", sevCritical) == nil {
		t.Fatalf("enabled inactive+dead unit must flag, got %+v", dead)
	}
}

// Exactly at the cap ⇒ no "+N more" indicator (pins the `extra > 0` boundary).
func TestWhatsWrong_MailAnomalyExactlyAtCap(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"available":true,"traffic":{"anomalies":[`)
	for i := 0; i < wwMailAnomalyCap; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"addr":"s@x","recent":9,"ratio":5,"kind":"spike"}`)
	}
	b.WriteString(`]}}`)
	got := evalMailTraffic(json.RawMessage(b.String()), map[string]string{})
	if len(got) != wwMailAnomalyCap {
		t.Fatalf("exactly cap should yield %d findings, got %d", wwMailAnomalyCap, len(got))
	}
	for _, f := range got {
		if strings.Contains(f.Title, "more outbound-mail") {
			t.Fatalf("no indicator expected at exactly the cap, got %+v", f)
		}
	}
}

// count>0 with an empty anomalies array ⇒ clean detail, no dangling "; top:".
func TestWhatsWrong_APIAnomaliesEmptyArray(t *testing.T) {
	got := evalAnomalies(json.RawMessage(`{"count":3,"anomalies":[]}`))
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %+v", got)
	}
	if strings.Contains(got[0].Detail, "top:") || strings.HasSuffix(got[0].Detail, "; ") {
		t.Fatalf("detail should have no dangling top-signals label: %q", got[0].Detail)
	}
	if topSignals(map[string]int{}) != "" {
		t.Fatalf("topSignals of empty map must be empty string")
	}
}

// An unmapped category sorts LAST within its severity tier, not first.
func TestWhatsWrong_UnmappedCategorySortsLast(t *testing.T) {
	fs := []finding{
		{Severity: sevWarning, Category: "zzz-unmapped", Title: "x"},
		{Severity: sevWarning, Category: "edge", Title: "y"},
	}
	sortFindings(fs)
	if fs[0].Category != "edge" || fs[1].Category != "zzz-unmapped" {
		t.Fatalf("unmapped category must sort last, got %+v", fs)
	}
}

// Info-only findings keep status "ok" (info is not an "issue"); ranking puts
// critical before warning before info, and category orders within a tier.
func TestWhatsWrong_RankingAndStatus(t *testing.T) {
	got := evaluateWhatsWrong(sec(
		"health", `{"disk":{"mounts":[{"mount":"/","used_pct":96}]},"runtime":{"frontend_working":"degraded"}}`,
		"anomalies", `{"count":2,"anomalies":[{"signal":"api_probe","count":2}]}`,
	))
	// disk critical, edge warning, abuse info.
	if got.Status != "issues" {
		t.Fatalf("status = %q, want issues", got.Status)
	}
	if len(got.Findings) < 3 {
		t.Fatalf("expected >=3 findings, got %+v", got.Findings)
	}
	if got.Findings[0].Severity != sevCritical {
		t.Errorf("first finding should be critical, got %+v", got.Findings[0])
	}
	if last := got.Findings[len(got.Findings)-1]; last.Severity != sevInfo {
		t.Errorf("last finding should be info, got %+v", last)
	}
	// Verify strict non-decreasing severity rank across the list.
	for i := 1; i < len(got.Findings); i++ {
		if sevRank(got.Findings[i-1].Severity) > sevRank(got.Findings[i].Severity) {
			t.Fatalf("findings not severity-ordered at %d: %+v", i, got.Findings)
		}
	}
}

// An info-only result (no critical/warning) reports status ok but still lists it.
func TestWhatsWrong_InfoOnlyIsOk(t *testing.T) {
	got := evaluateWhatsWrong(sec(
		"anomalies", `{"count":2,"anomalies":[{"signal":"api_probe","count":2}]}`,
	))
	if got.Status != "ok" {
		t.Fatalf("info-only status = %q, want ok", got.Status)
	}
	if got.Counts[sevInfo] != 1 || len(got.Findings) != 1 {
		t.Fatalf("expected exactly one info finding, got %+v", got)
	}
}
