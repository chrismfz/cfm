package dbwebcorr

import "testing"

func TestAccountOf(t *testing.T) {
	cases := map[string]string{
		"chris_wp":   "chris",
		"chris_shop": "chris",
		"chris":      "chris",
		"root":       "root",
		"  bob_db ":  "bob",
		"_leading":   "_leading", // no account prefix (i==0) → returned as-is
		"":           "",
	}
	for in, want := range cases {
		if got := AccountOf(in); got != want {
			t.Errorf("AccountOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func findAcct(rows []Account, name string) *Account {
	for i := range rows {
		if rows[i].Account == name {
			return &rows[i]
		}
	}
	return nil
}

func TestCorrelate_FlagsFewHitsHighPressure(t *testing.T) {
	db := []DBUser{
		// chris: heavy DB, will have almost no web traffic → should flag.
		{User: "chris_wp", CPUSec: 3.0, QueryCount: 5000, Conns: 4, Active: 2},
		{User: "chris_shop", CPUSec: 1.5, QueryCount: 1000, Conns: 2, Active: 1},
		// busy: heavy DB but also heavy web traffic → NOT few-hits.
		{User: "busy_main", CPUSec: 4.0, QueryCount: 8000, Conns: 10, Active: 6},
		// idle: below the pressure floor → never flagged.
		{User: "idle_db", CPUSec: 0.001, QueryCount: 3, Conns: 1},
	}
	web := []Vhost{
		{Host: "chris.com", RPS: 0.01},  // ~0.6 hits/min → few
		{Host: "busy.com", RPS: 20.0},   // ~1200 hits/min → lots
		{Host: "idle.com", RPS: 0.0},    //
		{Host: "orphan.com", RPS: 99.0}, // no owner mapping → skipped
	}
	hostOwner := map[string]string{
		"chris.com": "chris",
		"busy.com":  "busy",
		"idle.com":  "idle",
		// orphan.com deliberately absent
	}

	rows := Correlate(db, web, hostOwner, Params{WindowSec: 60})

	chris := findAcct(rows, "chris")
	if chris == nil {
		t.Fatal("chris account missing")
	}
	if !chris.FewHitsHighPressure {
		t.Errorf("chris should be flagged few-hits/high-pressure: %+v", chris)
	}
	if chris.Pressure != 4.5 { // 3.0 + 1.5 summed across db users
		t.Errorf("chris.Pressure = %v, want 4.5", chris.Pressure)
	}
	if len(chris.DBUsers) != 2 || chris.DBUsers[0] != "chris_shop" || chris.DBUsers[1] != "chris_wp" {
		t.Errorf("chris.DBUsers = %v, want sorted [chris_shop chris_wp]", chris.DBUsers)
	}
	if len(chris.Vhosts) != 1 || chris.Vhosts[0] != "chris.com" {
		t.Errorf("chris.Vhosts = %v", chris.Vhosts)
	}

	busy := findAcct(rows, "busy")
	if busy == nil {
		t.Fatal("busy account missing")
	}
	if busy.FewHitsHighPressure {
		t.Errorf("busy should NOT be flagged (high traffic): hits=%v", busy.WebHits)
	}

	idle := findAcct(rows, "idle")
	if idle == nil {
		t.Fatal("idle account missing")
	}
	if idle.FewHitsHighPressure {
		t.Errorf("idle should NOT be flagged (below pressure floor): pressure=%v", idle.Pressure)
	}

	// The orphan vhost must not have created an account.
	if a := findAcct(rows, "orphan"); a != nil {
		t.Errorf("orphan vhost should be skipped (no owner), got %+v", a)
	}

	// Flagged account sorts ahead of unflagged ones.
	if rows[0].Account != "chris" {
		t.Errorf("expected chris first (flagged), got %q", rows[0].Account)
	}
}

func TestCorrelate_CaseInsensitiveJoin(t *testing.T) {
	// Mixed-case MySQL user vs lowercase userdomains owner must join to ONE
	// account (regression: previously split into "Chris" + "chris", falsely
	// flagging the DB half). Real traffic on the mapped host must count.
	db := []DBUser{{User: "Chris_wp", CPUSec: 3.0, QueryCount: 1000}}
	web := []Vhost{{Host: "chris.com", RPS: 20.0}} // ~1200 hits/min → not few-hits
	hostOwner := map[string]string{"chris.com": "chris"}

	rows := Correlate(db, web, hostOwner, Params{WindowSec: 60})
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 joined account, got %d: %+v", len(rows), rows)
	}
	a := rows[0]
	if a.Account != "chris" {
		t.Errorf("account key not normalized: %q", a.Account)
	}
	if a.Pressure != 3.0 || a.WebRPS != 20.0 {
		t.Errorf("DB pressure and web hits did not join: %+v", a)
	}
	if a.FewHitsHighPressure {
		t.Errorf("must NOT be flagged — it has heavy traffic once joined: %+v", a)
	}
}

func TestCorrelate_BusySecProxyWhenCPUZero(t *testing.T) {
	// CloudLinux MariaDB path: CPUSec 0, BusySec carries the signal.
	db := []DBUser{{User: "cl_db", CPUSec: 0, BusySec: 2.5, QueryCount: 400}}
	rows := Correlate(db, nil, nil, Params{WindowSec: 60})
	a := findAcct(rows, "cl")
	if a == nil {
		t.Fatal("cl account missing")
	}
	if a.Pressure != 2.5 {
		t.Errorf("Pressure should fall back to BusySec: got %v want 2.5", a.Pressure)
	}
	if !a.FewHitsHighPressure {
		t.Errorf("cl should flag: no web hits, pressure 2.5")
	}
}

func TestCorrelate_ExcludeAccounts(t *testing.T) {
	db := []DBUser{
		{User: "root", CPUSec: 5.0},
		{User: "eximstats", CPUSec: 3.0},
		{User: "real_db", CPUSec: 1.0},
	}
	rows := Correlate(db, nil, nil, Params{
		WindowSec:       60,
		ExcludeAccounts: []string{"root", "EximStats"}, // case-insensitive
	})
	if findAcct(rows, "root") != nil {
		t.Error("root should be excluded")
	}
	if findAcct(rows, "eximstats") != nil {
		t.Error("eximstats should be excluded (case-insensitive)")
	}
	if findAcct(rows, "real") == nil {
		t.Error("real account should remain")
	}
}

func TestCorrelate_TopNAndOrdering(t *testing.T) {
	db := []DBUser{
		{User: "a_db", CPUSec: 1.0},
		{User: "b_db", CPUSec: 3.0},
		{User: "c_db", CPUSec: 2.0},
	}
	rows := Correlate(db, nil, nil, Params{WindowSec: 60, TopN: 2})
	if len(rows) != 2 {
		t.Fatalf("TopN=2 should cap to 2 rows, got %d", len(rows))
	}
	// All flagged (no web hits), so order is by PressurePerHit desc == pressure desc.
	if rows[0].Account != "b" || rows[1].Account != "c" {
		t.Errorf("expected [b c] by pressure desc, got [%s %s]", rows[0].Account, rows[1].Account)
	}
}

func TestCorrelate_Empty(t *testing.T) {
	if rows := Correlate(nil, nil, nil, Params{}); len(rows) != 0 {
		t.Errorf("empty inputs → no rows, got %d", len(rows))
	}
}
