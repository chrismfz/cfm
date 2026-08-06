package svcstat

import "testing"

func TestParseShowBlocks(t *testing.T) {
	raw := `Id=cfm.service
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
Description=CFM daemon
MainPID=1234
MemoryCurrent=52428800
NRestarts=2
ActiveEnterTimestamp=Tue 2026-08-06 10:20:30 UTC
ActiveEnterTimestampMonotonic=5000000

Id=mariadb.service
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
Description=MariaDB
MainPID=999
MemoryCurrent=18446744073709551615
NRestarts=0
ActiveEnterTimestamp=Tue 2026-08-06 09:00:00 UTC
ActiveEnterTimestampMonotonic=1000000

Id=ghost.service
LoadState=not-found
ActiveState=inactive
SubState=dead
UnitFileState=
Description=ghost.service
MainPID=0
MemoryCurrent=[not set]
NRestarts=0
ActiveEnterTimestamp=
ActiveEnterTimestampMonotonic=0`

	got := parseShowBlocks(raw)
	if len(got) != 3 {
		t.Fatalf("blocks = %d, want 3", len(got))
	}

	cfm := got[0]
	if cfm.Unit != "cfm.service" || cfm.Load != "loaded" || cfm.Active != "active" ||
		cfm.Sub != "running" || cfm.Enabled != "enabled" || cfm.MainPID != 1234 ||
		cfm.MemoryBytes != 52428800 || cfm.Restarts != 2 {
		t.Fatalf("cfm parsed wrong: %+v", cfm)
	}
	if cfm.ActiveSince != "Tue 2026-08-06 10:20:30 UTC" {
		t.Fatalf("cfm ActiveSince = %q", cfm.ActiveSince)
	}
	if cfm.monoUsec != 5000000 {
		t.Fatalf("cfm monoUsec = %d, want 5000000", cfm.monoUsec)
	}

	// MemoryCurrent sentinel (uint64 max) → not set → omitted (0).
	if got[1].MemoryBytes != 0 {
		t.Fatalf("mariadb MemoryBytes = %d, want 0 (sentinel elided)", got[1].MemoryBytes)
	}

	// not-found unit still parses (explicit-query callers keep it).
	if got[2].Load != "not-found" || got[2].Unit != "ghost.service" {
		t.Fatalf("ghost parsed wrong: %+v", got[2])
	}
	// "[not set]" literal → omitted.
	if got[2].MemoryBytes != 0 {
		t.Fatalf("ghost MemoryBytes = %d, want 0", got[2].MemoryBytes)
	}
}

// Several query names can alias the same unit (mysql/mysqld → mariadb.service),
// so systemctl show emits one block per name for the same Id. parseShowBlocks
// must keep the first and drop the repeats.
func TestParseShowBlocks_DedupByID(t *testing.T) {
	raw := `Id=mariadb.service
LoadState=loaded
ActiveState=active
SubState=running
MainPID=999

Id=mariadb.service
LoadState=loaded
ActiveState=active
SubState=running
MainPID=999

Id=lshttpd.service
LoadState=loaded
ActiveState=active
SubState=running
MainPID=111`

	got := parseShowBlocks(raw)
	if len(got) != 2 {
		t.Fatalf("blocks = %d, want 2 (mariadb collapsed)", len(got))
	}
	if got[0].Unit != "mariadb.service" || got[1].Unit != "lshttpd.service" {
		t.Fatalf("wrong units after dedup: %q, %q", got[0].Unit, got[1].Unit)
	}
}

func TestFillUptime(t *testing.T) {
	svcs := []Service{
		{Unit: "a.service", Active: "active", monoUsec: 5_000_000},   // activated 5s after boot
		{Unit: "b.service", Active: "inactive", monoUsec: 1_000_000}, // not active → no uptime
		{Unit: "c.service", Active: "active", monoUsec: 0},           // no stamp → no uptime
	}
	// system has been up 3605s → a has been active 3600s.
	fillUptime(svcs, 3605)
	if svcs[0].UptimeSec != 3600 {
		t.Fatalf("a uptime = %d, want 3600", svcs[0].UptimeSec)
	}
	if svcs[1].UptimeSec != 0 {
		t.Fatalf("b uptime = %d, want 0 (inactive)", svcs[1].UptimeSec)
	}
	if svcs[2].UptimeSec != 0 {
		t.Fatalf("c uptime = %d, want 0 (no stamp)", svcs[2].UptimeSec)
	}

	// procUptime unavailable (0) → no uptime, no panic.
	svcs2 := []Service{{Unit: "a.service", Active: "active", monoUsec: 5_000_000}}
	fillUptime(svcs2, 0)
	if svcs2[0].UptimeSec != 0 {
		t.Fatalf("uptime with no /proc/uptime = %d, want 0", svcs2[0].UptimeSec)
	}
}

func TestNormalizeUnit(t *testing.T) {
	cases := map[string]string{
		"cfm":          "cfm.service",
		" mariadb ":    "mariadb.service",
		"angie.service": "angie.service",
		"cfm.timer":    "cfm.timer",
		"":             "",
		"   ":          "",
	}
	for in, want := range cases {
		if got := normalizeUnit(in); got != want {
			t.Errorf("normalizeUnit(%q) = %q, want %q", in, got, want)
		}
	}
}
