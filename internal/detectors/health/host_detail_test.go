package health

import (
	"testing"
	"time"
)

const sampleMeminfo = `MemTotal:       196608000 kB
MemFree:         8000000 kB
MemAvailable:   123456000 kB
Buffers:         1250000 kB
Cached:         84000000 kB
SwapCached:        12000 kB
SwapTotal:       8388604 kB
SwapFree:        6291452 kB
`

func TestParseMemInfoDetail(t *testing.T) {
	m := parseMemInfoDetail([]byte(sampleMeminfo))
	if m.TotalBytes != 196608000*1024 {
		t.Fatalf("total = %d", m.TotalBytes)
	}
	if m.AvailableBytes != 123456000*1024 {
		t.Fatalf("available = %d", m.AvailableBytes)
	}
	if m.BuffersBytes != 1250000*1024 {
		t.Fatalf("buffers = %d", m.BuffersBytes)
	}
	if m.CachedBytes != 84000000*1024 {
		t.Fatalf("cached = %d (SwapCached must not leak in)", m.CachedBytes)
	}
	if m.SwapTotalBytes != 8388604*1024 {
		t.Fatalf("swap total = %d", m.SwapTotalBytes)
	}
	if want := uint64(8388604-6291452) * 1024; m.SwapUsedBytes != want {
		t.Fatalf("swap used = %d want %d", m.SwapUsedBytes, want)
	}
	if m.SwapUsedPct < 24.9 || m.SwapUsedPct > 25.1 {
		t.Fatalf("swap pct = %f want ~25", m.SwapUsedPct)
	}
}

func TestParseMemInfoDetailNoSwap(t *testing.T) {
	m := parseMemInfoDetail([]byte("MemTotal: 1000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"))
	if m.SwapTotalBytes != 0 || m.SwapUsedBytes != 0 || m.SwapUsedPct != 0 {
		t.Fatalf("no-swap host should report zeros: %+v", m)
	}
}

func TestParseUptimeSeconds(t *testing.T) {
	if got := parseUptimeSeconds([]byte("6785343.17 216456478.11\n")); got != 6785343 {
		t.Fatalf("uptime = %d", got)
	}
	if got := parseUptimeSeconds([]byte("garbage")); got != 0 {
		t.Fatalf("garbage uptime = %d", got)
	}
}

const sampleCPUInfo = `processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
cpu MHz		: 2608.032

processor	: 1
model name	: Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
cpu MHz		: 2599.998
`

func TestParseCPUInfo(t *testing.T) {
	c := parseCPUInfo([]byte(sampleCPUInfo))
	if c.Threads != 2 {
		t.Fatalf("threads = %d", c.Threads)
	}
	if c.Model != "Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz" {
		t.Fatalf("model = %q", c.Model)
	}
	if c.MHz < 2608 || c.MHz > 2609 {
		t.Fatalf("mhz = %f (want first occurrence)", c.MHz)
	}
}

func TestParseOSPrettyName(t *testing.T) {
	in := "NAME=\"AlmaLinux\"\nPRETTY_NAME=\"AlmaLinux 9.4 (Seafoam Ocelot)\"\n"
	if got := parseOSPrettyName([]byte(in)); got != "AlmaLinux 9.4 (Seafoam Ocelot)" {
		t.Fatalf("pretty name = %q", got)
	}
}

func TestCPUUtilFromDelta(t *testing.T) {
	prev := cpuTicks{user: 100, nice: 0, system: 50, idle: 800, iowait: 40, irq: 5, softirq: 5, steal: 0}
	cur := cpuTicks{user: 160, nice: 10, system: 70, idle: 880, iowait: 60, irq: 10, softirq: 10, steal: 0}
	// deltas: user+nice=70, system+irq+softirq=30, idle=80, iowait=20, total=200
	u := cpuUtilFromDelta(prev, cur)
	if !u.Valid {
		t.Fatal("expected valid")
	}
	if u.BusyPct != 50 {
		t.Fatalf("busy = %f want 50", u.BusyPct)
	}
	if u.UserPct != 35 || u.SystemPct != 15 || u.IOWaitPct != 10 || u.StealPct != 0 {
		t.Fatalf("breakdown = %+v", u)
	}
}

func TestCPUUtilFromDeltaCounterReset(t *testing.T) {
	prev := cpuTicks{user: 1000, idle: 1000}
	cur := cpuTicks{user: 10, idle: 10}
	if u := cpuUtilFromDelta(prev, cur); u.Valid {
		t.Fatalf("counter reset must be invalid, got %+v", u)
	}
}

func TestParseCPUStat(t *testing.T) {
	in := "cpu  100 5 50 800 40 5 5 2 0 0\ncpu0 50 2 25 400 20 2 2 1 0 0\n"
	ticks, ok := parseCPUStat([]byte(in))
	if !ok {
		t.Fatal("parse failed")
	}
	if ticks.user != 100 || ticks.idle != 800 || ticks.steal != 2 {
		t.Fatalf("ticks = %+v", ticks)
	}
}

const sampleDiskstats = ` 259       0 nvme0n1 1000 0 160000 500 2000 0 320000 900 0 700 1400
 259       1 nvme0n1p1 10 0 100 5 20 0 200 9 0 7 14
   8       0 sda 500 0 80000 250 1000 0 160000 450 0 350 700
   7       0 loop0 5 0 50 1 0 0 0 0 0 0 0
`

func TestParseDiskstatsAndRates(t *testing.T) {
	allowed := wholeDiskAllowSet([]string{"nvme0n1", "sda", "loop0"})
	if allowed["loop0"] {
		t.Fatal("loop devices must be excluded")
	}
	cur := parseDiskstats([]byte(sampleDiskstats), allowed)
	if len(cur) != 2 {
		t.Fatalf("devices = %v (partitions must be skipped via allow-set)", cur)
	}
	if cur["nvme0n1"].readSectors != 160000 || cur["nvme0n1"].writeSectors != 320000 {
		t.Fatalf("nvme0n1 counters = %+v", cur["nvme0n1"])
	}
}

func TestReadDiskIORatesSeedThenDelta(t *testing.T) {
	origBlock, origStats, origNow := readSysBlockNames, readProcDiskstats, throughputNow
	defer func() { readSysBlockNames, readProcDiskstats, throughputNow = origBlock, origStats, origNow }()

	readSysBlockNames = func() ([]string, error) { return []string{"sda"}, nil }
	content := " 8 0 sda 0 0 1000 0 0 0 2000 0 0 0 0\n"
	readProcDiskstats = func() ([]byte, error) { return []byte(content), nil }
	base := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	now := base
	throughputNow = func() time.Time { return now }

	d := New(Config{})
	if got := d.readDiskIORates(); got != nil {
		t.Fatalf("seeding call must return nil, got %v", got)
	}

	// +10s, +1000 sectors read (512e3 B → 51200 B/s), +4000 written (204800 B/s)
	content = " 8 0 sda 0 0 2000 0 0 0 6000 0 0 0 0\n"
	now = base.Add(10 * time.Second)
	got := d.readDiskIORates()
	if len(got) != 1 || got[0].Device != "sda" {
		t.Fatalf("rates = %+v", got)
	}
	if got[0].ReadBps != 51200 || got[0].WriteBps != 204800 {
		t.Fatalf("bps = %+v", got[0])
	}
}

func TestPerNICRates(t *testing.T) {
	prev := map[string]nicCounters{
		"eno1":  {rxBytes: 0, txBytes: 0},
		"vmbr0": {rxBytes: 1000, txBytes: 1000},
	}
	cur := map[string]nicCounters{
		"eno1":  {rxBytes: 1_250_000, txBytes: 2_500_000}, // 1 Mbps / 2 Mbps over 10s
		"vmbr0": {rxBytes: 1000, txBytes: 1000},           // idle but has counters
		"tap0":  {rxBytes: 0, txBytes: 0},                 // never saw traffic → dropped
	}
	rates := perNICRates(prev, cur, 10)
	if len(rates) != 2 {
		t.Fatalf("rates = %+v", rates)
	}
	if rates[0].Name != "eno1" || rates[0].RxMbps != 1 || rates[0].TxMbps != 2 {
		t.Fatalf("busiest-first expected eno1 1/2 Mbps, got %+v", rates[0])
	}
	if rates[1].Name != "vmbr0" || rates[1].RxMbps != 0 {
		t.Fatalf("idle nic = %+v", rates[1])
	}
	if perNICRates(nil, cur, 10) != nil {
		t.Fatal("no previous state must yield nil")
	}
}
