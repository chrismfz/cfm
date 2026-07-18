package agent

import (
	"os"
	"strconv"
	"strings"
	"time"

	"cfm/internal/healthstore"
	"cfm/internal/mailq"
)

// Heartbeat vitals: quick-glance host metrics for the cfm-web Agents
// list (load/cpu/ram/swap/disk at a glance, HetrixTools-style), riding
// on the heartbeat the daemon already sends every ~30s. Nothing is
// measured here: the health detector samples the host every ~10s into
// the healthstore ring, and the exim/postfix queue detectors publish
// into mailq — this file only reads those stores. When the health
// detector is disabled (or its latest sample is stale) the vitals block
// is omitted entirely so cfm-web keeps its last record instead of
// showing zeros.

// HeartbeatVitals is the `vitals` object in the heartbeat body. Mail
// fields are only meaningful when MailMTA is non-empty (no queue
// detector enabled otherwise).
type HeartbeatVitals struct {
	CollectedAt   time.Time `json:"collected_at"`
	Load1         float64   `json:"load1"`
	CPUPct        float64   `json:"cpu_pct"`
	RamUsedPct    float64   `json:"ram_used_pct"`
	SwapUsedPct   float64   `json:"swap_used_pct"`
	DiskRootPct   float64   `json:"disk_root_pct"`
	UptimeSeconds uint64    `json:"uptime_seconds,omitempty"`
	MailMTA       string    `json:"mail_mta,omitempty"`
	MailQueued    int       `json:"mail_queued"`
	MailFrozen    int       `json:"mail_frozen,omitempty"`
}

// vitalsMaxAge rejects stale health samples: with the detector ticking
// every ~10s, anything older means it stopped — stale numbers presented
// as current are worse than none.
const vitalsMaxAge = 2 * time.Minute

// Test seams.
var (
	vitalsNow        = time.Now
	vitalsStore      = healthstore.Global
	vitalsNodeID     = healthNodeID
	vitalsMailLatest = mailq.Latest
	readUptimeFile   = func() ([]byte, error) { return os.ReadFile("/proc/uptime") }
)

// collectVitals returns nil when no fresh health sample exists (health
// detector disabled/stopped) — the heartbeat then omits the key.
func collectVitals() *HeartbeatVitals {
	sample, ok := vitalsStore().Latest(vitalsNodeID())
	if !ok {
		return nil
	}
	if age := vitalsNow().Sub(sample.CollectedAt); age < 0 || age > vitalsMaxAge {
		return nil
	}
	v := &HeartbeatVitals{
		CollectedAt: sample.CollectedAt,
		Load1:       sample.Load1,
		CPUPct:      sample.CPUPct,
		RamUsedPct:  sample.RamUsedPct,
		SwapUsedPct: sample.SwapUsedPct,
		DiskRootPct: sample.DiskRootPct,
	}
	if b, err := readUptimeFile(); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if secs, err := strconv.ParseFloat(f[0], 64); err == nil && secs > 0 {
				v.UptimeSeconds = uint64(secs)
			}
		}
	}
	if m, ok := vitalsMailLatest(); ok {
		v.MailMTA = m.MTA
		v.MailQueued = m.Total
		v.MailFrozen = m.Frozen
	}
	return v
}

// healthNodeID mirrors the health detector's node key (RunOnce:
// hostname from /proc, "local" fallback) so the ring lookup matches.
func healthNodeID() string {
	if b, err := os.ReadFile("/proc/sys/kernel/hostname"); err == nil {
		if h := strings.TrimSpace(string(b)); h != "" {
			return h
		}
	}
	return "local"
}
