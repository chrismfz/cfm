package detectors

import (
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/health"
	"cfm/internal/detectors/meta"
	// "cfm/internal/logging"
)

// /tmp watch defaults: alert, and delete regular files older than
// healthDefaultTmpCleanOlder, once /tmp reaches healthDefaultTmpPct percent.
// They must equal the stock configs/detectors.conf [health] values
// (reference_defaults_config_test.go). TMP_PCT = 0 in a section turns the
// watch off.
const (
	healthDefaultTmpPct        = 85
	healthDefaultTmpCleanOlder = 12 * time.Hour
)

// Backup check defaults (internal/backupcheck). They must equal the stock
// configs/detectors.conf [health] values (reference_defaults_config_test.go).
const (
	healthDefaultBackupEvery        = 15 * time.Minute
	healthDefaultBackupStuckAfter   = 24 * time.Hour
	healthDefaultBackupProxmoxStale = 8 * 24 * time.Hour
	healthDefaultBackupDestFreePct  = 5
)

func init() {
	meta.Register(meta.DetectorMeta{
		TypeKey:          "health",
		Title:            "System health",
		Description:      "Resource/host health watcher detector.",
		DefaultsTemplate: map[string]string{"ENABLED": "1", "EVERY": "10s", "WINDOW": "2m", "COOLDOWN": "15m"},
	})
	Register("health", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 10*time.Second)
		defWindow := kvDur(global, "DEFAULT_WINDOW", 2*time.Minute)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 15*time.Minute)

		// --- Enrichment options ---
		enrichOn := kvBool(kv, "ENRICH", true)
		ptrOn := kvBool(kv, "PTR", true)
		// default dirs already handled in health.New, but allow override
		dirsRaw := kvStrClean(kv, "ENRICH_DIRS", "")
		var dirs []string
		if dirsRaw != "" {
			for _, p := range strings.Split(dirsRaw, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					dirs = append(dirs, p)
				}
			}
		}
		spikeTopN := kvInt(kv, "SPIKE_PROBE_TOPN", 10)

		cfg := health.Config{
			Every:    kvDur(kv, "EVERY", defEvery),
			Window:   kvDur(kv, "WINDOW", defWindow),
			Cooldown: kvDur(kv, "COOLDOWN", defCooldown),

			CpuLoadPct:  kvInt(kv, "CPU_LOAD_PCT", 120),
			RamUsedPct:  kvInt(kv, "RAM_USED_PCT", 90),
			DiskRootPct: kvInt(kv, "DISK_ROOT_PCT", 90),
			TmpUsedPct:  kvInt(kv, "TMP_PCT", healthDefaultTmpPct),

			ConnTotalSpikeX: kvFlt(kv, "CONN_TOTAL_SPIKE", 3.0),
			ConnEstSpikeX:   kvFlt(kv, "CONN_EST_SPIKE", 3.0),
			ConnSynSpikeX:   kvFlt(kv, "CONN_SYN_SPIKE", 3.0),
			ConnTotalAbs:    kvInt(kv, "CONN_TOTAL_ABS", 20000),
			EstablishedAbs:  kvInt(kv, "ESTABLISHED_ABS", 8000),
			SynRecvAbs:      kvInt(kv, "SYN_RECV_ABS", 500),

			// NEW floors for spike alerts
			ConnTotalMin:   kvInt(kv, "CONN_TOTAL_MIN", 50),
			EstablishedMin: kvInt(kv, "ESTABLISHED_MIN", 30),
			SynRecvMin:     kvInt(kv, "SYN_RECV_MIN", 50),
			SpikeMinDelta:  kvInt(kv, "SPIKE_MIN_DELTA", 10),

			ThruSpikeX:  kvFlt(kv, "THROUGHPUT_SPIKE_X", 4.0),
			ThruMinMbps: kvFlt(kv, "THROUGHPUT_MIN_MBPS", 0.0),

			TempWarnC:        kvInt(kv, "TEMP_C_WARN", 85),
			TempCritC:        kvInt(kv, "TEMP_C_CRIT", 95),
			SmartWearWarnPct: kvInt(kv, "SMART_WEAR_WARN_PCT", 80),
			SmartWearCritPct: kvInt(kv, "SMART_WEAR_CRIT_PCT", 95),

			SmartAlert: kvBool(kv, "SMART_FAIL_ALERT", true),
			MdadmAlert: kvBool(kv, "MDADM_ALERT", true),
			ZfsAlert:   kvBool(kv, "ZFS_ALERT", true),
			ECCAlert:   kvBool(kv, "ECC_ALERT", true),

			// enrichment
			SpikeProbeTopN: spikeTopN,
			UseEnrich:      enrichOn,
			UsePTR:         ptrOn,
			EnrichDirs:     dirs,

			TmpCleanOlder: kvDur(kv, "TMP_CLEAN_OLDER", healthDefaultTmpCleanOlder),

			BackupAlert:             kvBool(kv, "BACKUP_ALERT", true),
			BackupEvery:             kvDur(kv, "BACKUP_EVERY", healthDefaultBackupEvery),
			BackupStuckAfter:        kvDur(kv, "BACKUP_STUCK_AFTER", healthDefaultBackupStuckAfter),
			BackupProxmoxStaleAfter: kvDur(kv, "BACKUP_PROXMOX_STALE", healthDefaultBackupProxmoxStale),
			BackupDestFreeMinPct:    kvFlt(kv, "BACKUP_DEST_FREE_PCT", healthDefaultBackupDestFreePct),
		}

		d := health.New(cfg)
		d.SetName(section)
		// Source isn’t a file; the detector actively samples (/proc, smartctl, sensors).
		// Implement with a ticker inside health.New(..). No core.LineSource needed.
		return d, nil
	})
}
