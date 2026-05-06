package status

import (
	"strings"

	"cfm/internal/conntrack"
	"cfm/internal/detectors/health"
)

type HeartbeatHealth struct {
	Hostname         string  `json:"hostname"`
	Load1            float64 `json:"load_1"`
	RAMUsedPct       float64 `json:"ram_used_pct"`
	DiskRootPct      float64 `json:"disk_root_pct"`
	TCPTotal         int     `json:"tcp_total"`
	TCPEstablished   int     `json:"tcp_established"`
	TCPSynRecv       int     `json:"tcp_syn_recv"`
	TCPListen        int     `json:"tcp_listen"`
	RAIDStatus       string  `json:"raid_status,omitempty"`
	SMARTStatus      string  `json:"smart_status,omitempty"`
	SMARTDevices     int     `json:"smart_devices,omitempty"`
	SMARTTempSummary string  `json:"smart_temp_summary,omitempty"`
	ConntrackCount   int     `json:"conntrack_count,omitempty"`
	ConntrackMax     int     `json:"conntrack_max,omitempty"`
	ConntrackPct     float64 `json:"conntrack_pct,omitempty"`
}

func BuildHeartbeatHealth() HeartbeatHealth {
	hs := health.SnapshotNow()

	out := HeartbeatHealth{
		Hostname:       hs.Host,
		Load1:          hs.Load1,
		RAMUsedPct:     hs.RamUsedPct,
		DiskRootPct:    hs.DiskRootPct,
		TCPTotal:       hs.TCP["total"],
		TCPEstablished: hs.TCP["ESTABLISHED"],
		TCPSynRecv:     hs.TCP["SYN_RECV"],
		TCPListen:      hs.TCP["LISTEN"],
	}

	if hs.Mdadm.Status != "" && hs.Mdadm.Status != "NO RAID" {
		out.RAIDStatus = hs.Mdadm.Status
	}

	total, fails := 0, 0
	temps := make([]string, 0, 3)
	for dev, info := range hs.Smart {
		total++
		h := strings.ToUpper(info.Health)
		if strings.Contains(h, "FAIL") || strings.Contains(h, "CRIT") {
			fails++
		}
		if info.TempC != "" && len(temps) < 3 {
			temps = append(temps, dev+"="+info.TempC+"C")
		}
	}
	if total > 0 {
		out.SMARTDevices = total
		if fails > 0 {
			out.SMARTStatus = "FAIL"
		} else {
			out.SMARTStatus = "PASS"
		}
		if len(temps) > 0 {
			out.SMARTTempSummary = strings.Join(temps, ", ")
		}
	}

	if usage, err := conntrack.ReadUsage(); err == nil && usage.Max > 0 {
		out.ConntrackCount = usage.Count
		out.ConntrackMax = usage.Max
		out.ConntrackPct = usage.UsagePct
	}

	return out
}
