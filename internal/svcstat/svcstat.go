// Package svcstat reports systemd unit status (the `systemctl status` view,
// structured): for a curated set of CFM / hosting-stack units — or an explicit
// list — whether each is loaded, active, enabled-at-boot, its main PID, memory,
// restart count and how long it has been up. It backs the read-only MCP tool
// `service_status` / GET /api/v1/system/services — the "is cfm/the edge/mysql/
// mail actually running, and has anything been flapping?" check.
//
// It shells out to `systemctl show` once for the whole set (property blocks are
// separated by a blank line), so it is one exec regardless of how many units are
// queried. Uptime is derived from the unit's CLOCK_MONOTONIC activation stamp
// against /proc/uptime, which is locale- and timezone-independent (unlike the
// human ActiveEnterTimestamp, which we still pass through verbatim).
package svcstat

import (
	"context"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Service is one systemd unit's status.
type Service struct {
	Unit        string `json:"unit"`
	Load        string `json:"load"`              // LoadState: loaded | not-found | masked
	Active      string `json:"active"`            // ActiveState: active | inactive | failed | activating
	Sub         string `json:"sub"`               // SubState: running | dead | exited | failed
	Enabled     string `json:"enabled"`           // UnitFileState: enabled | disabled | static | masked | ""
	Description string `json:"description,omitempty"`
	MainPID     int    `json:"main_pid,omitempty"`
	MemoryBytes int64  `json:"memory_bytes,omitempty"` // omitted when accounting is off / not set
	Restarts    int    `json:"restarts"`
	ActiveSince string `json:"active_since,omitempty"` // raw ActiveEnterTimestamp (human, as systemd formats it)
	UptimeSec   int64  `json:"uptime_sec,omitempty"`   // seconds active, derived from the monotonic stamp

	// monoUsec is ActiveEnterTimestampMonotonic (µs since boot), carried from
	// the parser to fillUptime. Unexported → never serialized.
	monoUsec int64
}

const showTimeout = 5 * time.Second

// memNotSet is systemd's uint64 sentinel for "MemoryCurrent not available".
const memNotSet = "18446744073709551615"

// showProps is the fixed property set we ask `systemctl show` for.
var showProps = []string{
	"Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "Description",
	"MainPID", "MemoryCurrent", "NRestarts", "ActiveEnterTimestamp",
	"ActiveEnterTimestampMonotonic",
}

// DefaultUnits is the curated candidate set queried when the caller names none:
// CFM itself, every edge/web frontend, the common database, mail, DNS, cache,
// FTP, panel and platform units. Units that aren't installed (LoadState
// not-found) are dropped from the default view; an explicit query keeps them so
// the operator sees "you asked about X — it isn't here".
var DefaultUnits = []string{
	"cfm",
	"angie", "openresty", "nginx", "httpd", "apache2", "lsws", "lshttpd",
	"mariadb", "mysql", "mysqld", "postgresql",
	"exim", "dovecot", "postfix",
	"named", "bind9", "pdns", "redis", "memcached",
	"pure-ftpd", "proftpd", "vsftpd",
	"sshd", "ssh", "crond", "cron", "fail2ban",
	"cpanel", "cpsrvd", "imunify360",
}

// Status returns systemd status for the given units. When units is empty the
// curated DefaultUnits set is used and not-installed units are elided; when the
// caller names units explicitly, not-found units are kept (so an operator who
// asks about a unit that isn't there gets told so). Unit names without a `.`
// suffix are treated as `.service`.
func Status(ctx context.Context, units []string) ([]Service, error) {
	explicit := len(units) > 0
	if !explicit {
		units = DefaultUnits
	}
	norm := make([]string, 0, len(units))
	for _, u := range units {
		u = normalizeUnit(u)
		if u != "" {
			norm = append(norm, u)
		}
	}
	if len(norm) == 0 {
		return nil, nil
	}

	cctx, cancel := context.WithTimeout(ctx, showTimeout)
	defer cancel()

	args := append([]string{"show", "--property=" + strings.Join(showProps, ",")}, norm...)
	// systemctl show exits non-zero on some units yet still prints valid blocks
	// for the rest; parse whatever came back rather than discarding it.
	raw, _ := exec.CommandContext(cctx, systemctlPath(), args...).Output()
	svcs := parseShowBlocks(string(raw))

	if !explicit {
		filtered := svcs[:0]
		for _, s := range svcs {
			if s.Load == "not-found" {
				continue
			}
			filtered = append(filtered, s)
		}
		svcs = filtered
	}

	fillUptime(svcs, readProcUptime())

	sort.Slice(svcs, func(i, j int) bool { return svcs[i].Unit < svcs[j].Unit })
	return svcs, nil
}

// parseShowBlocks parses the `systemctl show` output: KEY=VALUE lines, one unit
// per block, blocks separated by a blank line. Separated from exec so it is
// unit-tested without systemd. monotonicUsec is carried out-of-band (not a JSON
// field) so fillUptime can turn it into UptimeSec. Blocks are de-duplicated by
// resolved unit Id: several query names can alias the same unit (mysql/mysqld →
// mariadb.service, lsws → lshttpd.service), and systemctl emits one block per
// name — we keep the first and drop the repeats.
func parseShowBlocks(raw string) []Service {
	blocks := strings.Split(strings.TrimSpace(raw), "\n\n")
	out := make([]Service, 0, len(blocks))
	seen := make(map[string]struct{}, len(blocks))
	for _, block := range blocks {
		kv := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if i := strings.IndexByte(line, '='); i > 0 {
				kv[line[:i]] = line[i+1:]
			}
		}
		id := kv["Id"]
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		s := Service{
			Unit:        id,
			Load:        kv["LoadState"],
			Active:      kv["ActiveState"],
			Sub:         kv["SubState"],
			Enabled:     kv["UnitFileState"],
			Description: kv["Description"],
			ActiveSince: kv["ActiveEnterTimestamp"],
		}
		if n, err := strconv.Atoi(kv["MainPID"]); err == nil && n > 0 {
			s.MainPID = n
		}
		if n, err := strconv.Atoi(kv["NRestarts"]); err == nil {
			s.Restarts = n
		}
		if m := kv["MemoryCurrent"]; m != "" && m != memNotSet && m != "[not set]" {
			if b, err := strconv.ParseInt(m, 10, 64); err == nil && b >= 0 {
				s.MemoryBytes = b
			}
		}
		s.monoUsec = parseMonotonicUsec(kv["ActiveEnterTimestampMonotonic"])
		out = append(out, s)
	}
	return out
}

// parseMonotonicUsec returns the ActiveEnterTimestampMonotonic in microseconds,
// or 0 if absent/zero. fillUptime resolves it against /proc/uptime.
func parseMonotonicUsec(s string) int64 {
	if v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil && v > 0 {
		return v
	}
	return 0
}

// fillUptime converts each service's monotonic activation stamp (µs since boot,
// parsed into monoUsec) into seconds-active, using the system's current
// monotonic clock reading (procUptimeSec, seconds since boot). Only active units
// with a usable stamp get a positive uptime; everything else stays zero.
func fillUptime(svcs []Service, procUptimeSec float64) {
	for i := range svcs {
		svcs[i].UptimeSec = 0
		if svcs[i].Active != "active" || svcs[i].monoUsec <= 0 || procUptimeSec <= 0 {
			continue
		}
		up := procUptimeSec - float64(svcs[i].monoUsec)/1e6
		if up > 0 {
			svcs[i].UptimeSec = int64(up)
		}
	}
}

// readProcUptime returns seconds since boot from /proc/uptime (0 on any error).
func readProcUptime() float64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return v
}

// normalizeUnit trims a unit name and appends `.service` when it carries no
// unit-type suffix, so callers can say "cfm" or "cfm.service" (or "cfm.timer").
func normalizeUnit(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	if !strings.ContainsRune(u, '.') {
		return u + ".service"
	}
	return u
}

func systemctlPath() string {
	if p, err := exec.LookPath("systemctl"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "systemctl"
}
