package mysql

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/enrich"
	"cfm/internal/logging"
)

type LoginConfig struct {
	Mode    string // "file"
	LogPath string // can be "auto" → resolveMySQLErrorLog()

	Every       time.Duration
	Window      time.Duration
	Cooldown    time.Duration
	SampleLimit int

	// thresholds
	DeniedPerIP   int // Access denied per remote IP
	DeniedPerUser int // Access denied per user (username)
	RootPerIP     int // Access denied for user 'root' per IP (tighter)
	ScanPerIP     int // unauthenticated aborted-connection bursts per IP

	// enrichment
	UseEnrich  bool
	UsePTR     bool
	EnrichDirs []string

	// ignore/self-noise
	IgnoreLocalhost bool // ignore host: 'localhost' and 127.0.0.1
	IgnoreCpanel    bool // ignore cPanel internal user 'Cpanel::MysqlUtils::Unprivileged'
}

type pend struct {
	kindKey string // e.g. "DENY|ip", "DENY|user", "ROOT|ip", "SCAN|ip"
	key     string // ip or user
}


type MySQL struct {
	cfg LoginConfig

	name string
	src  core.LineSource

	// window primitives
	pending map[string]pend
	samples *core.SampleRing
	gate    *core.AlertGate
	counts  *core.SlidingCounter

	// enrichment
	enr *enrich.Enricher

	// regexes
	// 2025-01-01  4:08:33 997817 [Warning] Access denied for user 'root'@'34.140.130.14' (using password: NO)
	reDenied *regexp.Regexp

	// 2025-01-01 11:50:00 1056978 [Warning] Aborted connection 1056978 to db: 'unconnected' user: 'unauthenticated' host: '188.113.160.108' (This connection closed normally without authentication)
	reAbortedUnauth *regexp.Regexp

	// noisy-but-irrelevant lines we just ignore (optional)
	reHostResemble *regexp.Regexp // "has been resolved to the host name ... which resembles IPv4-address itself."
	reHostNX       *regexp.Regexp // "Host name '...' could not be resolved"
}


func NewMySQL(cfg LoginConfig) *MySQL {

	// sensible defaults
	if cfg.Mode == "" { cfg.Mode = "file" }
	if cfg.LogPath == "auto" || cfg.LogPath == "" {
		if p := resolveMySQLErrorLog(); p != "" { cfg.LogPath = p }
	}
	if cfg.Every <= 0    { cfg.Every = 2 * time.Second }
	if cfg.Window <= 0   { cfg.Window = 15 * time.Minute }
	if cfg.Cooldown <= 0 { cfg.Cooldown = 20 * time.Minute }
	if cfg.SampleLimit <= 0 { cfg.SampleLimit = 10 }
	if !cfg.UseEnrich && !cfg.UsePTR { cfg.UsePTR = true }
	if cfg.UseEnrich && len(cfg.EnrichDirs) == 0 {
		cfg.EnrichDirs = []string{"/etc/cfm", "/usr/share/GeoIP", "/usr/local/share/GeoIP", "./configs"}
	}

	m := &MySQL{cfg: cfg}
	// window primitives
	m.pending = make(map[string]pend)
	m.samples = core.NewSampleRing(cfg.SampleLimit)
	m.gate    = core.NewAlertGate(cfg.Cooldown)
	m.counts  = core.NewSlidingCounter(cfg.Window, 0)

	// Denied
	m.reDenied = regexp.MustCompile(`(?i)\bAccess denied for user '([^']+)'@'([^']+)'(?:\s+\(using password: (YES|NO)\))?`)

	// Aborted unauthenticated
	m.reAbortedUnauth = regexp.MustCompile(`(?i)\bAborted connection \d+ to db: 'unconnected' user: 'unauthenticated' host: '([^']+)'`)

	// Noisy informational
	m.reHostResemble = regexp.MustCompile(`(?i)has been resolved to the host name .* resembles IPv4-address`)
	m.reHostNX = regexp.MustCompile(`(?i)Host name '.*' could not be resolved`)

	if cfg.UseEnrich {
		if e, _ := enrich.New(cfg.EnrichDirs...); e != nil {
			m.enr = e
			logging.Logf("[detectors] mysql/enrich enabled (dirs=%v)", cfg.EnrichDirs)
		}
	}
	return m
}

func (m *MySQL) Name() string         { if m.name != "" { return m.name } ; return "mysql/login" }
func (m *MySQL) SetName(n string)     { m.name = n }
func (m *MySQL) Every() time.Duration { if m.cfg.Every > 0 { return m.cfg.Every } ; return 2 * time.Second }

func (m *MySQL) SetSource(src core.LineSource) { m.src = src }
func (m *MySQL) ApplyPosition(p core.Position) {
	if ft, ok := m.src.(*core.FileTailer); ok {
		ft.ApplyResume(p.Inode, p.Offset)
	}
}
func (m *MySQL) Position() core.Position {
	if m.src == nil { return core.Position{} }
	off, ino, ts := m.src.Position()
	return core.Position{Offset: off, Inode: ino, TS: ts}
}

func (m *MySQL) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	if m.src == nil { return nil }
	if err := m.src.Open(); err != nil { return nil }
	defer m.src.Close()

	now := time.Now()
	lines := 0
	for {
		line, err := m.src.ReadNext(ctx)
		if err == io.EOF { break }
		if err != nil { break }
		lines++
		m.processLine(line)
	}
	m.flush(now, out)

	if os.Getenv("CFM_DEBUG") == "2" && lines > 0 {
		logging.Logf("[detectors] mysql scanned %d new lines", lines)
	}
	return nil
}





func (m *MySQL) processLine(s string) {
	// quick skip
	if m.reHostResemble.MatchString(s) || m.reHostNX.MatchString(s) {
		return
	}

	// Access denied
	if md := m.reDenied.FindStringSubmatch(s); md != nil {
		user := md[1]
		host := md[2]

		if m.cfg.IgnoreLocalhost && (host == "localhost" || host == "127.0.0.1") {
			return
		}
		if m.cfg.IgnoreCpanel && strings.HasPrefix(user, "Cpanel::MysqlUtils::") {
			return
		}

		luser := strings.ToLower(user)
		now := time.Now()

		// deny per IP
		m.bump(now, "DENY|ip", host, s)
		// deny per user
		m.bump(now, "DENY|user", luser, s)
		// root per IP (separate threshold; own counter+samples)
		if strings.EqualFold(user, "root") {
			m.bump(now, "ROOT|ip", host, s)
		}
		return
	}

	// Aborted unauthenticated: treat as scanning only when remote (not localhost)
	if ma := m.reAbortedUnauth.FindStringSubmatch(s); ma != nil {
		host := ma[1]
		if m.cfg.IgnoreLocalhost && (host == "localhost" || host == "127.0.0.1") {
			return
		}

		now := time.Now()
		m.bump(now, "SCAN|ip", host, s)
		return
	}

	// else ignore
}





func (m *MySQL) flush(now time.Time, out chan<- core.Alert) {
	for sk, p := range m.pending {
		limit, kindStr, displayKey := m.thresholdAndDisplay(p.kindKey, p.key)
		if limit <= 0 { continue }
		n := m.counts.Count(sk, now)
		if n < limit { continue }
		if !m.gate.Allow(sk, now, n, limit) { continue }

		extra := map[string]string{
			"window":   m.cfg.Window.String(),
			"cooldown": m.cfg.Cooldown.String(),
			"limit":    strconv.Itoa(limit),
			"log":      m.cfg.LogPath,
		}

        // help autoblock sink: tag what to block / who
        if strings.HasSuffix(p.kindKey, "|ip") {
            extra["ip"] = p.key
        }
        if strings.HasSuffix(p.kindKey, "|user") {
            extra["user"] = p.key
        }

		samples := m.samples.GetAndClear(sk)
		out <- core.Alert{
			When:    now,
			Kind:    core.AlertKind(kindStr),
			Key:     displayKey,
			Count:   n,
			Samples: samples,
			Extra:   extra,
		}
	}
}

// bump aggregates into window primitives and tracks the key for this tick
func (m *MySQL) bump(now time.Time, kindKey, key, line string) {
	sk := kindKey + ":" + key
	if _, ok := m.pending[sk]; !ok {
		m.pending[sk] = pend{kindKey: kindKey, key: key}
	}
	_ = m.counts.Add(sk, now)
	m.samples.Add(sk, line)
}

// threshold + display resolution per key
func (m *MySQL) thresholdAndDisplay(kindKey, key string) (limit int, kindStr, displayKey string) {
	switch kindKey {
	case "DENY|ip":
		limit = m.cfg.DeniedPerIP
		kindStr = "MYSQL/ACCESS_DENIED"
		displayKey = m.decorateIP(key)
	case "DENY|user":
		limit = m.cfg.DeniedPerUser
		kindStr = "MYSQL/ACCESS_DENIED"
		displayKey = key
	case "ROOT|ip":
		limit = m.cfg.RootPerIP
		if limit <= 0 { limit = m.cfg.DeniedPerIP }
		kindStr = "MYSQL/ROOT_DENIED"
		displayKey = m.decorateIP(key)
	case "SCAN|ip":
		limit = m.cfg.ScanPerIP
		kindStr = "MYSQL/UNAUTH_SCANS"
		displayKey = m.decorateIP(key)
	default:
		limit = 0
	}
	return
}










func (m *MySQL) decorateIP(ip string) string {
	if (!m.cfg.UseEnrich && !m.cfg.UsePTR) || ip == "" {
		return ip
	}
	ptr, asn, asname, country := "", 0, "", ""
	if m.enr != nil && m.cfg.UseEnrich {
		res := m.enr.Lookup(ip)
		if res.PTR != "" { ptr = strings.TrimSuffix(res.PTR, ".") }
		if res.ASN > 0 { asn = int(res.ASN) }
		if res.ASNName != "" { asname = res.ASNName }
		if res.Country != "" { country = res.Country }
	}
	if m.cfg.UsePTR && ptr == "" {
		// defer DNS to enricher elsewhere if you prefer; keeping light here
	}
	var tag []string
	if asn > 0 { tag = append(tag, strconv.Itoa(asn)) }
	if asname != "" { tag = append(tag, asname) }
	if country != "" { tag = append(tag, country) }
	parts := []string{ip}
	if ptr != "" { parts = append(parts, ptr) }
	if len(tag) > 0 { parts = append(parts, "["+strings.Join(tag, " ")+"]") }
	return strings.Join(parts, " ")
}


// ---- helpers ----
// ---- Auto resolve MySQL error log path (LOG_PATH="auto") ----

// resolveMySQLErrorLog tries:
// 1) parse /etc/my.cnf (and /etc/mysql/my.cnf) looking for "log-error = ..."
//    (supports bare path or directory + host.err)
// 2) common defaults in order
// Returns empty string if nothing found.
func resolveMySQLErrorLog() string {
	candidates := []string{
		"/etc/my.cnf",
		"/etc/mysql/my.cnf",
		"/etc/mariadb/my.cnf",
	}

	for _, cfg := range candidates {
		if p := parseLogErrorFrom(cfg); p != "" {
			if fileExists(p) { return p }
			// If it's a directory, try host.err inside it (best-effort)
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				// try *.err files, prefer the newest
				if newest := newestErrFile(p); newest != "" {
					return newest
				}
			}
		}
	}

	// common distro paths
	common := []string{
		"/var/log/mysqld.log",
		"/var/log/mysql/error.log",
		"/var/lib/mysql/mysqld.err",
		"/var/lib/mysql/mysql.err",
		"/var/lib/mysql/`hostname`.err", // may expand in shell; here we can’t
		"/var/lib/mysql/mariadb.err",
		"/var/lib/mariadb/mariadb.err",
	}
	for _, p := range common {
		if fileExists(p) { return p }
	}

	// scan for *.err under these dirs (best-effort)
	for _, dir := range []string{"/var/lib/mysql", "/var/lib/mariadb"} {
		if newest := newestErrFile(dir); newest != "" {
			return newest
		}
	}
	return ""
}

func parseLogErrorFrom(path string) string {
	f, err := os.Open(path)
	if err != nil { return "" }
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || line == "" { continue }
		// crude INI-ish parse; we only care for key = value
		if i := strings.Index(line, "log-error"); i >= 0 {
			// accept "log-error", "log_error"
			if !strings.HasPrefix(line, "log-error") && !strings.HasPrefix(line, "log_error") {
				continue
			}
			// split on '=', ':' or space
			var val string
			if j := strings.IndexAny(line, "=:"); j > 0 {
				val = strings.TrimSpace(line[j+1:])
			} else {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					val = strings.Join(parts[1:], " ")
				}
			}
			val = strings.Trim(val, `"'`)
			return val
		}
	}
	return ""
}

func newestErrFile(dir string) string {
	d, err := os.ReadDir(dir)
	if err != nil { return "" }
	var best string
	var bestInfo os.FileInfo
	for _, de := range d {
		if de.IsDir() { continue }
		name := de.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".err") { continue }
		fi, err := de.Info()
		if err != nil { continue }
		if best == "" || fi.ModTime().After(bestInfo.ModTime()) {
			best = filepath.Join(dir, name)
			bestInfo = fi
		}
	}
	return best
}
func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
