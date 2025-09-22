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

type MySQL struct {
	cfg LoginConfig

	name string
	src  core.LineSource

	// aggregation
	nByIP    map[string]int
	nByUser  map[string]int
	nRootIP  map[string]int
	nScanIP  map[string]int // unauthenticated aborted connections per IP
	samples  map[string][]string
	lastFire map[string]time.Time

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
	m := &MySQL{cfg: cfg}

	m.nByIP = make(map[string]int)
	m.nByUser = make(map[string]int)
	m.nRootIP = make(map[string]int)
	m.nScanIP = make(map[string]int)
	m.samples = make(map[string][]string)
	m.lastFire = make(map[string]time.Time)

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

		keyIP := "DENY|ip:" + host
		keyUser := "DENY|user:" + strings.ToLower(user)
		m.nByIP[host]++
		m.nByUser[strings.ToLower(user)]++
		if strings.EqualFold(user, "root") {
			m.nRootIP[host]++
		}
		m.samples[keyIP] = appendSample(m.samples[keyIP], s, 64)
		m.samples[keyUser] = appendSample(m.samples[keyUser], s, 64)
		return
	}

	// Aborted unauthenticated: treat as scanning only when remote (not localhost)
	if ma := m.reAbortedUnauth.FindStringSubmatch(s); ma != nil {
		host := ma[1]
		if m.cfg.IgnoreLocalhost && (host == "localhost" || host == "127.0.0.1") {
			return
		}
		key := "SCAN|ip:" + host
		m.nScanIP[host]++
		m.samples[key] = appendSample(m.samples[key], s, 64)
		return
	}

	// else ignore
}

func (m *MySQL) flush(now time.Time, out chan<- core.Alert) {
	// Access denied – per IP
	for ip, n := range m.nByIP {
		if m.cfg.DeniedPerIP > 0 && n >= m.cfg.DeniedPerIP && m.cool("DENY|ip:"+ip, now) {
			out <- core.Alert{
				When:    now,
				Kind:    core.AlertKind("MYSQL/ACCESS_DENIED"),
				Key:     m.decorateIP(ip),
				Count:   n,
				Samples: limit(m.samples["DENY|ip:"+ip], m.cfg.SampleLimit),
				Extra:   map[string]string{"limit": itoa(m.cfg.DeniedPerIP), "log": m.cfg.LogPath},
			}
			m.samples["DENY|ip:"+ip] = nil
		}
	}

	// Access denied – per user
	for user, n := range m.nByUser {
		if m.cfg.DeniedPerUser > 0 && n >= m.cfg.DeniedPerUser && m.cool("DENY|user:"+user, now) {
			out <- core.Alert{
				When:    now,
				Kind:    core.AlertKind("MYSQL/ACCESS_DENIED"),
				Key:     user,
				Count:   n,
				Samples: limit(m.samples["DENY|user:"+user], m.cfg.SampleLimit),
				Extra:   map[string]string{"limit": itoa(m.cfg.DeniedPerUser), "log": m.cfg.LogPath},
			}
			m.samples["DENY|user:"+user] = nil
		}
	}

	// Access denied – root per IP (special)
	for ip, n := range m.nRootIP {
		lim := m.cfg.RootPerIP
		if lim <= 0 { lim = m.cfg.DeniedPerIP }
		if lim > 0 && n >= lim && m.cool("ROOT|ip:"+ip, now) {
			out <- core.Alert{
				When:    now,
				Kind:    core.AlertKind("MYSQL/ROOT_DENIED"),
				Key:     m.decorateIP(ip),
				Count:   n,
				Samples: limit(m.samples["DENY|ip:"+ip], m.cfg.SampleLimit), // reuse same sample pool
				Extra:   map[string]string{"limit": itoa(lim), "log": m.cfg.LogPath},
			}
		}
	}

	// Scanner bursts – unauthenticated aborted connections per IP
	for ip, n := range m.nScanIP {
		if m.cfg.ScanPerIP > 0 && n >= m.cfg.ScanPerIP && m.cool("SCAN|ip:"+ip, now) {
			out <- core.Alert{
				When:    now,
				Kind:    core.AlertKind("MYSQL/UNAUTH_SCANS"),
				Key:     m.decorateIP(ip),
				Count:   n,
				Samples: limit(m.samples["SCAN|ip:"+ip], m.cfg.SampleLimit),
				Extra:   map[string]string{"limit": itoa(m.cfg.ScanPerIP), "log": m.cfg.LogPath},
			}
			m.samples["SCAN|ip:"+ip] = nil
		}
	}

	// reset counters for next window
	clearMap(m.nByIP)
	clearMap(m.nByUser)
	clearMap(m.nRootIP)
	clearMap(m.nScanIP)
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

func (m *MySQL) cool(key string, now time.Time) bool {
	cd := m.cfg.Cooldown
	if cd <= 0 { cd = 20 * time.Minute }
	if last, ok := m.lastFire[key]; ok {
		if now.Sub(last) < cd {
			return false
		}
	}
	m.lastFire[key] = now
	return true
}

// ---- helpers ----

func appendSample(ss []string, s string, max int) []string {
	ss = append(ss, s)
	if len(ss) > max {
		return ss[len(ss)-max:]
	}
	return ss
}
func limit(ss []string, n int) []string {
	if n <= 0 || len(ss) <= n { return ss }
	return ss[:n]
}
func clearMap[M ~map[string]int](m M) {
	for k := range m { delete(m, k) }
}
func itoa(i int) string { return strconv.Itoa(i) }

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
