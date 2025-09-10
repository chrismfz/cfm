package exim

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"
	"net"
	"strings"

	core "cfm/internal/detectors/core"
	"cfm/internal/logging"
	"cfm/internal/enrich"

	"html"
	"mime"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"

	"strconv"
)

// ---- Config ----

type RelaysConfig struct {
	LogPath     string        // αν κενό, θα δοκιμάσουμε AutoDetect()
	Every       time.Duration // default: 5s
	Window      time.Duration // default: 15m
	SampleLimit int           // default: 10
	Cooldown    time.Duration // default: 10m

	// Thresholds (>= triggers)
	LocalUserMax   int // U=user, P=local
	AuthUserMax    int // P=esmtpa|esmtpsa + A=user
	AuthIPMax      int // P=esmtpa|esmtpsa + H=[ip]
	AuthUserIPMax  int // combined key ip/user
	UnauthIPMax    int // P=esmtp|esmtps + H=[ip] (χωρίς A=)

 // enrichment flags (νέα)
    UseEnrich  bool          // default: true
    UsePTR     bool          // default: true (αν enrich αποτύχει)
    EnrichDirs []string      // π.χ. ["/etc/cfm", "/usr/share/GeoIP"]
}

// ---- Alert kinds ----
const (
	KindLocalRelay  core.AlertKind = "LOCALRELAY"
	KindAuthRelay   core.AlertKind = "AUTHRELAY"
	KindRelay       core.AlertKind = "RELAY"
)

// ---- Detector ----

type Relays struct {
	cfg RelaysConfig

	mu       sync.Mutex
	off      int64      // file offset
	inode    uint64     // file inode για rotation
	lastFire map[string]time.Time // per-kind/key cooldown
	samples  map[string][]string  // per-kind/key rolling samples
	counts   *windowCounter       // per-kind/key sliding window
	path     string               // effective path
	readyLog bool
	recent []string // last few lines to infer PHP context
	enr *enrich.Enricher //enrich output
	pending map[string]pend
}


type pend struct {
	kindKey string
	key     string
	n       int
}


func NewRelays(cfg RelaysConfig) *Relays {
    if cfg.Every <= 0 { cfg.Every = 5 * time.Second }
    if cfg.Window <= 0 { cfg.Window = 15 * time.Minute }
    if cfg.SampleLimit <= 0 { cfg.SampleLimit = 10 }
    if cfg.Cooldown <= 0 { cfg.Cooldown = 10 * time.Minute }
    // enrichment defaults
    if !cfg.UseEnrich && !cfg.UsePTR {
        cfg.UsePTR = true
    }
    if cfg.UseEnrich && len(cfg.EnrichDirs) == 0 {
        cfg.EnrichDirs = []string{"/etc/cfm", "/usr/share/GeoIP", "/usr/local/share/GeoIP", "./configs"}
    }

    d := &Relays{
        cfg:      cfg,
        lastFire: make(map[string]time.Time),
        samples:  make(map[string][]string),
        counts:   newWindowCounter(cfg.Window),
    }

    if cfg.UseEnrich {
        if e, _ := enrich.New(cfg.EnrichDirs...); e != nil {
            d.enr = e
            logging.Logf("[detectors] exim/relays enrichment enabled (dirs=%v, geo=%v asn=%v)",
                cfg.EnrichDirs, e.Enabled(), e.Enabled())
        } else {
            logging.Logf("[detectors] exim/relays enrichment unavailable; falling back to PTR only")
        }
    }
    return d
}



func (d *Relays) Name() string         { return "exim/relays" }
func (d *Relays) Every() time.Duration { return d.cfg.Every }

func (d *Relays) RunOnce(ctx context.Context, out chan<- core.Alert) error {
d.pending = make(map[string]pend)

	// Ensure log path (one-off autodetect)
	if d.path == "" {
		if d.cfg.LogPath != "" {
			d.path = d.cfg.LogPath
		} else {
			d.path = autoDetectEximLog()
		}
		if d.path == "" {
			if !d.readyLog {
				logging.Logf("[detectors] exim/relays: no log path found (set LOG_PATH)")
				d.readyLog = true
			}
			return nil
		}
		if !d.readyLog {
			logging.Logf("[detectors] exim/relays using log: %s", d.path)
			d.readyLog = true
		}
	}

	f, err := os.Open(d.path)
	if err != nil {
		return nil // quiet: ίσως προσωρινό
	}
	defer f.Close()

	// rotation check
	stat, _ := f.Stat()
	if stat != nil {
		if st, ok := stat.Sys().(*syscall.Stat_t); ok {
			in := uint64(st.Ino)
			if d.inode != 0 && in != d.inode {
				// rotated: reset offset
				d.off = 0
			}
			d.inode = in
		}
	}

	// adjust offset
	if d.off > 0 {
		if _, err := f.Seek(d.off, 0); err != nil {
			d.off = 0
			f.Seek(0, 0)
		}
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	now := time.Now()
	lines := 0
	for sc.Scan() {
		line := sc.Text()
		lines++
		d.processLine(now, line, out)
	}
	// record new offset
	if pos, err := f.Seek(0, 1); err == nil {
		d.off = pos
	}

// ---- flush aggregated alerts (τέλος run) ----
nowSend := time.Now()
for _, p := range d.pending {
	threshold, alertKind, baseKey := d.thresholdAndKey(p.kindKey, p.key)
	if threshold <= 0 || p.n < threshold {
		continue
	}
	// cooldown per key
	sk := p.kindKey + ":" + p.key
	if !d.cool(sk, nowSend) {
		continue
	}


// --- META ---
isPHP, cwd, uid := false, "", ""
if alertKind == KindLocalRelay {
    if ok, c, u := d.guessPHP(); ok {
        isPHP, cwd, uid = true, c, u
        baseKey += " (php)"
    }
}
	// εμπλουτισμός key
	displayKey := d.enrichDisplay(p.kindKey, baseKey, p.key)

	// δείγματα (και subject decode, αν το έχεις)
	samples := d.samples[sk]
	if len(samples) > d.cfg.SampleLimit {
		samples = samples[:d.cfg.SampleLimit]
	}
	pretty := make([]string, 0, len(samples)*2)
	for _, ln := range samples {
		pretty = append(pretty, ln)
		if subj := decodeSubjectFromLine(ln); subj != "" {
			pretty = append(pretty, "SUBJ: "+subj)
		}
	}

	// extra info (βάζουμε και το limit)
	extra := map[string]string{
		"log":      d.path,
		"window":   d.cfg.Window.String(),
		"cooldown": d.cfg.Cooldown.String(),
		"limit":    strconv.Itoa(threshold),
	}
if isPHP {
    if cwd != "" { extra["cwd"] = cwd }
    if uid != "" { extra["uid"] = uid }
}
	// για LOCALRELAY: web/php context
	if alertKind == KindLocalRelay {
		if isPHP, cwd, uid := d.guessPHP(); isPHP {
			if cwd != "" { extra["cwd"] = cwd }
			if uid != "" { extra["uid"] = uid }
		}
	}

	out <- core.Alert{
		When:    nowSend,
		Kind:    alertKind,
		Key:     displayKey,
		Count:   p.n,        // <— ΤΟ ΣΥΝΟΛΟ που είδες (π.χ. 180)
		Samples: pretty,
		Extra:   extra,
	}

	// reset samples για φρέσκα entries στο επόμενο alert
	d.samples[sk] = nil
}


	// προαιρετικό metrics όταν τρέχεις με debug
	if os.Getenv("CFM_DEBUG") == "2" && lines > 0 {
		logging.Logf("[detectors] exim/relays scanned %d new lines", lines)
	}
	return nil
}

// ---- Parsing ----
// Δουλεύουμε πάνω σε γραμμές τύπου:
// 2025-09-06 12:34:05 ... <= user@domain H=(host) [1.2.3.4]:57781 P=esmtpa A=dovecot_login:user ...
// 2025-09-08 13:03:39 ... <= user@... U=username P=local ...
// 2025-09-06 12:34:05 ... <= ... H=... [1.2.3.4]:port P=esmtp ... (NO A=)

// πιο χαλαρά regex για να μην «σπάνε» σε edge cases
var (
	reHasArrowIn = regexp.MustCompile(`\s<=\s`) // μόνο εισερχόμενα στο exim (γένεση μηνύματος)
	reIP         = regexp.MustCompile(`\[(\d{1,3}(?:\.\d{1,3}){3})\]`)
	reUserLocal  = regexp.MustCompile(`\bU=([^\s]+)\s+P=local\b`)
	reAuthUser   = regexp.MustCompile(`\bA=[^:\s]+:([^\s]+)`)
	reProto      = regexp.MustCompile(`\bP=(\w+)\b`) // esmtp, esmtps, esmtpa, esmtpsa, local
)

// process a single line
// process a single line
func (d *Relays) processLine(now time.Time, line string, out chan<- core.Alert) {
	// πάντα κράτα την γραμμή στο μικρό buffer των "recent"
	defer d.pushRecent(line)

	if !reHasArrowIn.MatchString(line) {
		return
	}
	proto := ""
	if m := reProto.FindStringSubmatch(line); m != nil {
		proto = m[1]
	}

	// LOCAL
	if proto == "local" {
		if m := reUserLocal.FindStringSubmatch(line); m != nil {
			user := m[1]
			d.bump(now, string(KindLocalRelay), user, line, out)
		}
		return
	}

	// Remote IP (αν υπάρχει)
	ip := ""
	if m := reIP.FindStringSubmatch(line); m != nil {
		ip = m[1]
	}

	// AUTH
	if proto == "esmtpa" || proto == "esmtpsa" {
		user := ""
		if m := reAuthUser.FindStringSubmatch(line); m != nil {
			user = m[1]
		}
		if user != "" {
			d.bump(now, string(KindAuthRelay)+"|user", user, line, out)
		}
		if ip != "" {
			d.bump(now, string(KindAuthRelay)+"|ip", ip, line, out)
		}
		if user != "" && ip != "" {
			d.bump(now, string(KindAuthRelay)+"|userip", ip+"/"+user, line, out)
		}
		return
	}

	// UNAUTH relay
	if proto == "esmtp" || proto == "esmtps" {
		if ip != "" {
			d.bump(now, string(KindRelay)+"|ip", ip, line, out)
		}
		return
	}
}






//func bump
func (d *Relays) bump(now time.Time, kindKey, key, line string, out chan<- core.Alert) {
	// sliding window count
	n := d.counts.Add(kindKey+":"+key, now)

	// samples per key
	d.mu.Lock()
	sk := kindKey + ":" + key
	if _, ok := d.samples[sk]; !ok {
		d.samples[sk] = make([]string, 0, d.cfg.SampleLimit)
	}
	if len(d.samples[sk]) < d.cfg.SampleLimit {
		d.samples[sk] = append(d.samples[sk], line)
	}
	d.mu.Unlock()

	// aggregate για αυτό το RunOnce
	if d.pending == nil {
		d.pending = make(map[string]pend)
	}
	d.pending[sk] = pend{kindKey: kindKey, key: key, n: n}
}

//fun bump end

// επιστρέφει threshold, alert kind και *βασικό* alertKey (χωρίς enrichment)
func (d *Relays) thresholdAndKey(kindKey, key string) (int, core.AlertKind, string) {
	switch kindKey {
	case string(KindLocalRelay):
		return d.cfg.LocalUserMax, KindLocalRelay, "Local Account - " + key
	case string(KindAuthRelay) + "|user":
		return d.cfg.AuthUserMax, KindAuthRelay, "user " + key
	case string(KindAuthRelay) + "|ip":
		return d.cfg.AuthIPMax, KindAuthRelay, "ip " + key
	case string(KindAuthRelay) + "|userip":
		return d.cfg.AuthUserIPMax, KindAuthRelay, "ip/user " + key
	case string(KindRelay) + "|ip":
		return d.cfg.UnauthIPMax, KindRelay, "ip " + key
	}
	return 0, "", key
}

// εμπλουτισμός displayKey (Geo/ASN/PTR) όπου υπάρχει IP
func (d *Relays) enrichDisplay(kindKey, alertKey, rawKey string) string {
	displayKey := alertKey
	if !(strings.HasPrefix(kindKey, string(KindRelay)) || strings.Contains(kindKey, "|ip")) {
		return displayKey
	}
	if !(d.cfg.UseEnrich || d.cfg.UsePTR) {
		return displayKey
	}

	// extract IP από rawKey ("1.2.3.4" ή "1.2.3.4/user")
	ip := rawKey
	if i := strings.IndexByte(ip, '/'); i > 0 {
		ip = ip[:i]
	}
	if ip == "" {
		return displayKey
	}
	if meta := d.lookupMeta(ip); meta != "" {
		switch {
		case strings.HasPrefix(displayKey, "ip/user "):
			rest := displayKey[len("ip/user "):]
			if i := strings.IndexByte(rest, '/'); i > 0 {
				return "ip/user " + ip + " (" + meta + ")/" + rest[i+1:]
			}
			return displayKey
		case strings.HasPrefix(displayKey, "ip "):
			return "ip " + ip + " (" + meta + ")"
		default:
			return displayKey + " (" + meta + ")"
		}
	}
	return displayKey
}







func (d *Relays) cool(sk string, now time.Time) bool {
	last, ok := d.lastFire[sk]
	if ok && now.Sub(last) < d.cfg.Cooldown {
		return false
	}
	d.lastFire[sk] = now
	return true
}

// ---- window counter ----

type windowCounter struct {
	mu     sync.Mutex
	window time.Duration
	events map[string][]time.Time
}

func newWindowCounter(d time.Duration) *windowCounter {
	return &windowCounter{
		window: d,
		events: make(map[string][]time.Time),
	}
}

func (w *windowCounter) Add(key string, t time.Time) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	ts := append(w.events[key], t)
	cut := t.Add(-w.window)
	i := 0
	for i < len(ts) && ts[i].Before(cut) {
		i++
	}
	ts = ts[i:]
	w.events[key] = ts
	return len(ts)
}

// ---- helpers ----

func autoDetectEximLog() string {
    // 1) γνωστά paths
    paths := []string{
        "/var/log/exim_mainlog",
        "/var/log/exim4/mainlog",
        "/var/log/exim/mainlog",
    }
    for _, p := range paths {
        if _, err := os.Stat(p); err == nil {
            return p
        }
    }

    // 2) scan /var/log
    var found string
    _ = filepath.Walk("/var/log", func(path string, info os.FileInfo, err error) error {
        if err != nil || info.IsDir() {
            return nil
        }
        base := filepath.Base(path)
        if base != "exim_mainlog" && base != "mainlog" {
            return nil
        }
        // ελαφρύ check ότι είναι όντως exim log
        out, _ := exec.Command("/bin/sh", "-lc", fmt.Sprintf("head -n1 %q | grep -qi exim", path)).CombinedOutput()
        if len(out) == 0 { // grep -q -> no output on match
            found = path
            return filepath.SkipDir // σταμάτα νωρίς
        }
        return nil
    })
    return found
}



func (d *Relays) lookupMeta(ip string) string {
    if ip == "" {
        return ""
    }

    var country, city, ptr, asname string
    var asn uint

    // 1) enrich package (PTR+ASN+City με cache 1h)
    if d.enr != nil {
        r := d.enr.Lookup(ip)
        if r.Country != "" { country = r.Country }   // μπορεί να είναι όνομα ή ISO (όπως το γεμίζεις εσύ)
        if r.City != "" { city = r.City }
        if r.PTR != "" { ptr = strings.TrimSuffix(r.PTR, ".") }
        if r.ASN > 0 {
            asn = r.ASN
            asname = r.ASNName
        }
    }

    // 2) PTR fallback αν ζητήθηκε και δεν ήρθε από το enrich
    if d.cfg.UsePTR && ptr == "" {
        names, _ := net.LookupAddr(ip)
        if len(names) > 0 {
            ptr = strings.TrimSuffix(names[0], ".")
        }
    }

    // compose
    geo := ""
    if country != "" || city != "" {
        if country == "" { country = "-" }
        if city == "" { city = "-" }
        geo = country + "/" + city
    }

    as := ""
    if asn > 0 && asname != "" {
        as = fmt.Sprintf("[AS%d %s", asn, asname)
    } else if asn > 0 {
        as = fmt.Sprintf("[AS%d", asn)
    }
    if ptr != "" {
        if as != "" { as += "; PTR " + ptr + "]" } else { as = "[PTR " + ptr + "]" }
    } else if as != "" {
        as += "]"
    }

    if geo != "" && as != "" {
        return geo + "/" + as
    }
    if geo != "" {
        return geo
    }
    return as // ίσως μόνο PTR
}


// keep last 6 lines for comments
func (d *Relays) pushRecent(line string) {
    const max = 6
    d.recent = append(d.recent, line)
    if len(d.recent) > max {
        d.recent = d.recent[len(d.recent)-max:]
    }
}



var (
    reCwd = regexp.MustCompile(`\bcwd=([^\s]+)`)
    reUid = regexp.MustCompile(`\buid=(\d+)\b`)
)

func looksWebRoot(cwd string) bool {
    // πολύ απλή ευρετική – μπορείς να προσθέσεις patterns
    patterns := []string{"/public_html", "/httpdocs", "/htdocs", "/var/www", "/www/", "/site/htdocs"}
    for _, p := range patterns {
        if strings.Contains(cwd, p) {
            return true
        }
    }
    return false
}

// Αναζήτησε στα 3-4 προηγούμενα lines στοιχεία που μαρτυρούν PHP/web
func (d *Relays) guessPHP() (bool, string, string) {
    for i := len(d.recent) - 1; i >= 0 && i >= len(d.recent)-4; i-- {
        line := d.recent[i]
        if !strings.Contains(line, "cwd=") {
            continue
        }
        var cwd, uid string
        if m := reCwd.FindStringSubmatch(line); len(m) > 1 {
            cwd = m[1]
        }
        if m := reUid.FindStringSubmatch(line); len(m) > 1 {
            uid = m[1]
        }
        if cwd != "" && looksWebRoot(cwd) {
            return true, cwd, uid
        }
    }
    return false, "", ""
}






// extract and decode Exim T="..." subject to readable UTF-8
func decodeSubjectFromLine(line string) string {
	raw, ok := extractEximQuoted(line, `T="`)
	if !ok || raw == "" {
		return ""
	}
	// 1) Unescape C-style (octal, \" etc) -> bytes
	b := unescapeExim(raw)

	// 2) UTF-8 (fallback ISO-8859-7)
	var s string
	if utf8.Valid(b) {
		s = string(b)
	} else {
		if dec, err := charmap.ISO8859_7.NewDecoder().Bytes(b); err == nil {
			s = string(dec)
		} else {
			s = string(b) // last resort
		}
	}

	// 3) RFC 2047 encoded-words (=?...?=) αν υπάρχουν
	if hasRFC2047(s) {
		wd := new(mime.WordDecoder)
		if decoded, err := wd.DecodeHeader(s); err == nil && decoded != "" {
			s = decoded
		}
	}

	// 4) HTML entities
	s = html.UnescapeString(s)

	return s
}

// Find a quoted field that starts at key (e.g. `T="`) and returns inner content with escapes still present.
func extractEximQuoted(s, key string) (string, bool) {
	i := strings.Index(s, key)
	if i < 0 {
		return "", false
	}
	// start after key
	i += len(key)
	var out []byte
	esc := false
	for ; i < len(s); i++ {
		c := s[i]
		if esc {
			out = append(out, '\\', c) // keep escapes for unescape step
			esc = false
			continue
		}
		if c == '\\' {
			esc = true
			continue
		}
		if c == '"' {
			// end of quoted string
			return string(out), true
		}
		out = append(out, c)
	}
	return string(out), true // tolerate missing closing quote
}

// Convert Exim-style escapes to raw bytes.
// Supports: \ooo (octal, up to 3 digits), \n \r \t \\ \" and \xHH (optional)
func unescapeExim(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			out = append(out, s[i])
			continue
		}
		// escape
		i++
		if i >= len(s) {
			out = append(out, '\\')
			break
		}
		switch s[i] {
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case '\\':
			out = append(out, '\\')
		case '"':
			out = append(out, '"')
		case 'x', 'X':
			// \xHH
			if i+2 < len(s) {
				h1 := hexVal(s[i+1])
				h2 := hexVal(s[i+2])
				if h1 >= 0 && h2 >= 0 {
					out = append(out, byte(h1<<4|h2))
					i += 2
					break
				}
			}
			// fallback: keep literally
			out = append(out, 'x')
		default:
			// octal \ooo (up to 3 digits)
			if s[i] >= '0' && s[i] <= '7' {
				val := int(s[i] - '0')
				read := 1
				for read < 3 && i+read < len(s) {
					c := s[i+read]
					if c < '0' || c > '7' {
						break
					}
					val = (val << 3) | int(c-'0')
					read++
				}
				out = append(out, byte(val))
				i += read - 1
			} else {
				// unknown escape -> keep as-is
				out = append(out, s[i])
			}
		}
	}
	return out
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func hasRFC2047(s string) bool {
	// very loose check
	return strings.Contains(s, "=?") && strings.Contains(s, "?=")
}
