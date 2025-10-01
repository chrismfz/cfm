package exim

import (
//	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
//	"syscall"
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

samples *core.SampleRing
gate    *core.AlertGate
counts  *core.SlidingCounter

	path     string               // effective path
	readyLog bool
	recent []string // last few lines to infer PHP context
	enr *enrich.Enricher //enrich output
	pending map[string]pend

	name string
	src  *core.FileTailer
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
        cfg.EnrichDirs = []string{"/etc/cfm", "/var/lib/cfm/maxmind"}
    }

    d := &Relays{ cfg: cfg }

    // init core window primitives
    d.samples = core.NewSampleRing(cfg.SampleLimit)
    d.gate    = core.NewAlertGate(cfg.Cooldown)
    d.counts  = core.NewSlidingCounter(cfg.Window, 0)

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



func (d *Relays) Every() time.Duration { return d.cfg.Every }

func (d *Relays) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	// fresh aggregation for this tick
	d.pending = make(map[string]pend)

	// 1) Ensure log path (one-off autodetect)
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

	// 2) Init non-blocking tailer (starts at "now" unless ApplyPosition set a resume)
	if d.src == nil {
		d.src = core.NewFileTailer(d.path)
	}

	// Open source (quietly skip if missing/rotating)
	if err := d.src.Open(); err != nil {
		return nil
	}
	defer d.src.Close()

	// 3) Read all newly appended lines and process
	now := time.Now()
	lines := 0
	for {
		line, err := d.src.ReadNext(ctx)
		if err == io.EOF {
			break // caught up
		}
		if err != nil {
			// transient read issue — bail out; next tick will retry
			break
		}
		lines++
		d.processLine(now, line, out)
	}

	// ---- 4) flush aggregated alerts (τέλος run) ----

nowSend := time.Now()
for _, p := range d.pending {
    thr, kind, baseKey := d.thresholdAndKey(p.kindKey, p.key)
    if thr <= 0 { continue }

    sk := p.kindKey + ":" + p.key
    n := d.counts.Count(sk, nowSend)
    if !d.gate.Allow(sk, nowSend, n, thr) { continue }

    // PHP guess stays unchanged
    isPHP, cwd, uid := false, "", ""
    if kind == KindLocalRelay {
        if ok, c, u := d.guessPHP(); ok {
            isPHP, cwd, uid = true, c, u
            baseKey += " (php)"
        }
    }

    displayKey := d.enrichDisplay(p.kindKey, baseKey, p.key)
    samples := d.samples.GetAndClear(sk)
    pretty  := make([]string, 0, len(samples)*2)
    for _, ln := range samples {
        pretty = append(pretty, ln)
        if subj := decodeSubjectFromLine(ln); subj != "" {
            pretty = append(pretty, "SUBJ: "+subj)
        }
    }

    extra := map[string]string{
        "log": d.path, "window": d.cfg.Window.String(),
        "cooldown": d.cfg.Cooldown.String(), "limit": strconv.Itoa(thr),
    }
    if isPHP {
        if cwd != "" { extra["cwd"] = cwd }
        if uid != "" { extra["uid"] = uid }
    }

    out <- core.Alert{
        When: nowSend, Kind: kind, Key: displayKey,
        Count: n, Samples: pretty, Extra: extra,
    }
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

func (d *Relays) bump(now time.Time, kindKey, key, line string, _ chan<- core.Alert) {
    sk := kindKey + ":" + key
    d.samples.Add(sk, line)
    _ = d.counts.Add(sk, now)
    if d.pending == nil { d.pending = make(map[string]pend) }
    d.pending[sk] = pend{kindKey: kindKey, key: key}
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








// ---- helpers ----



func autoDetectEximLog() string {
        paths := []string{"/var/log/exim_mainlog", "/var/log/exim4/mainlog", "/var/log/exim/mainlog"}
        for _, p := range paths {
                if _, err := os.Stat(p); err == nil { return p }
        }
        var found string
        _ = filepath.Walk("/var/log", func(path string, info os.FileInfo, err error) error {
                if err != nil || info.IsDir() { return nil }
                base := filepath.Base(path)
                if base != "exim_mainlog" && base != "mainlog" { return nil }
                out, _ := exec.Command("/bin/sh", "-lc", fmt.Sprintf("head -n1 %q | grep -qi exim", path)).CombinedOutput()
                if len(out) == 0 { found = path; return filepath.SkipDir }
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





func (d *Relays) SetName(n string) { d.name = n }

func (d *Relays) setSource(src *core.FileTailer) { d.src = src }

// --- PositionAware implementation ---

func (d *Relays) Name() string { 
    if d.name != "" { return d.name }
    return "exim/relays" // fallback
}

func (d *Relays) ApplyPosition(p core.Position) {
    if d.src != nil {
        d.src.ApplyResume(p.Inode, p.Offset) // resume from saved inode/offset
    }
}

func (d *Relays) Position() core.Position {
    if d.src == nil {
        return core.Position{}
    }
    off, ino, ts := d.src.Position()
    return core.Position{Offset: off, Inode: ino, TS: ts}
}
