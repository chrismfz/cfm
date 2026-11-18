package detectors

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/meta"
	"cfm/internal/detectors/modsec"
	"cfm/internal/logging"
)

// shared state for detectors
var modsecState = core.DefaultState()

var (
	modsecQuick403 = regexp.MustCompile(`ModSecurity:\s+Access denied with code 403`)
	jsonHTTP403    = regexp.MustCompile(`"http_code"\s*:\s*403`)
	jsonDenied     = regexp.MustCompile(`"action"\s*:\s*"access denied"`)
)

func scoreFile(path string, maxTail int64) (hits int, _ error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil || st.IsDir() {
		return 0, io.EOF
	}
	start := st.Size() - maxTail
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return 0, err
	}

	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 128*1024)
	sc.Buffer(buf, 2*1024*1024)

	for sc.Scan() {
		line := sc.Text()
		if modsecQuick403.MatchString(line) || jsonHTTP403.MatchString(line) || jsonDenied.MatchString(line) {
			hits++
		}
	}
	return hits, nil
}

// modsecCandidates are the error/audit logs MODE=auto scans, in tie-break
// order (the first wins on equal hits, and on no hits at all the first that
// exists). /var/log/apache2/error_log is cPanel EA4's real path: EA4 links
// /usr/local/apache/logs -> /etc/apache2/logs -> /var/log/apache2, so on EA4
// the first two name one file. It is SUSE's Apache error log as well.
var modsecCandidates = []string{
	"/usr/local/apache/logs/error_log",        // cPanel Apache error
	"/var/log/apache2/error_log",              // cPanel EA4 real path / SUSE
	"/var/log/httpd/error_log",                // RHEL/CentOS/DirectAdmin Apache error
	"/var/log/apache2/error.log",              // Debian/Ubuntu Apache error
	"/usr/local/apache/logs/modsec_audit.log", // cPanel audit (often JSON)
	"/var/log/httpd/modsec_audit.log",         // RHEL audit
	"/var/log/modsec_audit.log",               // generic audit
	"/var/log/modsecurity/audit.log",          // generic audit
	"/var/log/nginx/error.log",                // Nginx + ModSec v3 error
	"/var/log/nginx/modsec_audit.log",         // Nginx audit
	"/var/log/virtualmin/error_log",           // sometimes aggregated
}

// modsecResolution is what resolveModsecLogPath picked and why. Path "" means
// no source: the detector builds but idles.
type modsecResolution struct {
	Path   string
	Reason string
	Warn   string // non-empty: log it (an explicit path missing in MODE=auto)
}

// modsecStat reports whether path is an existing regular file.
func modsecStat(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// resolveModsecLogPath picks the file the [modsec] section tails.
//
//   - MODE=file with a concrete LOG_PATH: that path, verbatim (an operator pin;
//     the tailer waits for it to appear).
//   - MODE=auto with a concrete LOG_PATH that exists: that path.
//   - MODE=auto with a concrete LOG_PATH that does NOT exist: warn and scan.
//     Stock confs up to 2026-11-18 shipped LOG_PATH = /var/log/apache2/error_log,
//     which only cPanel EA4 (and SUSE) have, and a live detectors.conf keeps
//     that line across upgrades: on a DirectAdmin / Debian / nginx host it
//     watched nothing. If the scan finds nothing either, the explicit path is
//     kept, so the section picks it up if it appears.
//   - MODE=auto with LOG_PATH empty / "auto": scan.
//
// The scan prefers the candidate with the most ModSecurity denials in its last
// 2 MiB; with none anywhere (a quiet host) it takes the first candidate that
// exists, so a fresh install still watches its web server's error log rather
// than nothing until the next restart. score is nil for a cheap, stat-only
// resolution (the source probe): then the first existing candidate is taken.
func resolveModsecLogPath(mode, logPath string, exists func(string) bool, score func(string, int64) (int, error)) modsecResolution {
	logPath = strings.TrimSpace(logPath)
	explicit := logPath != "" && !strings.EqualFold(logPath, "auto")
	if explicit && strings.EqualFold(mode, "file") {
		return modsecResolution{Path: logPath, Reason: "explicit LOG_PATH (MODE=file)"}
	}
	var warn string
	if explicit {
		if exists(logPath) {
			return modsecResolution{Path: logPath, Reason: "explicit LOG_PATH"}
		}
		warn = "LOG_PATH " + logPath + " does not exist; MODE=auto, scanning the known locations instead"
	}
	best, bestHits, first := "", 0, ""
	for _, p := range modsecCandidates {
		if !exists(p) {
			continue
		}
		if first == "" {
			first = p
		}
		if score == nil {
			break
		}
		if h, _ := score(p, 2*1024*1024); h > bestHits {
			best, bestHits = p, h
		}
	}
	switch {
	case best != "":
		return modsecResolution{Path: best, Reason: fmt.Sprintf("autodetect: most ModSecurity denials (hits=%d)", bestHits), Warn: warn}
	case first != "":
		return modsecResolution{Path: first, Reason: "autodetect: first existing candidate (no ModSecurity denials seen yet)", Warn: warn}
	case explicit:
		return modsecResolution{Path: logPath, Reason: "explicit LOG_PATH kept: no candidate exists either", Warn: warn}
	}
	return modsecResolution{Reason: "autodetect: no candidate log exists", Warn: warn}
}

// probeModsecSource is the source probe for a [modsec] section: the stat-only
// resolution, then a readability check of what it picked. It answers "is
// there a log to watch", not "which one": in a scan the register scores the
// candidates and may tail a busier one (SourceReport runs the scored
// resolution).
func probeModsecSource(kv KV) (bool, string) {
	mode := strings.ToLower(kvStrClean(kv, "MODE", "auto"))
	if mode != "file" && mode != "auto" {
		return false, "unknown MODE " + mode
	}
	res := resolveModsecLogPath(mode, kvStrClean(kv, "LOG_PATH", "auto"), modsecStat, nil)
	if res.Path == "" {
		return false, res.Reason
	}
	f, err := os.Open(res.Path) // #nosec G304 -- a fixed candidate or the admin's LOG_PATH.
	if err != nil {
		return false, "log file unreadable: " + err.Error()
	}
	_ = f.Close()
	msg := "log file readable: " + res.Path
	if strings.HasPrefix(res.Reason, "autodetect") {
		msg += " (first existing candidate; the detector tails the one with the most denials)"
	}
	if res.Warn != "" {
		msg += " (" + res.Warn + ")"
	}
	return true, msg
}

func init() {
	meta.Register(meta.DetectorMeta{
		TypeKey:           "modsec",
		Title:             "ModSecurity",
		Description:       "Detect WAF-denied traffic from ModSecurity logs.",
		DefaultsTemplate:  map[string]string{"ENABLED": "1", "MODE": "auto", "EVERY": "10s", "WINDOW": "10m", "COOLDOWN": "20m", "BLOCK": "dryrun"},
		LeniencySupported: true,
	})
	Register("modsec", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 2*time.Second)
		defWindow := kvDur(global, "DEFAULT_WINDOW", 15*time.Minute)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)

		rawDirs := kvStrClean(kv, "ENRICH_DIRS", kvStr(global, "ENRICH_DIRS", ""))
		var dirs []string
		if rawDirs != "" {
			fields := strings.FieldsFunc(rawDirs, func(r rune) bool { return r == ',' || r == ':' || r == ' ' || r == '\t' })
			for _, f := range fields {
				if f != "" {
					dirs = append(dirs, f)
				}
			}
		}
		useEnrich := kvBool(kv, "ENRICH", kvBool(global, "ENRICH", true))
		usePTR := kvBool(kv, "PTR", kvBool(global, "PTR", true))

		cfg := modsec.Config{
			Mode:        strings.ToLower(kvStrClean(kv, "MODE", "auto")), // auto|file
			LogPath:     kvStrClean(kv, "LOG_PATH", "auto"),              // path|auto
			Every:       kvDur(kv, "EVERY", defEvery),
			Window:      kvDur(kv, "WINDOW", defWindow),
			Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),
			SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 10),
			ModsecPerIP: kvInt(kv, "MODSEC_IP", 20),
			UseEnrich:   useEnrich,
			UsePTR:      usePTR,
			EnrichDirs:  dirs,
		}

		d := modsec.New(cfg)
		d.SetName(section)

		// FILE-ONLY selection
		mode := strings.ToLower(cfg.Mode)
		if mode == "file" || mode == "auto" {
			res := resolveModsecLogPath(mode, cfg.LogPath, modsecStat, scoreFile)
			if res.Warn != "" {
				logging.Logf("[detectors][modsec] %s", res.Warn)
			}
			if res.Path == "" {
				logging.Logf("[detectors][modsec] %s; set LOG_PATH explicitly", res.Reason)
				return d, nil
			}
			logging.Logf("[detectors][modsec] using log: %s (%s)", res.Path, res.Reason)
			src := core.NewFileTailer(res.Path)
			d.SetSource(src)
			// resume state (unique key per section+path)
			if modsecState != nil {
				key := core.FileStateKey(section, res.Path)
				d.SetState(modsecState, key)
			}
			return d, nil
		}

		// Unknown mode → conservative
		logging.Logf("[detectors][modsec] unknown MODE=%q; use MODE=file or MODE=auto", cfg.Mode)
		return d, nil
	})
}
