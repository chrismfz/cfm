package detectors

import (
	"bufio"
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
			path := cfg.LogPath
			if path == "" || strings.EqualFold(path, "auto") {
				// common locations (cPanel / RHEL / Debian / Nginx / Virtualmin; include audit logs)
				candidates := []string{
					"/usr/local/apache/logs/error_log",        // cPanel Apache error
					"/usr/local/apache/logs/modsec_audit.log", // cPanel audit (often JSON)
					"/var/log/httpd/error_log",                // RHEL/CentOS Apache error
					"/var/log/httpd/modsec_audit.log",         // RHEL audit
					"/var/log/apache2/error.log",              // Debian/Ubuntu Apache error
					"/var/log/modsec_audit.log",               // generic audit
					"/var/log/modsecurity/audit.log",          // generic audit
					"/var/log/nginx/error.log",                // Nginx + ModSec v3 error
					"/var/log/nginx/modsec_audit.log",         // Nginx audit
					"/var/log/virtualmin/error_log",           // sometimes aggregated
				}
				best := ""
				bestHits := 0
				for _, p := range candidates {
					if st, err := os.Stat(p); err == nil && !st.IsDir() {
						h, _ := scoreFile(p, 2*1024*1024) // tail ~2MiB
						if h > bestHits {
							best, bestHits = p, h
						}
					}
				}
				if best != "" && bestHits >= 1 {
					logging.Logf("[detectors][modsec] autodetect: using %s (hits=%d)", best, bestHits)
					src := core.NewFileTailer(best)
					d.SetSource(src)
					// resume state (unique key per section+path)
					if modsecState != nil {
						key := core.FileStateKey(section, best)
						d.SetState(modsecState, key)
					}
					return d, nil
				}
				logging.Logf("[detectors][modsec] autodetect: no suitable log source found; set LOG_PATH explicitly")
				return d, nil
			}
			// explicit path
			logging.Logf("[detectors][modsec] using log: %s", path)
			src := core.NewFileTailer(path)
			d.SetSource(src)
			if modsecState != nil {
				key := core.FileStateKey(section, path)
				d.SetState(modsecState, key)
			}
			return d, nil
		}

		// Unknown mode → conservative
		logging.Logf("[detectors][modsec] unknown MODE=%q; use MODE=file or MODE=auto", cfg.Mode)
		return d, nil
	})
}
