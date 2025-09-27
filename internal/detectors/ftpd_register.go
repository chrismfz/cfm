package detectors

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/ftpd"
	"cfm/internal/logging"
)

/*
Autodetect strategy
- Prefer journald if a known unit emits ftp failure lines (fast probe).
- If probe sees nothing, but a unit is ACTIVE → use that unit anyway (log it).
- Else score candidate files by scanning the last ~2 MiB:
    * prefer files with more fail hits; tie-break on daemon mentions.
- If nothing convincing, log a hint and return without wiring a source.
*/

// Genuine ftp failure-ish line (daemon + fail verb)
var ftpQuick = regexp.MustCompile(`(?i)\b(pure-?ftpd|vsftpd|proftpd|cpanel_ftp_auth)\b.*\b(fail|failed|violation|denied|authentication failure|maximum login)\b`)
// Genuine ftp daemon mention (even without failure words)
var ftpDaemon = regexp.MustCompile(`(?i)\b(pure-?ftpd|vsftpd|proftpd|cpanel_ftp_auth)\b`)
// Hard exclude: ssh noise (e.g., "sshd: Invalid user ftpuser …")
var sshNoise = regexp.MustCompile(`\bsshd\b`)

// read the last N bytes and count ftp daemon lines and failure lines (excluding sshNoise)
func scoreFTPFile(path string, maxTailBytes int64) (daemonHits, failHits int, _ error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil || st.IsDir() {
		return 0, 0, io.EOF
	}
	start := st.Size() - maxTailBytes
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return 0, 0, err
	}

	sc := bufio.NewScanner(f)
	// allow long syslog lines
	buf := make([]byte, 0, 128*1024)
	sc.Buffer(buf, 512*1024)

	for sc.Scan() {
		line := sc.Text()
		if sshNoise.MatchString(line) {
			continue
		}
		if ftpDaemon.MatchString(line) {
			daemonHits++
			if ftpQuick.MatchString(line) {
				failHits++
			}
		}
	}
	return daemonHits, failHits, nil
}

// open a journal tailer and see if we get an ftpQuick line within deadline
func probeJournalUnit(unit string, deadline time.Duration) bool {
	j := core.NewJournalTailer(unit)
	if err := j.Open(); err != nil {
		return false
	}
	defer j.Close()

	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	for {
		line, err := j.ReadNext(ctx)
		if err != nil {
			break
		}
		if sshNoise.MatchString(line) {
			continue
		}
		if ftpQuick.MatchString(line) {
			return true
		}
	}
	return false
}

// isUnitActive returns true if `systemctl is-active --quiet <unit>` succeeds.
func isUnitActive(unit string) bool {
	cmd := exec.Command("systemctl", "is-active", "--quiet", unit)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func init() {
	Register("ftpd", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		// cadence defaults from [global]
		defEvery := kvDur(global, "DEFAULT_EVERY", 2*time.Second)
		defWindow := kvDur(global, "DEFAULT_WINDOW", 15*time.Minute)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)

		// enrichment defaults from [global], allow per-section override
		rawDirs := kvStrClean(kv, "ENRICH_DIRS", kvStrClean(global, "ENRICH_DIRS", ""))
		var dirs []string
		if rawDirs != "" {
			fields := strings.FieldsFunc(rawDirs, func(r rune) bool {
				return r == ',' || r == ':' || r == ' ' || r == '\t'
			})
			for _, f := range fields {
				if f != "" {
					dirs = append(dirs, f)
				}
			}
		}
		useEnrich := kvBool(kv, "ENRICH", kvBool(global, "ENRICH", true))
		usePTR := kvBool(kv, "PTR", kvBool(global, "PTR", true))

		cfg := ftpd.Config{
			Mode:            strings.ToLower(kvStrClean(kv, "MODE", "auto")), // auto|file|journal
			LogPath:         kvStrClean(kv, "LOG_PATH", "auto"),              // path|auto
			JournalUnit:     kvStrClean(kv, "JOURNAL_UNIT", "auto"),          // unit|auto
			Every:           kvDur(kv, "EVERY", defEvery),
			Window:          kvDur(kv, "WINDOW", defWindow),
			Cooldown:        kvDur(kv, "COOLDOWN", defCooldown),
			SampleLimit:     kvInt(kv, "SAMPLE_LIMIT", 10),
			AuthFailPerIP:   kvInt(kv, "AUTHFAIL_IP", 20),
			AuthFailPerUser: kvInt(kv, "AUTHFAIL_USER", 10),
			UseEnrich:       useEnrich,
			UsePTR:          usePTR,
			EnrichDirs:      dirs,
		}

		d := ftpd.NewAuth(cfg)
		d.SetName(section)

		mode := strings.ToLower(cfg.Mode)
		switch mode {
		case "journal", "auto":
			unit := strings.ToLower(cfg.JournalUnit)
			known := []string{"vsftpd.service", "pure-ftpd.service", "proftpd.service"}

			if unit != "" && unit != "auto" {
				// explicit unit: prefer probe; else accept if active
				if probeJournalUnit(unit, 800*time.Millisecond) || isUnitActive(unit) {
					if !probeJournalUnit(unit, 0) && isUnitActive(unit) {
						logging.Logf("[detectors][ftpd] journal: using %s (active; no recent lines seen yet)", unit)
					} else {
						logging.Logf("[detectors][ftpd] journal: using %s", unit)
					}
					d.SetSource(core.NewJournalTailer(unit))
					// (5) PASS DAEMON HINT from unit name
					switch {
					case strings.Contains(unit, "vsftpd"):
						d.SetDaemon("vsftpd")
					case strings.Contains(unit, "proftpd"):
						d.SetDaemon("proftpd")
					case strings.Contains(unit, "pure-ftpd"), strings.Contains(unit, "pureftpd"):
						d.SetDaemon("pure-ftpd")
					}

					return d, nil
				}
			} else {
				// auto: try probe first
				for _, u := range known {
					if probeJournalUnit(u, 800*time.Millisecond) {
						logging.Logf("[detectors][ftpd] autodetect: using journal unit %s", u)
						d.SetSource(core.NewJournalTailer(u))
						if strings.Contains(u, "vsftpd") { d.SetDaemon("vsftpd") }
						if strings.Contains(u, "proftpd") { d.SetDaemon("proftpd") }
						if strings.Contains(u, "pure-ftpd") || strings.Contains(u, "pureftpd") { d.SetDaemon("pure-ftpd") }

						return d, nil
					}
				}
				// no probe hits → fall back to any active unit
				for _, u := range known {
					if isUnitActive(u) {
						logging.Logf("[detectors][ftpd] autodetect: using journal unit %s (active; no recent lines seen yet)", u)
						d.SetSource(core.NewJournalTailer(u))
						if strings.Contains(u, "vsftpd") { d.SetDaemon("vsftpd") }
						if strings.Contains(u, "proftpd") { d.SetDaemon("proftpd") }
						if strings.Contains(u, "pure-ftpd") || strings.Contains(u, "pureftpd") { d.SetDaemon("pure-ftpd") }
						return d, nil
					}
				}
			}
			// no journal source matched → try files
			fallthrough

		case "file":
			path := cfg.LogPath
			if path == "" || strings.EqualFold(path, "auto") {
				// score candidates; choose best using failHits first, else daemonHits
				candidates := []string{
					"/var/log/messages",
					"/var/log/maillog",
					"/var/log/auth.log",
					"/var/log/proftpd/proftpd.log",
					"/var/log/pure-ftpd/transfer.log",
					"/var/log/secure", // guarded by scoring
				}
				best := ""
				bestFail, bestDaemon := 0, 0
				for _, p := range candidates {
					if st, err := os.Stat(p); err == nil && !st.IsDir() {
						dHits, fHits, _ := scoreFTPFile(p, 2*1024*1024) // tail ~2 MiB
						if fHits > bestFail || (fHits == bestFail && dHits > bestDaemon) {
							best, bestFail, bestDaemon = p, fHits, dHits
						}
					}
				}
				// Accept if there is ANY daemon signal (even if no recent fails)
				if best != "" && (bestFail >= 1 || bestDaemon >= 1) {
					if bestFail >= 1 {
						logging.Logf("[detectors][ftpd] autodetect: using %s (fail_hits=%d, daemon_hits=%d)", best, bestFail, bestDaemon)
					} else {
						logging.Logf("[detectors][ftpd] autodetect: using %s (daemon_hits=%d, no recent failures; monitoring)", best, bestDaemon)
					}
					d.SetSource(core.NewFileTailer(best))
					// (5) PASS DAEMON HINT from path heuristic
					lb := strings.ToLower(best)
					switch {
					case strings.Contains(lb, "vsftpd"):
						d.SetDaemon("vsftpd")
					case strings.Contains(lb, "proftpd"):
						d.SetDaemon("proftpd")
					case strings.Contains(lb, "pure-ftpd"), strings.Contains(lb, "pureftpd"):
						d.SetDaemon("pure-ftpd")
					}
					return d, nil
				}
				logging.Logf("[detectors][ftpd] autodetect: no suitable log source found; set LOG_PATH or JOURNAL_UNIT explicitly")
				return d, nil
			}
			// explicit file path
			d.SetSource(core.NewFileTailer(path))
			// best effort daemon hint from explicit path
			lb := strings.ToLower(path)
			if strings.Contains(lb, "vsftpd") { d.SetDaemon("vsftpd") }
			if strings.Contains(lb, "proftpd") { d.SetDaemon("proftpd") }
			if strings.Contains(lb, "pure-ftpd") || strings.Contains(lb, "pureftpd") { d.SetDaemon("pure-ftpd") }
			return d, nil

		default:
			logging.Logf("[detectors][ftpd] unknown MODE=%q; try MODE=auto or set LOG_PATH/JOURNAL_UNIT", cfg.Mode)
			return d, nil
		}
	})
}
