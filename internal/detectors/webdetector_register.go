// internal/detectors/webdetector_register.go
package detectors

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cfm/internal/apiserver"
	core "cfm/internal/detectors/core"
	"cfm/internal/logging"
	webdet "cfm/internal/webdetector"
)

// webdetectorWrapped ensures that background servers (API + challenge)
// are tied to the manager's ctx, so they STOP on reload.
// Without this, hot-reload can leave orphan listeners serving a stale snapshot.
type webdetectorWrapped struct {
	eng       *webdet.Engine
	cfg       webdet.Config
	startOnce sync.Once

	// Global ignore (from [global] IGNORE_IPS/IGNORE_NETS)
	ipIgnore *IPIgnore

	// Track background servers so hot-reload waits for ports to be free.
	srvWG    sync.WaitGroup
	stopOnce sync.Once
	chalSrv  *webdet.ChallengeServer

	// challenge redirect rules can be lost if firewall reloads/recreates tables.
	// Re-ensure periodically from RunOnce as a self-healing watchdog.
	lastEnsureMu sync.Mutex
	lastEnsure   time.Time

	// External alerts coming from background components (e.g. challenge server
	// abuse self-protection). These are drained into the normal RunOnce(out)
	// channel so the section sink (API/firewall/notifier + our logs) handles them.
	extMu   sync.Mutex
	extQ    chan core.Alert
	extDrop uint64
}

var (
	webdetRoutesOnce sync.Once
	webdetRoutesMu   sync.RWMutex
	webdetRoutesH    http.Handler = http.NotFoundHandler()
)

func setWebdetRoutesHandler(h http.Handler) {
	if h == nil {
		h = http.NotFoundHandler()
	}
	webdetRoutesMu.Lock()
	webdetRoutesH = h
	webdetRoutesMu.Unlock()
}

func webdetRoutesProxy(w http.ResponseWriter, r *http.Request) {
	webdetRoutesMu.RLock()
	h := webdetRoutesH
	webdetRoutesMu.RUnlock()
	h.ServeHTTP(w, r)
}

func (w *webdetectorWrapped) enqueueExternal(a core.Alert) {
	if w == nil {
		return
	}
	w.extMu.Lock()
	q := w.extQ
	w.extMu.Unlock()
	if q == nil {
		return
	}
	select {
	case q <- a:
	default:
		// bounded queue: drop if overloaded (still log once in a while)
		w.extMu.Lock()
		w.extDrop++
		drops := w.extDrop
		w.extMu.Unlock()
		if drops == 1 || drops%1000 == 0 {
			ip := ""
			if a.Extra != nil {
				ip = a.Extra["ip"]
			}
			logging.Logf("[webdetector] external alert queue full: dropped=%d (kind=%s ip=%s)", drops, a.Kind, ip)
		}
	}
}

func (w *webdetectorWrapped) drainExternal(out chan<- core.Alert) {
	if out == nil {
		return
	}
	w.extMu.Lock()
	q := w.extQ
	w.extMu.Unlock()
	if q == nil {
		return
	}
	for {
		select {
		case a := <-q:
			out <- a
		default:
			return
		}
	}
}

func (w *webdetectorWrapped) Name() string         { return w.eng.Name() }
func (w *webdetectorWrapped) Every() time.Duration { return w.eng.Every() }

func (w *webdetectorWrapped) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	w.startOnce.Do(func() {
		SetNginxBridge(nil) // default (DNAT mode)

		// IMPORTANT:
		// ctx here is a per-run watchdog ctx (timeout) from runOnceSafeTimed.
		// If we bind background servers to it, they will be shut down at the end
		// of every tick and ports will never stay open.
		pctx := parentCtxFrom(ctx)
		if pctx == nil {
			pctx = ctx
		}

		// Build per-engine mux and hot-swap it behind a stable proxy route.
		// This avoids duplicate ServeMux registrations on detector reload while
		// still exposing the newest engine state through the shared apiserver.
		localMux := http.NewServeMux()
		w.eng.RegisterHTTP(localMux)
		setWebdetRoutesHandler(localMux)

		webdetRoutesOnce.Do(func() {
			apiserver.Register(func(m *http.ServeMux) {
				m.HandleFunc("/api/v1/webdet/", webdetRoutesProxy)
				m.HandleFunc("/api/v1/challenge/", webdetRoutesProxy)
				m.HandleFunc("/api/v1/waf/", webdetRoutesProxy)
			})
			logging.Logf("[webdetector] routes registered on shared apiserver")
		})
		logging.Logf("[webdetector] routes handler updated")

		if strings.TrimSpace(w.cfg.APIListen) != "" {
			logging.Logf("[webdetector] API_LISTEN is deprecated and ignored; using shared apiserver")
		}

		// NginxBridge decision socket — same lifecycle as API server
		if w.cfg.OpenRestyMode {

			// Disable nft dynamic DNAT challenge sets in OpenResty mode
			if fwBackend != nil {
				if t, ok := any(fwBackend).(interface{ SetChallengeDNATEnabled(bool) }); ok {
					t.SetChallengeDNATEnabled(false)
				} else if t, ok := any(fwBackend).(interface{ CleanupChallengeDNAT() error }); ok {
					_ = t.CleanupChallengeDNAT()
				}
			}

			if b := w.eng.NginxBridge(); b != nil {

				// expose to sinks so challenge enforcement uses bridge instead of fw.AddChallenge()
				SetNginxBridge(b)

				// ── NEW: wire bypass so handleDecision respects IGNORE_IPS/IGNORE_NETS ──
				if w.ipIgnore != nil {
					b.SetBypassFunc(w.ipIgnore.ShouldIgnore)
				}
				// ─────────────────────────────────────────────────

				go b.RunExpireLoop(pctx)
				w.srvWG.Add(1)
				go func() {
					defer w.srvWG.Done()
					if err := b.ServeDecisions(pctx); err != nil {
						logging.Logf("[webdetector] nginx bridge exited: %v", err)
					}
				}()
			}
		}

		// Challenge token source: detectors.conf [webdetector] CHALLENGE_TOKEN.
		// If unset, challenge server logs a warning and falls back to legacy default.
		webdet.SetChallengeToken(w.cfg.ChallengeToken)

		// Challenge server + nft redirect rules (ctx-bound)
		if w.cfg.ChallengeHTTPListen != "" || w.cfg.ChallengeHTTPSListen != "" {
			// initial ensure (best-effort)
			w.ensureChallengeRedirect("init")

			srv := webdet.NewChallengeServer(webdet.SSLCollector(), fwBackend)
			w.chalSrv = srv

			// Global ignore: [global] IGNORE_IPS / IGNORE_NETS
			if w.ipIgnore != nil {
				srv.SetIPIgnore(w.ipIgnore.ShouldIgnore, w.ipIgnore.LogIgnoredReports())
			}

			// Challenge abuse blocking knobs
			if w.cfg.ChallengeAbuseEnabled {
				srv.SetAbuseConfig(
					true,
					w.cfg.ChallengeAbuseWindow,
					w.cfg.ChallengeAbuseBadN,
					w.cfg.ChallengeAbuseBlockTTL,
					w.cfg.ChallengeAbuseCooldown,
				)
			}

			// Separate access log for [challenge_http] lines
			if w.cfg.ChallengeAccessLogPath != "" {
				srv.SetAccessLogPath(w.cfg.ChallengeAccessLogPath)
			}

			// Make cookie + OK TTL match configured cookie life
			if w.cfg.ChallengeCookieLife > 0 {
				srv.SetCookieLife(w.cfg.ChallengeCookieLife)
			}

			// OpenResty mode: wire bridge so solve → ClearIP instead of nft remove.
			if w.cfg.OpenRestyMode {
				if b := w.eng.NginxBridge(); b != nil {
					srv.SetNginxBridge(b)
				}
			}

			// Hook solved logging into detectors layer (adds enrichment + lets us emit "expired" elsewhere).
			webdet.SetChallengeSolvedHook(func(ip, host, uri string, diff int, ms int64) {
				// Best-effort enrichment using the same enricher as the engine.
				suffix := ""
				if enr := w.eng.Enricher(); enr != nil {
					r := enr.Lookup(ip)
					parts := []string{}
					if r.ASN > 0 {
						if r.ASNName != "" {
							parts = append(parts, fmt.Sprintf("AS%d %s", r.ASN, r.ASNName))
						} else {
							parts = append(parts, fmt.Sprintf("AS%d", r.ASN))
						}
					}
					if r.Country != "" {
						parts = append(parts, r.Country)
					}
					if len(parts) > 0 {
						suffix = " - (" + strings.Join(parts, ", ") + ")"
					}
				}

				// Look up WAF/detector reason BEFORE bridge.ClearIP() deletes the entry.
				// The hook is called before ClearIP in challenge_server.go, so this is safe.
				reason := ""
				if b := w.eng.NginxBridge(); b != nil {
					reason = b.GetReason(ip)
				}
				reasonPart := ""
				if reason != "" {
					reasonPart = " reason=" + reason
				}

				logging.LogfCHALLENGES(
					"[challenge] ip=%s host=%s uri=%s result=solved ms=%d diff=%d%s%s",
					ip, host, uri, ms, diff, reasonPart, suffix,
				)

				// Record solve in challenge API store (best-effort)
				w.eng.RecordChallengeSolved(ip, host, uri, diff, ms)

			})

			// Hook WAF trigger events (from cfm_waf.lua via POST /nginx/ip with a reason)
			// into cfm.challenges.log so trigger + solved appear in the same log.
			// action = "challenge" or "block"; reason = "WAF_XSS", "WAF_TRAVERSAL", etc.
			if b := w.eng.NginxBridge(); b != nil {
				b.SetTriggerHook(func(ip, action, reason string, ttl time.Duration, host, uri, method string) {
					suffix := ""
					var asn uint
					var asnName, country string
					if enr := w.eng.Enricher(); enr != nil {
						r := enr.Lookup(ip)
						asn = r.ASN
						asnName = r.ASNName
						country = r.Country
						parts := []string{}
						if r.ASN > 0 {
							if r.ASNName != "" {
								parts = append(parts, fmt.Sprintf("AS%d %s", r.ASN, r.ASNName))
							} else {
								parts = append(parts, fmt.Sprintf("AS%d", r.ASN))
							}
						}
						if r.Country != "" {
							parts = append(parts, r.Country)
						}
						if len(parts) > 0 {
							suffix = " - (" + strings.Join(parts, ", ") + ")"
						}
					}

					// Optional meta fields from Lua (host/uri/method)
					// Keep same format as CHALLENGE_* lines when available.
					meta := ""
					if host != "" {
						meta += " host=" + host
					}
					if uri != "" {
						meta += " uri=" + uri
					}
					if method != "" {
						meta += " method=" + method
					}

					logging.LogfWAF(
						"[waf_engine] ip=%s%s result=%s reason=%s ttl=%s%s",
						ip,
						meta,
						action+"_triggered",
						reason,
						ttl.String(),
						suffix,
					)
					w.eng.RecordWAFTrigger(ip, host, uri, method, action, reason, ttl, asn, asnName, country)

				})

				// NEW: Hook per-request observations (e.g. OpenResty WAF returned 403)
				// into the webdetector engine so the existing "403 after X tries"
				// logic can escalate to firewall blocks normally (no double log parsing).
				b.SetObserveHook(func(ip, host, uri, method string, status int, reason string) {
					// Non-blocking: InjectObserved takes e.mu.Lock but returns fast.
					// Called from bridge's HTTP handler goroutine; must not block.
					w.eng.InjectObserved(ip, host, uri, method, status, reason)
				})

			}

			// Hook challenge-server abuse into the unified detector sink.
			// This produces a new alert kind: WEB/CHALLENGE_SERVER_ABUSE
			webdet.SetChallengeAbuseHook(func(ip, host, uri string, status int, badN int, window, blockTTL, cooldown time.Duration) {
				now := time.Now()
				a := core.Alert{
					Kind:    "WEB/CHALLENGE_SERVER_ABUSE",
					Key:     ip,
					When:    now,
					Count:   badN,
					Samples: []string{fmt.Sprintf("[challenge_abuse] ip=%s host=%s bad>=%d window=%s status=%d uri=%s block_ttl=%s cooldown=%s", ip, host, badN, window.String(), status, uri, blockTTL.String(), cooldown.String())},
					Extra: map[string]string{
						"ip":        ip,
						"host":      host,
						"uri":       uri,
						"status":    fmt.Sprintf("%d", status),
						"badN":      fmt.Sprintf("%d", badN),
						"window":    window.String(),
						"block_ttl": blockTTL.String(),
						"cooldown":  cooldown.String(),
						"reason":    "challenge_server_abuse",
					},
				}
				w.enqueueExternal(a)
			})

			// Start in goroutine so RunOnce never blocks. Also detect if Start()
			// stalls with a small timeout (best-effort watchdog).
			started := make(chan error, 1)
			w.srvWG.Add(1)
			go func() {
				defer w.srvWG.Done()
				started <- srv.Start(pctx, w.cfg.ChallengeHTTPListen, w.cfg.ChallengeHTTPSListen)
			}()

			select {
			case err := <-started:
				if err != nil {
					logging.Logf("[webdetector] challenge server start failed: %v", err)
				}
			case <-time.After(5 * time.Second):
				logging.Logf("[webdetector] challenge server start timeout (still starting)")
			}

		}
	})

	// Watchdog: re-ensure redirect rules periodically to recover from
	// nft table reloads (e.g. autoblock/loadAll paths).
	if w.cfg.ChallengeHTTPListen != "" || w.cfg.ChallengeHTTPSListen != "" {
		w.ensureChallengeRedirect("tick")
	}

	// Flush any external alerts that were queued by background components
	// (e.g. challenge-server abuse), before we do the ingest pass.
	w.drainExternal(out)

	err := w.eng.RunOnce(ctx, out)

	// Drain again after ingest pass (in case abuse triggers during RunOnce()).
	w.drainExternal(out)

	// On shutdown (reload), wait for background servers to actually exit so
	// ports are free before the new instance starts.
	// Use the long-lived parent ctx, not the per-run ctx.
	pctx := parentCtxFrom(ctx)
	if pctx == nil {
		pctx = ctx
	}

	if pctx.Err() != nil {
		w.stopOnce.Do(func() {
			SetNginxBridge(nil) // avoid stale pointer after reload
			webdet.SetChallengeAbuseHook(nil)
			if b := w.eng.NginxBridge(); b != nil {
				b.SetTriggerHook(nil)
				b.SetObserveHook(nil)
			}
			waitCtx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()

			if w.chalSrv != nil {
				_ = w.chalSrv.Wait(waitCtx)
			}

			done := make(chan struct{})
			go func() {
				w.srvWG.Wait()
				close(done)
			}()

			select {
			case <-done:
			case <-waitCtx.Done():
				logging.Logf("[webdetector] server shutdown wait timeout")
			}
		})
	}

	return err

}

type folderScanStats struct {
	DirsSeen      int
	FilesSeen     int
	MatchedFiles  int
	StateHits     int
	SampleMatched []string
}

func scanFolderSourceForDebug(dir, glob string, recursive bool, st *core.State, section string) folderScanStats {
	stats := folderScanStats{}
	if strings.TrimSpace(glob) == "" {
		glob = "*.log"
	}

	_ = filepath.WalkDir(dir, func(path string, de os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if de.IsDir() {
			stats.DirsSeen++
			if !recursive && path != dir {
				return filepath.SkipDir
			}
			return nil
		}
		stats.FilesSeen++

		base := filepath.Base(path)
		lb := strings.ToLower(base)
		if strings.HasSuffix(lb, ".gz") || strings.HasSuffix(lb, ".bz2") || strings.HasSuffix(lb, ".xz") ||
			strings.HasSuffix(lb, ".zst") || strings.HasSuffix(lb, ".zip") {
			return nil
		}
		if ok, _ := filepath.Match(glob, base); !ok {
			return nil
		}
		if info, e := os.Stat(path); e != nil || !info.Mode().IsRegular() {
			return nil
		}

		stats.MatchedFiles++
		if len(stats.SampleMatched) < 8 {
			stats.SampleMatched = append(stats.SampleMatched, path)
		}
		if st != nil {
			if _, ok := st.Get(core.FileStateKey(section, path)); ok {
				stats.StateHits++
			}
		}
		return nil
	})

	return stats
}

// ensureChallengeRedirect runs EnsureChallengeRedirect at most once per minute.
// This is intentionally cheap and self-healing.
func (w *webdetectorWrapped) ensureChallengeRedirect(tag string) {
	// throttle

	skip := func() bool {
		w.lastEnsureMu.Lock()
		defer w.lastEnsureMu.Unlock()
		if !w.lastEnsure.IsZero() && time.Since(w.lastEnsure) < 10*time.Minute {
			return true
		}
		w.lastEnsure = time.Now()
		return false
	}()
	if skip {
		return
	}

	// OpenResty mode: do not manage challenge DNAT sets/rules
	if w.cfg.OpenRestyMode {
		if fwBackend != nil {
			if t, ok := any(fwBackend).(interface{ SetChallengeDNATEnabled(bool) }); ok {
				t.SetChallengeDNATEnabled(false)
			} else if t, ok := any(fwBackend).(interface{ CleanupChallengeDNAT() error }); ok {
				_ = t.CleanupChallengeDNAT()
			}
		}
		return
	}

	if fwBackend == nil {
		logging.Logf("[webdetector] no firewall backend; cannot ensure challenge redirect rules (%s)", tag)
		return
	}
	cr, ok := any(fwBackend).(interface {
		EnsureChallengeRedirect(httpListen, httpsListen string) error
	})
	if !ok {
		logging.Logf("[webdetector] firewall backend does not support EnsureChallengeRedirect (%s)", tag)
		return
	}

	if err := cr.EnsureChallengeRedirect(w.cfg.ChallengeHTTPListen, w.cfg.ChallengeHTTPSListen); err != nil {
		logging.Logf("[webdetector] EnsureChallengeRedirect failed (%s): %v", tag, err)
		return
	}
	logging.Logf("[webdetector] challenge redirect rules ensured (%s) (http=%q https=%q)",
		tag, w.cfg.ChallengeHTTPListen, w.cfg.ChallengeHTTPSListen)
}

func init() {
	Register("webdetector", func(section string, kv, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 5*time.Second)
		defWindow := kvDur(global, "DEFAULT_WINDOW", 120*time.Second)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 10*time.Minute)
		// Global cooldown used by challenge logic (can be overridden in [webdetector]).
		defChalCooldown := kvDur(global, "CHALLENGE_COOLDOWN", 30*time.Minute)
		chalCooldown := kvDur(kv, "CHALLENGE_COOLDOWN", defChalCooldown)

		useEnrich := kvBool(kv, "ENRICH", kvBool(global, "ENRICH", true))
		usePTR := kvBool(kv, "PTR", kvBool(global, "PTR", true))
		rawDirs := kvStrClean(kv, "ENRICH_DIRS", kvStr(global, "ENRICH_DIRS", ""))

		var dirs []string
		if rawDirs != "" {
			for _, f := range strings.FieldsFunc(rawDirs, func(r rune) bool {
				return r == ',' || r == ':' || r == ' ' || r == '\t'
			}) {
				if f != "" {
					dirs = append(dirs, f)
				}
			}
		}

		cfg := webdet.Config{
			Mode:        strings.ToLower(kvStrClean(kv, "MODE", "file")),
			LogPath:     kvStrClean(kv, "LOG_PATH", "/var/log/apache2/access_cfm_tsv.log"),
			LogDir:      kvStrClean(kv, "LOG_DIR", ""),
			Recursive:   kvBool(kv, "RECURSIVE", false),
			Glob:        kvStrClean(kv, "GLOB", "*.log"),
			StartAtEnd:  kvBool(kv, "START_AT_END", true),
			Every:       kvDur(kv, "EVERY", defEvery),
			Window:      kvDur(kv, "WINDOW", defWindow),
			Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),
			SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 20),

			UseEnrich:  useEnrich,
			UsePTR:     usePTR,
			EnrichDirs: dirs,

			LongFactor: kvInt(kv, "LONG_FACTOR", 10),
			MinScore:   kvFlt(kv, "MIN_SCORE", 0.60),

			// Deprecated: webdetector routes are now served by the shared apiserver.
			APIListen: kvStrClean(kv, "API_LISTEN", ""),

			ChallengeHTTPListen:  kvStrClean(kv, "CHALLENGE_HTTP_LISTEN", ""),
			ChallengeHTTPSListen: kvStrClean(kv, "CHALLENGE_HTTPS_LISTEN", ""),

			// Separate per-request access log for the challenge server ([challenge_http] lines).
			ChallengeAccessLogPath: kvStrClean(kv, "CHALLENGE_ACCESS_LOG", "/var/log/cfm/challenge.access.log"),

			// Challenge abuse blocking (only if enabled)
			ChallengeAbuseEnabled:  kvBool(kv, "CHALLENGE_ABUSE_ENABLED", false),
			ChallengeAbuseWindow:   kvDur(kv, "CHALLENGE_ABUSE_WINDOW", 10*time.Second),
			ChallengeAbuseBadN:     kvInt(kv, "CHALLENGE_ABUSE_BAD_N", 15),
			ChallengeAbuseBlockTTL: kvDur(kv, "CHALLENGE_ABUSE_BLOCK_TTL", 1*time.Hour),
			ChallengeAbuseCooldown: kvDur(kv, "CHALLENGE_ABUSE_COOLDOWN", 30*time.Minute),

			ChallengeToken: kvStrClean(kv, "CHALLENGE_TOKEN", ""),

			// OpenResty in-path mode (replaces standalone challenge_server)
			OpenRestyMode:  kvBool(kv, "OPENRESTY_MODE", false),
			OpenRestySock:  kvStrClean(kv, "OPENRESTY_SOCK", "/var/run/cfm_nginx.sock"),
			OpenRestyToken: kvStrClean(kv, "OPENRESTY_TOKEN", ""),

			OpenRestyOkIPTTL: kvDur(kv, "OPENRESTY_OK_IP_TTL", 1*time.Minute),

			// How long the solved cookie should live. If unset/0 => inherit CHALLENGE_COOLDOWN.
			ChallengeCookieLife: 0,

			// Challenge emit controls:
			// - CHALLENGE_LOG=0 disables [challenge] logs
			// - CHALLENGE_NOTIFY=0 disables Alert emissions (notifications)
			// (CHALLENGE_NOTIFICATION is accepted as an alias)
			ChallengeLog:    kvBool(kv, "CHALLENGE_LOG", true),
			ChallengeNotify: kvBool(kv, "CHALLENGE_NOTIFY", kvBool(kv, "CHALLENGE_NOTIFICATION", true)),

			IP404Count:    kvInt(kv, "IP404_COUNT", 0),
			IP403Count:    kvInt(kv, "IP403_COUNT", 0),
			IP403WAFCount: kvInt(kv, "IP403WAF_COUNT", 0),

			// 40x combo (403+404) detector
			IP40xComboCount:       kvInt(kv, "IP40X_COMBO", 0),
			IP40xComboUniquePaths: kvInt(kv, "IP40X_UNIQUE_PATHS", 0),

			AgentCount:   kvInt(kv, "AGENT_COUNT", 0),
			MalPathCount: kvInt(kv, "MALPATH_COUNT", 0),

			// Challenge-only paths (like MALPATH but for CHALLENGE action)
			ChallengePathsEnabled: kvBool(kv, "CHALLENGE_PATHS", false),
			ChallengePathsFile:    kvStrClean(kv, "CHALLENGE_PATHS_FILE", "/etc/cfm/webdetector_challenge_paths.txt"),
			ChallengePathsCount:   kvInt(kv, "CHALLENGE_PATHS_COUNT", 1),
			ChallengePathsTTL:     kvDur(kv, "CHALLENGE_PATHS_TTL", 30*time.Minute),

			// -------------------------------------------------------------------
			// NEW: Unique-based challenge filters (phase 1: challenge-only)
			// -------------------------------------------------------------------
			ChallengeIPUniqPathsEnabled: kvBool(kv, "CHALLENGE_IP_UNIQPATHS_ENABLED", false),
			ChallengeIPUniqPathsMin:     kvInt(kv, "CHALLENGE_IP_UNIQPATHS_MIN", 0),
			ChallengeIPUniqPathsTTL:     kvDur(kv, "CHALLENGE_IP_UNIQPATHS_TTL", 0),
			ChallengeIPUniqPathsCap:     kvInt(kv, "CHALLENGE_IP_UNIQPATHS_CAP", 0),

			ChallengeIPUniqHostsEnabled: kvBool(kv, "CHALLENGE_IP_UNIQHOSTS_ENABLED", false),
			ChallengeIPUniqHostsMin:     kvInt(kv, "CHALLENGE_IP_UNIQHOSTS_MIN", 0),
			ChallengeIPUniqHostsTTL:     kvDur(kv, "CHALLENGE_IP_UNIQHOSTS_TTL", 0),
			ChallengeIPUniqHostsCap:     kvInt(kv, "CHALLENGE_IP_UNIQHOSTS_CAP", 0),

			ChallengeVhostUniqPathsEnabled: kvBool(kv, "CHALLENGE_VHOST_UNIQPATHS_ENABLED", false),
			ChallengeVhostUniqPathsMin:     kvInt(kv, "CHALLENGE_VHOST_UNIQPATHS_MIN", 0),
			ChallengeVhostUniqPathsOff:     kvInt(kv, "CHALLENGE_VHOST_UNIQPATHS_OFF", 0),
			ChallengeVhostUniqPathsTTL:     kvDur(kv, "CHALLENGE_VHOST_UNIQPATHS_TTL", 0),
			ChallengeVhostUniqPathsCap:     kvInt(kv, "CHALLENGE_VHOST_UNIQPATHS_CAP", 0),

			ChallengeIPRPSMin:       kvFlt(kv, "CHALLENGE_RPS_TOTAL_MIN", 0),
			ChallengeIP4xxRPSMin:    kvFlt(kv, "CHALLENGE_RPS_4XX_MIN", 0),
			ChallengeIP5xxRPSMin:    kvFlt(kv, "CHALLENGE_RPS_5XX_MIN", 0),
			ChallengeIPErrRatioMin:  kvFlt(kv, "CHALLENGE_ERR_RATIO_MIN", 0),
			ChallengeIPPostRatioMin: kvFlt(kv, "CHALLENGE_POST_RATIO_MIN", 0),
			ChallengeIPNoUAMin:      kvInt(kv, "CHALLENGE_NO_UA_MIN", 0),
			ChallengeIPHTTP10Min:    kvInt(kv, "CHALLENGE_HTTP10_MIN", 0),

			// VHOST-wide challenge knobs
			ChallengeSuspiciousVHost:     kvBool(kv, "CHALLENGE_SUSPICIOUS_VHOST", false),
			ChallengeSuspiciousScoreOn:   kvFlt(kv, "CHALLENGE_SUSPICIOUS_VHOST_SCORE_ON", 0),
			ChallengeSuspiciousScoreOff:  kvFlt(kv, "CHALLENGE_SUSPICIOUS_VHOST_SCORE_OFF", 0),
			ChallengeSuspiciousMinUniqIP: kvInt(kv, "CHALLENGE_SUSPICIOUS_VHOST_MIN_UNIQIP", 0),
			ChallengeSuspiciousHolddown:  kvDur(kv, "CHALLENGE_SUSPICIOUS_VHOST_HOLDDOWN", 0),

			// Optional uniqIP-based vhost auto mode
			ChallengeSuspiciousUniqIP:    kvBool(kv, "CHALLENGE_SUSPICIOUS_VHOST_UNIQIP", false),
			ChallengeSuspiciousUniqIPOn:  kvInt(kv, "CHALLENGE_SUSPICIOUS_VHOST_UNIQIP_ON", 0),
			ChallengeSuspiciousUniqIPOff: kvInt(kv, "CHALLENGE_SUSPICIOUS_VHOST_UNIQIP_OFF", 0),
			ChallengeSuspiciousUniqIPMax: kvInt(kv, "CHALLENGE_SUSPICIOUS_VHOST_UNIQIP_MAX", 0),

			ChallengeSubnetEnabled:     kvBool(kv, "CHALLENGE_SUBNET_ENABLED", false),
			ChallengeSubnetPrefixV4:    kvInt(kv, "CHALLENGE_SUBNET_PREFIX_V4", 24),
			ChallengeSubnetMinIPs:      kvInt(kv, "CHALLENGE_SUBNET_MIN_IPS", 4),
			ChallengeSubnetMinReq:      kvInt(kv, "CHALLENGE_SUBNET_MIN_REQ", 25),
			ChallengeSubnetMinUniqPath: kvInt(kv, "CHALLENGE_SUBNET_MIN_UNIQPATH", 20),
			ChallengeSubnetMinUniqHost: kvInt(kv, "CHALLENGE_SUBNET_MIN_UNIQHOST", 1),
			ChallengeSubnetTTL:         kvDur(kv, "CHALLENGE_SUBNET_TTL", 30*time.Minute),
			ChallengeSubnetCap:         kvInt(kv, "CHALLENGE_SUBNET_CAP", 2048),
			ChallengeSubnetSameHost:    kvBool(kv, "CHALLENGE_SUBNET_SAME_HOST", true),

			ChallengeExcludeStorePath: kvStrClean(kv, "CHALLENGE_EXCLUDE_STORE_PATH", "/var/lib/cfm/webdetector_challenge_excludes.json"),
			WAFExcludeStorePath:       kvStrClean(kv, "WAF_EXCLUDE_STORE_PATH", "/var/lib/cfm/webdetector_waf_excludes.json"),
			HistoryEnabled:            kvBool(kv, "HISTORY_ENABLED", true),
			HistoryDBPath:             kvStrClean(kv, "HISTORY_DB_PATH", "/var/lib/cfm/webdetector-history.db"),
			HistoryRetentionDays:      kvInt(kv, "HISTORY_RETENTION_DAYS", 30),
			HistoryPruneEvery:         kvDur(kv, "HISTORY_PRUNE_EVERY", time.Hour),
		}

		// If CHALLENGE_COOKIE_LIFE not set, default to CHALLENGE_COOLDOWN
		if _, ok := kv["CHALLENGE_COOKIE_LIFE"]; ok {
			cfg.ChallengeCookieLife = kvDur(kv, "CHALLENGE_COOKIE_LIFE", chalCooldown)
		} else {
			cfg.ChallengeCookieLife = chalCooldown
		}

		// CHALLENGE_VHOST (comma/space separated)
		rawVHosts := kvStrClean(kv, "CHALLENGE_VHOST", "")
		if rawVHosts != "" {
			for _, h := range strings.FieldsFunc(rawVHosts, func(r rune) bool {
				return r == ',' || r == ':' || r == ' ' || r == '\t'
			}) {
				h = strings.ToLower(strings.TrimSpace(h))
				if h != "" {
					cfg.ChallengeVHost = append(cfg.ChallengeVHost, h)
				}
			}
		}

		// CHALLENGE_VHOST_IGNORE (comma/space separated)
		rawIgnoreV := kvStrClean(kv, "CHALLENGE_VHOST_IGNORE", "")
		if rawIgnoreV != "" {
			for _, h := range strings.FieldsFunc(rawIgnoreV, func(r rune) bool {
				return r == ',' || r == ':' || r == ' ' || r == '\t'
			}) {
				h = strings.ToLower(strings.TrimSpace(h))
				if h != "" {
					cfg.ChallengeVHostIgnore = append(cfg.ChallengeVHostIgnore, h)
				}
			}
		}

		// CHALLENGE_HOST_BYPASS (comma/space separated)
		rawBypass := kvStrClean(kv, "CHALLENGE_HOST_BYPASS", "")
		if rawBypass != "" {
			for _, h := range strings.FieldsFunc(rawBypass, func(r rune) bool {
				return r == ',' || r == ':' || r == ' ' || r == '\t'
			}) {
				h = strings.ToLower(strings.TrimSpace(h))
				if h != "" {
					cfg.ChallengeHostBypass = append(cfg.ChallengeHostBypass, h)
				}
			}
		}

		rawAgents := kvStrClean(kv, "AGENT_LIST", "")
		if rawAgents != "" {
			for _, a := range strings.FieldsFunc(rawAgents, func(r rune) bool {
				return r == ',' || r == ':' || r == ' ' || r == '\t'
			}) {
				a = strings.ToLower(strings.TrimSpace(a))
				if a != "" {
					cfg.AgentList = append(cfg.AgentList, a)
				}
			}
		}

		// IGNORE40X_PREFIXES (comma/space separated)
		rawIgnore := kvStrClean(kv, "IGNORE40X_PREFIXES", "")
		if rawIgnore != "" {
			for _, p := range strings.FieldsFunc(rawIgnore, func(r rune) bool {
				return r == ',' || r == ':' || r == ' ' || r == '\t'
			}) {
				p = strings.ToLower(strings.TrimSpace(p))
				if p != "" {
					cfg.Ignore40xPrefixes = append(cfg.Ignore40xPrefixes, p)
				}
			}
		}

		// MALPATH_LIST (comma/space separated)
		rawMal := kvStrClean(kv, "MALPATH_LIST", "")
		if rawMal != "" {
			for _, a := range strings.FieldsFunc(rawMal, func(r rune) bool {
				return r == ',' || r == ':' || r == ' ' || r == '\t'
			}) {
				a = strings.ToLower(strings.TrimSpace(a))
				if a != "" {
					cfg.MalPathList = append(cfg.MalPathList, a)
				}
			}
		}

		// MALPATH_FILE (one entry per line; supports comments with #)
		cfg.MalPathFile = kvStrClean(kv, "MALPATH_FILE", "")
		if cfg.MalPathFile != "" {
			f, err := os.Open(cfg.MalPathFile)
			if err != nil {
				logging.Logf("[webdetector] MALPATH_FILE open failed: %s: %v", cfg.MalPathFile, err)
			} else {
				defer f.Close()
				sc := bufio.NewScanner(f)
				for sc.Scan() {
					line := strings.TrimSpace(sc.Text())
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					line = strings.ToLower(line)
					cfg.MalPathList = append(cfg.MalPathList, line)
				}
				if err := sc.Err(); err != nil {
					logging.Logf("[webdetector] MALPATH_FILE scan failed: %s: %v", cfg.MalPathFile, err)
				}
			}
		}

		// CHALLENGE_PATHS_FILE (one entry per line; supports comments with #)
		if cfg.ChallengePathsEnabled && cfg.ChallengePathsFile != "" {
			f, err := os.Open(cfg.ChallengePathsFile)
			if err != nil {
				logging.Logf("[webdetector] CHALLENGE_PATHS_FILE open failed: %s: %v", cfg.ChallengePathsFile, err)
			} else {
				defer f.Close()
				sc := bufio.NewScanner(f)
				for sc.Scan() {
					line := strings.TrimSpace(sc.Text())
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					line = strings.ToLower(line)

					// IMPORTANT: needs cfg.ChallengePathsList []string in webdet.Config
					cfg.ChallengePathsList = append(cfg.ChallengePathsList, line)
				}
				if err := sc.Err(); err != nil {
					logging.Logf("[webdetector] CHALLENGE_PATHS_FILE scan failed: %s: %v", cfg.ChallengePathsFile, err)
				}
			}
		}

		if cfg.Mode == "dir" {
			cfg.Mode = "folder"
		}

		// Build ipIgnore FIRST — it's needed both by the engine (bypass predicate)
		// and by the wrapped struct (challenge server + bridge wiring in startOnce).
		ipIgnore := newIPIgnoreFromGlobal(global)

		engine := webdet.NewEngine(cfg)

		// Wire IGNORE_IPS / IGNORE_NETS to engine immediately (before RunOnce).
		// The bridge gets it inside startOnce.Do once OpenResty mode starts.
		if ipIgnore != nil {
			engine.SetBypassFunc(ipIgnore.ShouldIgnore)
		}

		// MODE=file: attach tailer if file exists
		if cfg.Mode == "file" || cfg.Mode == "" {
			path := cfg.LogPath
			if st, err := os.Stat(path); err == nil && !st.IsDir() {
				logging.Logf("[webdetector] using log: %s", path)
				src := core.NewFileTailer(path)
				src.StartAtEnd = cfg.StartAtEnd
				engine.SetSource(src)
				if stt, _ := core.LoadState(""); stt != nil {
					key := core.FileStateKey(section, path)
					engine.SetState(stt, key)
				}
			} else {
				logging.Logf("[webdetector] log path not found: %s (set LOG_PATH)", path)
			}
		}

		// MODE=folder: tail multiple files under a directory (DirectAdmin/cPanel domlogs)
		if cfg.Mode == "folder" {
			dir := cfg.LogDir
			if dir == "" {
				logging.Logf("[webdetector] folder mode requires LOG_DIR")
			} else if st, err := os.Stat(dir); err == nil && st.IsDir() {
				logging.Logf("[webdetector] using log dir: %s (recursive=%v glob=%s)", dir, cfg.Recursive, cfg.Glob)
				src := core.NewDirTailer(dir, cfg.Recursive, cfg.Glob)
				src.StartAtEnd = cfg.StartAtEnd

				var stt *core.State
				if stt, _ := core.LoadState(""); stt != nil {
					// persist per-file offsets: key = FileStateKey(section, fullpath)
					src.SetState(stt, section)
				}
				stats := scanFolderSourceForDebug(dir, cfg.Glob, cfg.Recursive, stt, section)
				logging.Logf("[webdetector][debug] folder scan: dirs=%d files=%d matched=%d state_hits=%d start_at_end=%v",
					stats.DirsSeen, stats.FilesSeen, stats.MatchedFiles, stats.StateHits, cfg.StartAtEnd)
				if len(stats.SampleMatched) > 0 {
					logging.Logf("[webdetector][debug] folder scan sample matched: %s", strings.Join(stats.SampleMatched, ", "))
				}
				engine.SetSource(src)
			} else {
				logging.Logf("[webdetector] log dir not found: %s (set LOG_DIR)", dir)
			}
		}

		// IMPORTANT: do NOT start background servers here.
		// Bind them to the manager ctx via webdetectorWrapped.RunOnce(ctx),
		// otherwise reload can leave orphan listeners serving stale stats.
		// Small bounded queue for background-triggered alerts (abuse, etc.).
		// Delivery is on next RunOnce tick (drained into out channel).
		return &webdetectorWrapped{
			eng:      engine,
			cfg:      cfg,
			ipIgnore: ipIgnore,
			extQ:     make(chan core.Alert, 2048),
		}, nil

	})
}

// SetBypassFunc forwards to the engine and to the bridge (if already created).
// Called from manager.go via interface assertion.
func (w *webdetectorWrapped) SetBypassFunc(fn func(string) bool) {
	w.eng.SetBypassFunc(fn)
	// Bridge may not exist yet (OpenResty disabled), but if it does, wire it too.
	if b := w.eng.NginxBridge(); b != nil {
		b.SetBypassFunc(fn)
	}
}

// SetChalExcludeFunc forwards to the engine.
// Called from manager.go via interface assertion.
func (w *webdetectorWrapped) SetChalExcludeFunc(fn func(string, string, string, string, string, string) (string, bool)) {
	w.eng.SetChalExcludeFunc(fn)
}
