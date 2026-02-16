// internal/detectors/webdetector_register.go
package detectors

import (
	"os"
	"strings"
	"time"
	"bufio"
	"context"
	"sync"
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

    // Track background servers so hot-reload waits for ports to be free.
    srvWG    sync.WaitGroup
    stopOnce sync.Once
    chalSrv  *webdet.ChallengeServer

    // challenge redirect rules can be lost if firewall reloads/recreates tables.
    // Re-ensure periodically from RunOnce as a self-healing watchdog.
    lastEnsureMu sync.Mutex
    lastEnsure   time.Time

}

func (w *webdetectorWrapped) Name() string         { return w.eng.Name() }
func (w *webdetectorWrapped) Every() time.Duration { return w.eng.Every() }

func (w *webdetectorWrapped) RunOnce(ctx context.Context, out chan<- core.Alert) error {
    w.startOnce.Do(func() {

        // IMPORTANT:
        // ctx here is a per-run watchdog ctx (timeout) from runOnceSafeTimed.
        // If we bind background servers to it, they will be shut down at the end
        // of every tick and ports will never stay open.
        pctx := parentCtxFrom(ctx)
        if pctx == nil {
            pctx = ctx
        }


        // API server (ctx-bound)
        if w.cfg.APIListen != "" {

            w.srvWG.Add(1)
            go func() {
                defer w.srvWG.Done()
                if err := w.eng.ServeHTTPWithContext(pctx, w.cfg.APIListen); err != nil {
                    logging.Logf("[webdetector] API server exited: %v", err)
                }
            }()

        }

        // Challenge server + nft redirect rules (ctx-bound)
        if w.cfg.ChallengeHTTPListen != "" || w.cfg.ChallengeHTTPSListen != "" {
            // initial ensure (best-effort)
            w.ensureChallengeRedirect("init")


            srv := webdet.NewChallengeServer(webdet.SSLCollector(), fwBackend)
            w.chalSrv = srv

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

    err := w.eng.RunOnce(ctx, out)

    // On shutdown (reload), wait for background servers to actually exit so
    // ports are free before the new instance starts.
    // Use the long-lived parent ctx, not the per-run ctx.
    pctx := parentCtxFrom(ctx)
    if pctx == nil {
        pctx = ctx
    }

    if pctx.Err() != nil {
        w.stopOnce.Do(func() {
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
		defEvery    := kvDur(global, "DEFAULT_EVERY",    5*time.Second)
		defWindow   := kvDur(global, "DEFAULT_WINDOW",   120*time.Second)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 10*time.Minute)

		useEnrich := kvBool(kv, "ENRICH", kvBool(global, "ENRICH", true))
		usePTR    := kvBool(kv, "PTR",    kvBool(global, "PTR", true))
		rawDirs   := kvStrClean(kv, "ENRICH_DIRS", kvStr(global, "ENRICH_DIRS", ""))

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
	Every:       kvDur(kv, "EVERY", defEvery),
	Window:      kvDur(kv, "WINDOW", defWindow),
	Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),
	SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 20),

	UseEnrich:  useEnrich,
	UsePTR:     usePTR,
	EnrichDirs: dirs,

	LongFactor: kvInt(kv, "LONG_FACTOR", 10),
	MinScore:   kvFlt(kv, "MIN_SCORE", 0.60),

	APIListen: kvStrClean(kv, "API_LISTEN", "127.0.0.1:9070"),

        ChallengeHTTPListen:  kvStrClean(kv, "CHALLENGE_HTTP_LISTEN", ""),
        ChallengeHTTPSListen: kvStrClean(kv, "CHALLENGE_HTTPS_LISTEN", ""),

	IP404Count: kvInt(kv, "IP404_COUNT", 0),
	IP403Count: kvInt(kv, "IP403_COUNT", 0),

	// 40x combo (403+404) detector
	IP40xComboCount:       kvInt(kv, "IP40X_COMBO", 0),
	IP40xComboUniquePaths: kvInt(kv, "IP40X_UNIQUE_PATHS", 0),


	AgentCount: kvInt(kv, "AGENT_COUNT", 0),
	MalPathCount: kvInt(kv, "MALPATH_COUNT", 0),

        // Challenge-only paths (like MALPATH but for CHALLENGE action)
        ChallengePathsEnabled: kvBool(kv, "CHALLENGE_PATHS", false),
        ChallengePathsFile:    kvStrClean(kv, "CHALLENGE_PATHS_FILE", "/etc/cfm/webdetector_challenge_paths.txt"),
        ChallengePathsCount:   kvInt(kv, "CHALLENGE_PATHS_COUNT", 1),
        ChallengePathsTTL:     kvDur(kv, "CHALLENGE_PATHS_TTL", 30*time.Minute),


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



if cfg.Mode == "dir" { cfg.Mode = "folder" }
engine := webdet.NewEngine(cfg)



		// MODE=file: attach tailer if file exists
		if cfg.Mode == "file" || cfg.Mode == "" {
			path := cfg.LogPath
			if st, err := os.Stat(path); err == nil && !st.IsDir() {
				logging.Logf("[webdetector] using log: %s", path)
				src := core.NewFileTailer(path)
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
                                if stt, _ := core.LoadState(""); stt != nil {
                                        // persist per-file offsets: key = FileStateKey(section, fullpath)
                                        src.SetState(stt, section)
                                }
				engine.SetSource(src)
			} else {
				logging.Logf("[webdetector] log dir not found: %s (set LOG_DIR)", dir)
			}
		}


        // IMPORTANT: do NOT start background servers here.
        // Bind them to the manager ctx via webdetectorWrapped.RunOnce(ctx),
        // otherwise reload can leave orphan listeners serving stale stats.
        return &webdetectorWrapped{eng: engine, cfg: cfg}, nil


	})
}


