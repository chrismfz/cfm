// internal/detectors/webdetector_register.go
package detectors

import (
	"os"
	"strings"
	"time"
	"bufio"
	"context"

	core "cfm/internal/detectors/core"
	"cfm/internal/logging"
	webdet "cfm/internal/webdetector"

//        "os/exec"
//        nft "cfm/internal/firewall/nft"

)

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


// normalize aliases
if cfg.Mode == "dir" {
        cfg.Mode = "folder"
}

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



		// Start HTTP API in a goroutine (if API_LISTEN is non-empty).
		if cfg.APIListen != "" {
			go engine.ServeHTTP(cfg.APIListen)
		}



                // Start Challenge server (optional) + ensure nft redirect rules.
                //
                // IMPORTANT:
                // - EnsureChallengeRedirect installs NAT prerouting redirect rules:
                //   src IP in @challenge_v4/@challenge_v6 + dport 80/443 -> redirect to challenge ports.
                // - This is idempotent: safe to call on startup.

// Start Challenge server (optional).

if cfg.ChallengeHTTPListen != "" || cfg.ChallengeHTTPSListen != "" {

        // 1) Ensure redirect/accept rules using the SAME firewall backend (best-effort)
        if fwBackend != nil {
                if cr, ok := any(fwBackend).(interface {
                        EnsureChallengeRedirect(httpListen, httpsListen string) error
                }); ok {
                        if err := cr.EnsureChallengeRedirect(cfg.ChallengeHTTPListen, cfg.ChallengeHTTPSListen); err != nil {
                                logging.Logf("[webdetector] EnsureChallengeRedirect failed: %v", err)
                        } else {
                                logging.Logf("[webdetector] challenge redirect rules ensured (http=%q https=%q)",
                                        cfg.ChallengeHTTPListen, cfg.ChallengeHTTPSListen)
                        }
                } else {
                        logging.Logf("[webdetector] firewall backend does not support EnsureChallengeRedirect")
                }
        } else {
                logging.Logf("[webdetector] no firewall backend; cannot ensure challenge redirect rules")
        }

        // 2) Start challenge server with SSL collector + SAME firewall backend
        srv := webdet.NewChallengeServer(webdet.SSLCollector(), fwBackend)

        go func() {
                if err := srv.Start(context.Background(), cfg.ChallengeHTTPListen, cfg.ChallengeHTTPSListen); err != nil {
                        logging.Logf("[webdetector] challenge start failed: %v", err)
                }
        }()

        if cfg.ChallengeHTTPListen != "" {
                logging.Logf("[webdetector] challenge HTTP listening on %s", cfg.ChallengeHTTPListen)
        }
        if cfg.ChallengeHTTPSListen != "" {
                logging.Logf("[webdetector] challenge HTTPS listening on %s", cfg.ChallengeHTTPSListen)
        }
}








		return engine, nil
	})
}


