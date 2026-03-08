// internal/webdetector/webdetector_config.go
package webdetector

import "time"

// Config is the full configuration for the webdetector engine.
// It is built from [webdetector] in cfm.conf by the detector register.
type Config struct {
	// Log ingestion
	Mode     string        // "file" | "folder"
	LogPath  string        // file mode: TSV log path
	LogDir   string        // folder mode: directory root
	Recursive bool         // folder mode: recurse into subfolders (cpanel domlogs)
	Glob     string        // folder mode: glob match for filenames, e.g. "*.log" (optional)

	Every    time.Duration // detector tick interval
	Window   time.Duration // short-window horizon (sliding)
	Cooldown time.Duration // reserved for future alert gating
	SampleLimit int        // max sample lines per host for drilldown

	// Enrichment
	UseEnrich  bool
	UsePTR     bool
	EnrichDirs []string

	// Long-window scoring
	LongFactor int     // how many short windows ~= long horizon (e.g. 10)
	MinScore   float64 // minimum suspicious score

	// API
	APIListen string // "127.0.0.1:9070" etc.

        // Challenge server listeners (optional)
        ChallengeHTTPListen  string
        ChallengeHTTPSListen string

        // Separate access log for per-request challenge HTTP lines ([challenge_http] ...).
        // If empty, [challenge_http] continues to go to the main challenges log.
        ChallengeAccessLogPath string // CHALLENGE_ACCESS_LOG = /var/log/cfm/challenge.access.log

        // Challenge server abuse blocking (based on challenge.access.log behavior)
        ChallengeAbuseEnabled  bool          // CHALLENGE_ABUSE_ENABLED = 1
        ChallengeAbuseWindow   time.Duration // CHALLENGE_ABUSE_WINDOW  = 10s
        ChallengeAbuseBadN     int           // CHALLENGE_ABUSE_BAD_N   = 15
        ChallengeAbuseBlockTTL time.Duration // CHALLENGE_ABUSE_BLOCK_TTL = 1h
        ChallengeAbuseCooldown time.Duration // CHALLENGE_ABUSE_COOLDOWN  = 30m

    // Challenge emit controls
    ChallengeLog    bool // controls [challenge] logging
    ChallengeNotify bool // controls Alert emissions for challenge actions

    // Optional: log extremely noisy per-request suppressed entries (cooldown/excluded).
    // Default: false.
    ChallengeLogSuppressed bool

// OpenResty integration (optional)
OpenRestyMode  bool          // OPENRESTY_MODE = 1
OpenRestySock  string        // OPENRESTY_SOCK  = /var/run/cfm_nginx.sock
OpenRestyToken string        // OPENRESTY_TOKEN = sometoken
OpenRestyOkIPTTL time.Duration // OPENRESTY_OK_IP_TTL = 1m (0 disables IP ok-state; cookie-only)

    // How long the solved cookie (cfm_ok) should live (challenge server).
    // If 0, detector register will default it to CHALLENGE_COOLDOWN.
    ChallengeCookieLife time.Duration // CHALLENGE_COOKIE_LIFE = 10m

    // Log one-line expiry when a challenged CID wasn't solved before TTL.
    // Default: true.
    ChallengeLogExpired bool

	// IP threshold detectors (CSF-like)
	IP404Count int
	IP403Count int

	// WAF-origin 403s reported via POST /nginx/observe (OpenResty cfm_waf.lua).
	// Counted separately so a distinct threshold and alert kind (WEB/403WAF) can be used.
	IP403WAFCount int // IP403WAF_COUNT = 50

	// 40x combo detector (403+404) with optional unique-path gating.
	IP40xComboCount       int
	IP40xComboUniquePaths int
	Ignore40xPrefixes     []string // optional: "/.well-known/", "/robots.txt", ...

	AgentList  []string      // substrings (lowercased)
	AgentCount int

	// Malicious path probes (webshell/env/uploader/etc)
	MalPathList  []string // substrings or paths (lowercased)
	MalPathFile  string   // optional file with one entry per line
	MalPathCount int

// NEW CHALLENGE RULES//
ChallengePathsList []string // loaded from CHALLENGE_PATHS_FILE

ChallengePathsEnabled bool   // CHALLENGE_PATHS
ChallengePathsFile    string // CHALLENGE_PATHS_FILE
ChallengePathsCount   int    // CHALLENGE_PATHS_COUNT (optional threshold)
ChallengePathsTTL     time.Duration // CHALLENGE_PATHS_TTL (optional)


    // Additional challenge triggers (all optional; 0 disables)
    ChallengeIPRPSMin       float64 // CHALLENGE_RPS_TOTAL_MIN (per-IP rps)
    ChallengeIP4xxRPSMin    float64 // CHALLENGE_RPS_4XX_MIN
    ChallengeIP5xxRPSMin    float64 // CHALLENGE_RPS_5XX_MIN
    ChallengeIPErrRatioMin  float64 // CHALLENGE_ERR_RATIO_MIN (err/total where err=4xx+5xx)
    ChallengeIPPostRatioMin float64 // CHALLENGE_POST_RATIO_MIN (POST/total)
    ChallengeIPNoUAMin      int     // CHALLENGE_NO_UA_MIN (empty/"-" UA hits)
    ChallengeIPHTTP10Min    int     // CHALLENGE_HTTP10_MIN (proto == http/1.0)

    // Malformed request burst: 400 Bad Request + 414 URI Too Long + 431 Headers Too Large.
    // High counts indicate header/URI fuzzing or WAF bypass tooling.
    // Action: challenge (escalate to block via BLOCK config if repeat offender).
    ChallengeIPMalformedMin int           // CHALLENGE_MALFORMED_MIN (abs count in window)
    ChallengeIPMalformedTTL time.Duration // CHALLENGE_MALFORMED_TTL

    // UA churn: an IP rotating too many distinct User-Agent strings in the window.
    // Tooling tries to evade UA-based heuristics by rotating; real browsers don't.
    ChallengeIPUniqUAMin    int           // CHALLENGE_UNIQUA_MIN
    ChallengeIPUniqUATTL    time.Duration // CHALLENGE_UNIQUA_TTL
    ChallengeIPUniqUACap    int           // CHALLENGE_UNIQUA_CAP (memory safety)

    // --- VHOST-wide challenge modes ---

    // Manual panic mode: challenge every IP that hits these vhosts (or their subdomains).
    // Example: "victim.com, *.victim.com"
    ChallengeVHost        []string // CHALLENGE_VHOST

    // Ignore list for vhost-wide actions (wins over manual+auto).
    // Example: "api.mybank.gr"
    ChallengeVHostIgnore  []string // CHALLENGE_VHOST_IGNORE

    // Absolute host bypass (wins over *all* challenge actions, including per-IP).
    // Use sparingly (typically for API/healthcheck hosts that must never be challenged).
    // Example: "api.mybank.gr, health.example.com, *.internal.example.com"
    ChallengeHostBypass   []string // CHALLENGE_HOST_BYPASS

    // Auto under-attack mode using long-window suspicious scoring.
    ChallengeSuspiciousVHost      bool          // CHALLENGE_SUSPICIOUS_VHOST (1/0)
    ChallengeSuspiciousScoreOn    float64       // CHALLENGE_SUSPICIOUS_VHOST_SCORE_ON
    ChallengeSuspiciousScoreOff   float64       // CHALLENGE_SUSPICIOUS_VHOST_SCORE_OFF
    ChallengeSuspiciousMinUniqIP  int           // CHALLENGE_SUSPICIOUS_VHOST_MIN_UNIQIP
    ChallengeSuspiciousHolddown   time.Duration // CHALLENGE_SUSPICIOUS_VHOST_HOLDDOWN

	// Optional: volume-based (uniqIP) auto under-attack mode with hysteresis.
	// Useful for sophisticated crawlers that avoid errors but spray many unique IPs.
	ChallengeSuspiciousUniqIP    bool // CHALLENGE_SUSPICIOUS_VHOST_UNIQIP (1/0)
	ChallengeSuspiciousUniqIPOn  int  // CHALLENGE_SUSPICIOUS_VHOST_UNIQIP_ON
	ChallengeSuspiciousUniqIPOff int  // CHALLENGE_SUSPICIOUS_VHOST_UNIQIP_OFF
	ChallengeSuspiciousUniqIPMax int  // CHALLENGE_SUSPICIOUS_VHOST_UNIQIP_MAX (hard cap; optional)



        // -------------------------------------------------------------------
        // NEW: unique-based challenge filters (phase 1: challenge-only)
        // -------------------------------------------------------------------
        // per-IP: many unique paths in short window -> challenge
        ChallengeIPUniqPathsEnabled bool          // CHALLENGE_IP_UNIQPATHS_ENABLED
        ChallengeIPUniqPathsMin     int           // CHALLENGE_IP_UNIQPATHS_MIN
        ChallengeIPUniqPathsTTL     time.Duration // CHALLENGE_IP_UNIQPATHS_TTL
        ChallengeIPUniqPathsCap     int           // CHALLENGE_IP_UNIQPATHS_CAP (memory safety)

        // per-IP: many unique hosts in short window -> challenge (scanner/vhost enumeration)
        ChallengeIPUniqHostsEnabled bool          // CHALLENGE_IP_UNIQHOSTS_ENABLED
        ChallengeIPUniqHostsMin     int           // CHALLENGE_IP_UNIQHOSTS_MIN
        ChallengeIPUniqHostsTTL     time.Duration // CHALLENGE_IP_UNIQHOSTS_TTL
        ChallengeIPUniqHostsCap     int           // CHALLENGE_IP_UNIQHOSTS_CAP

        // per-vhost: many unique paths in short window -> challenge vhost (bridge)
        ChallengeVhostUniqPathsEnabled bool          // CHALLENGE_VHOST_UNIQPATHS_ENABLED
        ChallengeVhostUniqPathsMin     int           // CHALLENGE_VHOST_UNIQPATHS_MIN
        ChallengeVhostUniqPathsOff     int           // CHALLENGE_VHOST_UNIQPATHS_OFF (hysteresis)
        ChallengeVhostUniqPathsTTL     time.Duration // CHALLENGE_VHOST_UNIQPATHS_TTL
        ChallengeVhostUniqPathsCap     int           // CHALLENGE_VHOST_UNIQPATHS_CAP (early stop)



	// Subnet-based challenge mode (behavioral, low-and-slow rotators)
	ChallengeSubnetEnabled     bool          // CHALLENGE_SUBNET_ENABLED
	ChallengeSubnetPrefixV4    int           // CHALLENGE_SUBNET_PREFIX_V4 (default 24)
	ChallengeSubnetMinIPs      int           // CHALLENGE_SUBNET_MIN_IPS
	ChallengeSubnetMinReq      int           // CHALLENGE_SUBNET_MIN_REQ
	ChallengeSubnetMinUniqPath int           // CHALLENGE_SUBNET_MIN_UNIQPATH
	ChallengeSubnetMinUniqHost int           // CHALLENGE_SUBNET_MIN_UNIQHOST
	ChallengeSubnetTTL         time.Duration // CHALLENGE_SUBNET_TTL
	ChallengeSubnetCap         int           // CHALLENGE_SUBNET_CAP
	ChallengeSubnetSameHost    bool          // CHALLENGE_SUBNET_SAME_HOST


}

// FillDefaults ensures sane defaults if some fields are zero.
func (c *Config) FillDefaults() {
	if c.Every <= 0 {
		c.Every = 5 * time.Second
	}
	if c.Window <= 0 {
		c.Window = 120 * time.Second
	}
	if c.Cooldown <= 0 {
		c.Cooldown = 10 * time.Minute
	}
	if c.SampleLimit <= 0 {
		c.SampleLimit = 20
	}
	if c.LongFactor <= 0 {
		c.LongFactor = 10
	}
	if c.MinScore <= 0 {
		c.MinScore = 0.60
	}
	if c.APIListen == "" {
		c.APIListen = "127.0.0.1:9070"
	}
	if c.Glob == "" {
		c.Glob = "*.log"
	}

        // Default: write per-request challenge access lines to a separate file.
        // This keeps cfm.challenges.log focused on higher-level [challenge] events.
        if c.ChallengeAccessLogPath == "" {
                c.ChallengeAccessLogPath = "/var/log/cfm/challenge.access.log"
        }

        // Safe defaults (disabled unless enabled explicitly)
        if c.ChallengeAbuseWindow <= 0 {
                c.ChallengeAbuseWindow = 10 * time.Second
        }
        if c.ChallengeAbuseBadN <= 0 {
                c.ChallengeAbuseBadN = 15
        }
        if c.ChallengeAbuseBlockTTL < 0 {
                c.ChallengeAbuseBlockTTL = 8 * time.Hour
        }
        if c.ChallengeAbuseCooldown <= 0 {
                c.ChallengeAbuseCooldown = 30 * time.Minute
        }


	// OpenResty: keep IP ok-state short by default (avoid CGNAT/Tor "whitelisting").
	// Set to 0 for cookie-only.
	if c.OpenRestyOkIPTTL == 0 {
		// default: 1 minute (only to prevent immediate redirect loops after solve)
		c.OpenRestyOkIPTTL = 1 * time.Minute
	}

if c.ChallengePathsFile == "" {
    c.ChallengePathsFile = "/etc/cfm/webdetector_challenge_paths.txt"
}
if c.ChallengePathsCount <= 0 {
    c.ChallengePathsCount = 1 // challenge on first hit by default
}
if c.ChallengePathsTTL <= 0 {
    c.ChallengePathsTTL = 30 * time.Minute
}

// Challenge logging defaults
// - Suppressed is noisy -> default off
// - Expired is useful -> default on
if !c.ChallengeLogSuppressed {
    // keep default false
}
if !c.ChallengeLogExpired {
    c.ChallengeLogExpired = true
}


    // Defaults for auto suspicious vhost mode (only meaningful when enabled).
    if c.ChallengeSuspiciousVHost {
        if c.ChallengeSuspiciousScoreOn <= 0 {
            c.ChallengeSuspiciousScoreOn = 0.70
        }
        // If OFF not set, default to ON-0.10 (but never below 0).
        if c.ChallengeSuspiciousScoreOff <= 0 {
            off := c.ChallengeSuspiciousScoreOn - 0.10
            if off < 0 {
                off = 0
            }
            c.ChallengeSuspiciousScoreOff = off
        }
        if c.ChallengeSuspiciousMinUniqIP <= 0 {
            c.ChallengeSuspiciousMinUniqIP = 80
        }
        if c.ChallengeSuspiciousHolddown <= 0 {
            c.ChallengeSuspiciousHolddown = 10 * time.Minute
        }
    }



	// Defaults for uniqIP-based auto mode (only meaningful when enabled).
	if c.ChallengeSuspiciousUniqIP {
		if c.ChallengeSuspiciousUniqIPOn <= 0 {
			c.ChallengeSuspiciousUniqIPOn = 300
		}
		if c.ChallengeSuspiciousUniqIPOff <= 0 {
			// default: 60% of ON
			off := int(float64(c.ChallengeSuspiciousUniqIPOn) * 0.60)
			if off < 1 {
				off = 1
			}
			c.ChallengeSuspiciousUniqIPOff = off
		}
		// Max is optional (0 disables)
		if c.ChallengeSuspiciousUniqIPMax < 0 {
			c.ChallengeSuspiciousUniqIPMax = 0
		}
	}




        // ----------------------------
        // Defaults for unique-filters (only if enabled)
        // ----------------------------
        if c.ChallengeIPUniqPathsEnabled {
                if c.ChallengeIPUniqPathsMin <= 0 {
                        c.ChallengeIPUniqPathsMin = 120
                }
                if c.ChallengeIPUniqPathsTTL <= 0 {
                        c.ChallengeIPUniqPathsTTL = 20 * time.Minute
                }
                if c.ChallengeIPUniqPathsCap <= 0 {
                        c.ChallengeIPUniqPathsCap = 512
                }
        }

        if c.ChallengeIPUniqHostsEnabled {
                if c.ChallengeIPUniqHostsMin <= 0 {
                        c.ChallengeIPUniqHostsMin = 10
                }
                if c.ChallengeIPUniqHostsTTL <= 0 {
                        c.ChallengeIPUniqHostsTTL = 30 * time.Minute
                }
                if c.ChallengeIPUniqHostsCap <= 0 {
                        c.ChallengeIPUniqHostsCap = 128
                }
        }

        if c.ChallengeVhostUniqPathsEnabled {
                if c.ChallengeVhostUniqPathsMin <= 0 {
                        c.ChallengeVhostUniqPathsMin = 1500
                }
                if c.ChallengeVhostUniqPathsOff <= 0 {
                        off := int(float64(c.ChallengeVhostUniqPathsMin) * 0.60)
                        if off < 1 {
                                off = 1
                        }
                        c.ChallengeVhostUniqPathsOff = off
                }
                if c.ChallengeVhostUniqPathsTTL <= 0 {
                        c.ChallengeVhostUniqPathsTTL = 20 * time.Minute
                }
                if c.ChallengeVhostUniqPathsCap <= 0 {
                        c.ChallengeVhostUniqPathsCap = 5000
                }
        }




	if c.ChallengeSubnetEnabled {
		if c.ChallengeSubnetPrefixV4 <= 0 {
			c.ChallengeSubnetPrefixV4 = 24
		}
		if c.ChallengeSubnetMinIPs <= 0 {
			c.ChallengeSubnetMinIPs = 4
		}
		if c.ChallengeSubnetMinReq <= 0 {
			c.ChallengeSubnetMinReq = 25
		}
		if c.ChallengeSubnetMinUniqPath <= 0 {
			c.ChallengeSubnetMinUniqPath = 20
		}
		if c.ChallengeSubnetMinUniqHost <= 0 {
			c.ChallengeSubnetMinUniqHost = 1
		}
		if c.ChallengeSubnetTTL <= 0 {
			c.ChallengeSubnetTTL = 30 * time.Minute
		}
		if c.ChallengeSubnetCap <= 0 {
			c.ChallengeSubnetCap = 2048
		}
	}


// Malformed burst defaults (only if enabled)
if c.ChallengeIPMalformedMin > 0 {
    if c.ChallengeIPMalformedTTL <= 0 {
        c.ChallengeIPMalformedTTL = 30 * time.Minute
    }
}

// UA churn defaults (only if enabled)
if c.ChallengeIPUniqUAMin > 0 {
    if c.ChallengeIPUniqUATTL <= 0 {
        c.ChallengeIPUniqUATTL = 20 * time.Minute
    }
    if c.ChallengeIPUniqUACap <= 0 {
        c.ChallengeIPUniqUACap = 64
    }
}

// Sensible defaults for the 40x combo detector (window defaults to 120s).
if c.IP40xComboCount > 0 {
    if c.IP40xComboUniquePaths <= 0 {
        c.IP40xComboUniquePaths = 20
    }
    if len(c.Ignore40xPrefixes) == 0 {
        c.Ignore40xPrefixes = []string{"/.well-known/", "/robots.txt", "/favicon.ico", "/sitemap", "/apple-touch-icon", "/manifest.json"}
    }
}


}

// LongHorizon returns the long-window horizon duration.
func (c Config) LongHorizon() time.Duration {
	return time.Duration(c.LongFactor) * c.Window
}
