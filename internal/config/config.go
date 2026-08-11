package config

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"time"
)

// Config is flat-by-category: one struct per logical area.
type Config struct {
	API              APIConfig
	Firewall         FirewallConfig
	Logging          LoggingConfig
	NFT              NFTConfig
	Ports            PortsConfig
	Connlimit        ConnlimitConfig
	PortFlood        PortFloodConfig
	PacketRate       PacketRateConfig
	Throttle         ThrottleConfig
	Portscan         PortscanConfig
	SystemTweaks     SystemTweaksConfig
	Hardening        HardeningConfig
	SMTPBlock        SMTPBlockConfig
	Outbound         OutboundConfig
	MaxMind          MaxMindConfig
	Debug            DebugConfig
	SSLCollectorSock SSLCollectorSockConfig
	Clam             ClamConfig
}

// --- Categories ---

// SSLCollectorSockConfig — exposes sslcollector over unix socket for OpenResty
type SSLCollectorSockConfig struct {
	Enabled      bool          // SSLCOLLECTOR_SOCK_ENABLE
	SockPath     string        // SSLCOLLECTOR_SOCK_PATH
	Token        string        // SSLCOLLECTOR_SOCK_TOKEN (optional)
	LuaTokenPath string        // SSLCOLLECTOR_LUA_TOKEN_PATH (default /var/lib/cfm/lua/cfm_token.lua)
	PEMTTL       time.Duration // SSLCOLLECTOR_SOCK_PEM_TTL (default 10m)
	PEMMax       int           // SSLCOLLECTOR_SOCK_PEM_MAX (default 50000)
	OfflineCache *bool         // SSLCOLLECTOR_OFFLINE_CACHE (default true — snapshot keeps certs warm across cfm-offline nginx restarts)
}

type ClamConfig struct {
	Enabled          bool          // CLAMD_ENABLED (pipeline/infra: manager runs, clamd wired)
	ScanDefault      bool          // CLAM_SCAN_DEFAULT (global scanning POLICY; default ON — the async notify-only scanner has run fleet-wide for months). Effective per host = Enabled && (ScanDefault XOR host-in-override). With the default, the override list is an OPT-OUT set; set CLAM_SCAN_DEFAULT = 0 to disable server-wide.
	ScanScope        string        // CLAM_SCAN_SCOPE (archives|all, default archives): which upload file types are worth clamd's time, decided by magic bytes in the scanner. "archives" scans only container formats (zip — incl. docx/xlsx/jar —, gzip, rar, 7z, xz, bzip2), the one class the WAF genuinely can't inspect; "all" restores full-coverage scanning of every multipart file part.
	SigIgnore        []string      // CLAM_SIG_IGNORE (comma-separated globs on the signature name, case-insensitive; default *_Hunting.UNOFFICIAL): verdicts DOWNGRADED to log-only — still logged + recorded in history with sig_ignored, but no CLAM/INFECTED notification and no quarantine. Hunting-grade third-party YARA rules are FP-prone by design; an empty value ("CLAM_SIG_IGNORE =") acts on everything.
	ScanMode         string        // CLAM_SCAN_MODE (async|inline, default async): async = today's notify-only pipeline; inline = the edge WAITS for the verdict and 403s an infected upload. Inline is FAIL-OPEN by contract: clamd down/hung/oversize/timeouts all allow the upload (degrading to an async scan). Per-vhost flips live in the mode-override store.
	InlineTimeout    time.Duration // CLAM_INLINE_TIMEOUT (default 3s): hard cap for one inline scan; on expiry the upload is allowed (fail-open).
	InlineDryRun     bool          // CLAM_INLINE_DRY_RUN (default 0): scan inline and record what WOULD block, without blocking — the burn-in guard before arming real inline blocking.
	NginxHookEnabled bool          // CLAMD_NGINX_HOOK_ENABLED (default true; controls whether cfm_clamav.lua intercepts uploads)
	Network          string        // CLAMD_NETWORK (unix|tcp)
	Address          string        // CLAMD_SOCKET or 127.0.0.1:3310
	Timeout          time.Duration // CLAMD_TIMEOUT
	MaxWorkers       int
	QueueSize        int
	PendingDir       string // CLAMD_PENDING_DIR  default /var/lib/cfm/scanner/pending
	InfectedDir      string // CLAMD_INFECTED_DIR default /var/lib/cfm/scanner/infected
}

// DebugConfig — controls the internal debug/metrics HTTP server
type DebugConfig struct {
	ListenAddress              string        // LISTEN_ADDRESS
	Port                       int           // PORT
	TLSPort                    int           // TLS_PORT (0 = disabled)
	TLSAddress                 string        // TLS_LISTEN_ADDRESS (default = ListenAddress)
	AuthDBPath                 string        // AUTH_DB_PATH (default /var/lib/cfm/auth.db)
	AuthSessionDBPath          string        // AUTH_SESSION_DB_PATH (optional; separate DB for sessions)
	AuthMFAEncryptionKey       string        // AUTH_MFA_ENCRYPTION_KEY (optional; 16/24/32-byte raw, hex, or base64)
	AuthMFALoginVerifyEnabled  bool          // AUTH_MFA_LOGIN_VERIFY_ENABLED (default true)
	AuthMFATOTPEnrollEnabled   bool          // AUTH_MFA_TOTP_ENROLL_ENABLED (default false)
	AuthMFATOTPPilotUsers      []string      // AUTH_MFA_TOTP_PILOT_USERS (comma-separated usernames)
	SessionTTL                 time.Duration // AUTH_SESSION_TTL (default 8h)
	SecureCookie               bool          // AUTH_SECURE_COOKIE
	CookieName                 string        // AUTH_COOKIE_NAME (default cfm-sid)
	DebugCaptureEnabled        bool          // DEBUG_CAPTURE_ENABLED
	DebugCaptureDir            string        // DEBUG_CAPTURE_DIR
	DebugCaptureCooldown       time.Duration // DEBUG_CAPTURE_COOLDOWN
	DebugCaptureMaxDuration    time.Duration // DEBUG_CAPTURE_MAX_DURATION
	DebugCaptureRetentionCount int           // DEBUG_CAPTURE_RETENTION_COUNT
	DebugCaptureRetentionAge   time.Duration // DEBUG_CAPTURE_RETENTION_AGE
}

// SMTPBlockConfig — CSF-like outbound SMTP control (no INI sections, flat keys only)
type SMTPBlockConfig struct {
	Enabled      bool     // SMTP_BLOCK
	Ports        []uint16 // SMTP_PORTS (defaults: 25,465,587)
	AllowLocal   bool     // SMTP_ALLOWLOCAL
	Redirect     bool     // SMTP_REDIRECT
	RedirectPort uint16   // SMTP_REDIRECT_PORT (default 25)
	AllowUsers   []string // SMTP_ALLOWUSER (usernames)
	AllowGroups  []string // SMTP_ALLOWGROUP (group names)
	AllowUIDs    []uint32 // SMTP_ALLOW_UIDS (optional explicit UIDs)
	AllowGIDs    []uint32 // SMTP_ALLOW_GIDS (optional explicit GIDs)
	// Logging knobs (for nft log/NFLOG + our own file sink)
	LogEnabled bool   // SMTP_LOG
	LogLimit   string // SMTP_LOG_LIMIT (e.g. "5/second")
	LogBurst   int    // SMTP_LOG_BURST
	LogNFLOG   int    // SMTP_LOG_NFLOG (0=kernel log, >0=nflog group)
	LogEnrich  bool   // SMTP_LOG_ENRICH (use enrich on DST IP in our consumer)
}

// OutboundConfig — Outbound Abuse Sentinel (phase 1: observe + warn).
//
// Watches new outbound TCP connections per Linux uid via NFLOG and
// classifies them by destination port group. When a uid crosses a per-window
// threshold for any signal, a forensic warning is logged to cfm.smtp.log and an
// admin notification is emitted. Phase 1 never throttles or suspends; an nft
// "observe" chain only NFLOGs.
type OutboundConfig struct {
	Enabled                bool     // OUTBOUND_ENABLED
	NFLOGGroup             int      // OUTBOUND_NFLOG (must differ from SMTP_LOG_NFLOG)
	WindowSec              int      // OUTBOUND_WINDOW_SECONDS (default 60)
	SMTPPerMin             int      // OUTBOUND_SMTP_CONN_PER_MIN (default 30)
	UniqueDstPerMin        int      // OUTBOUND_SCAN_UNIQUE_DST_PER_MIN (default 50)
	HTTPPerMin             int      // OUTBOUND_HTTP_RATE_PER_MIN (default 200)
	ScanPorts              []uint16 // OUTBOUND_SCAN_PORTS (default 22,23,3389)
	SMTPPorts              []uint16 // OUTBOUND_SMTP_PORTS (default 25,465,587)
	HTTPPorts              []uint16 // OUTBOUND_HTTP_PORTS (default 80,443,8080,8443)
	LogDedupSec            int      // OUTBOUND_LOG_DEDUP_SECONDS (default 300)
	NotifySeverity         string   // OUTBOUND_NOTIFY_SEVERITY (default warning)
	QueueSamples           int      // OUTBOUND_QUEUE_SAMPLES (default 5)
	AllowUsers             []string // OUTBOUND_ALLOW_USERS (extra usernames; cfm/mailnull auto-checked)
	AllowGroups            []string // OUTBOUND_ALLOW_GROUPS (extra group names; cfm/mail auto-checked)
	AllowUIDs              []uint32 // OUTBOUND_ALLOW_UIDS (root always allowed)
	AllowGIDs              []uint32 // OUTBOUND_ALLOW_GIDS
	Enrich                 bool     // OUTBOUND_LOG_ENRICH (GeoIP/ASN on dst)
	HTTPAttributionEnabled bool     // OUTBOUND_HTTP_ATTRIBUTION_ENABLED (disabled; reserved for optional best-effort/privacy-sensitive attribution)
}

// MaxMindConfig — updater and DB locations for GeoLite/GeoIP2
type MaxMindConfig struct {
	Enabled         bool          // MAXMIND_ENABLED
	Source          string        // MAXMIND_SOURCE (auto|maxmind|iplocate)
	AccountID       string        // MAXMIND_ACCOUNT_ID
	LicenseKey      string        // MAXMIND_LICENSE_KEY
	Editions        []string      // MAXMIND_EDITIONS (comma-separated), e.g. GeoLite2-ASN,GeoLite2-City
	Dir             string        // MAXMIND_DIR (default: /var/lib/cfm/maxmind)
	CheckEvery      time.Duration // MAXMIND_CHECK_EVERY (default: 24h)
	MinAgeBetweenDL time.Duration // MAXMIND_MIN_AGE (default: 72h)
	HTTPTimeout     time.Duration // MAXMIND_HTTP_TIMEOUT (default: 30s)
	// Optional: override permalinks per edition
	// {"GeoLite2-ASN":"https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz", ...}
	Permalinks map[string]string // MAXMIND_PERMALINKS_JSON (edition->url)
}

type HardeningConfig struct {
	BlockBadTCPFlags bool // BLOCK_BAD_TCP_FLAGS
	NewRate          int  // NEW_RATE (per-IP ct state new / sec; 0=off)
	NewBurst         int  // NEW_BURST (packets)
	ICMPRate         int  // ICMP_RATE_LIMIT (per-IP echo-request / sec; 0=off)
	ICMPBurst        int  // ICMP_RATE_BURST
}

type SystemTweaksConfig struct {
	Enable  bool // SYS_TWEAKS_ENABLE
	Persist bool // SYS_TWEAKS_PERSIST
	// Conntrack sizing
	CTPerGB int // SYS_CT_PER_GB
	CTMin   int // SYS_CT_MIN
	CTMax   int // SYS_CT_MAX

	// Strictness/timeouts
	TCPLooseStrict   bool // SYS_TCP_LOOSE_STRICT  (true => nf_conntrack_tcp_loose=0)
	TCPSynRetries    int  // SYS_TCP_SYN_RETRIES
	TCPSynAckRetries int  // SYS_TCP_SYNACK_RETRIES
	TCPFinTimeout    int  // SYS_TCP_FIN_TIMEOUT
	CTTimeWait       int  // SYS_CT_TIMEWAIT
	CTFinWait        int  // SYS_CT_FINWAIT
	CTCloseWait      int  // SYS_CT_CLOSEWAIT

	// Hygiene
	RPFilter        int  // SYS_RP_FILTER (0/1/2 σε κάποια συστήματα, αλλά 1 είναι το σύνηθες)
	AcceptRedirects bool // SYS_ACCEPT_REDIRECTS
	SendRedirects   bool // SYS_SEND_REDIRECTS

	// DNAT-to-loopback support (needed for challenge DNAT -> 127.0.0.1)
	RouteLocalnet       bool   // SYS_ROUTE_LOCALNET (0/1)
	RouteLocalnetIF     string // SYS_ROUTE_LOCALNET_IF (e.g. eth0) optional
	IPv6AcceptRedirects bool   // SYS_IPV6_ACCEPT_REDIRECTS
	IPv6SendRedirects   bool   // SYS_IPV6_SEND_REDIRECTS
	IPv6Disable         bool   // SYS_IPV6_DISABLE (0/1) optional hard kill switch if you ever want it

}

type APIConfig struct {
	URL             string
	AuthToken       string
	MCPToken        string // MCP_TOKEN — client-facing auth for the read-only MCP server; kept separate from AuthToken so the MCP credential is not the admin/API token
	AutoBlockSend   bool // AUTOBLOCK_SEND_TO_API
	ManualBlockSend bool // MANUAL_BLOCK_SEND_TO_API
	UnblockSend     bool // UNBLOCK_SEND_TO_API
	DetectorsSend   bool // DETECTORS_SEND_TO_API (optional, falls back to AutoBlockSend if false)
}

type FirewallConfig struct {
	Engine string // FIREWALL_ENGINE
}

type LoggingConfig struct {
	Stdout bool   // LOG_STDOUT
	File   string // LOG_FILE

	APIStdout bool   // API_LOG_STDOUT
	APIFile   string // API_LOG_FILE

	DETECTORStdout bool   // DETECTOR_LOG_STDOUT
	DETECTORFile   string // DETECTOR_LOG_FILE

	// NEW: web challenges log sink
	CHALLENGESStdout bool   // CHALLENGES_LOG_STDOUT
	CHALLENGESFile   string // CHALLENGES_LOG_FILE

	SMTPStdout bool   // SMTP_LOG_STDOUT
	SMTPFile   string // SMTP_LOG_FILE

	MYSQLStdout bool   // MYSQL_LOG_STDOUT
	MYSQLFile   string // MYSQL_LOG_FILE

	WAFStdout bool   // WAF_LOG_STDOUT
	WAFFile   string // WAF_LOG_FILE

	CLAMStdout bool   // CLAM_LOG_STDOUT
	CLAMFile   string // CLAM_LOG_FILE

	SOCKETStdout bool   // SOCKET_LOG_STDOUT
	SOCKETFile   string // SOCKET_LOG_FILE

	LSMStdout bool   // LSM_LOG_STDOUT
	LSMFile   string // LSM_LOG_FILE

}

type NFTConfig struct {
	InputPriority int // clamped -300..+300
	// DNATPriority controls priority of CFM's NAT prerouting DNAT chain.
	// Recommended: -99 (Imunify/WebShield first), -101 (CFM first). Avoid -100.
	DNATPriority int // clamped -300..+300
}

type PortsConfig struct {
	TCPIn, TCPOut []PortRange
	UDPIn, UDPOut []PortRange
}

type ConnlimitConfig struct {
	Rules []ConnlimitRule
}

type PortFloodConfig struct {
	Rules []PortFloodRule
}

type PacketRateConfig struct {
	Rate  int    // packets per second per IP (0 = disabled)
	Burst int    // burst size in packets
	Mode  string // "syn" | "all"
}

type ThrottleConfig struct {
	Enabled     bool
	WindowSec   int
	Hits        int
	Mode        string // "permanent" | "ttl"
	TTLSeconds  int
	Sources     []string // e.g. ["syn","portflood","pps"]
	SetTTL      int      // seconds for nft set timeout (tracking)
	CooldownSec int      // seconds to suppress repeat autoblocks per IP
}

type PortscanConfig struct {
	Enabled    bool
	Interval   int    // seconds between scans/rotations; 0 disables if Enabled not set explicitly
	Mode       string // "temporary" | "permanent" | "alert"
	TTLSeconds int
	Limit      int // distinct ports threshold
	Diversity  int // >=1 persistent port presence
	TrackTCP   bool
	TrackUDP   bool
	OnlyPorts  []PortRange // optional filters (ranges)
	Ports      []int       // optional focus ports (exact)
}

// --- Common leaf types ---

type PortRange struct{ From, To int }

type ConnlimitRule struct {
	Proto string // "tcp" | "udp"
	Port  int
	Limit int // concurrent conns per source IP
}

type PortFloodRule struct {
	Proto     string // "tcp" | "udp"
	Port      int
	WindowSec int // window size in seconds
	Packets   int // max packets in window
}

// SetDefaults populates sane defaults where zero values are ambiguous.
func (c *Config) SetDefaults() {
	// Firewall
	c.Firewall.Engine = strings.ToLower(strings.TrimSpace(c.Firewall.Engine))
	if c.Firewall.Engine == "" {
		c.Firewall.Engine = "nft"
	}

	// NFT
	c.NFT.InputPriority = clamp(c.NFT.InputPriority, -300, 300)
	if c.NFT.DNATPriority == 0 {
		c.NFT.DNATPriority = -99
	}
	c.NFT.DNATPriority = clamp(c.NFT.DNATPriority, -300, 300)
	// PacketRate
	if c.PacketRate.Mode == "" {
		c.PacketRate.Mode = "syn"
	}
	if c.PacketRate.Burst < 0 {
		c.PacketRate.Burst = 0
	}
	if c.PacketRate.Rate < 0 {
		c.PacketRate.Rate = 0
	}
	// Throttle
	if c.Throttle.WindowSec == 0 {
		c.Throttle.WindowSec = 120
	}
	if c.Throttle.Hits == 0 {
		c.Throttle.Hits = 3
	}
	if c.Throttle.Mode == "" {
		c.Throttle.Mode = "permanent"
	}

	if c.Clam.Network == "" {
		c.Clam.Network = "unix"
	}
	if c.Clam.Timeout <= 0 {
		c.Clam.Timeout = 10 * time.Second
	}

	if c.Clam.MaxWorkers <= 0 {
		c.Clam.MaxWorkers = 2
	}
	if c.Clam.QueueSize <= 0 {
		c.Clam.QueueSize = 256
	}

	if c.Clam.PendingDir == "" {
		c.Clam.PendingDir = "/var/lib/cfm/scanner/pending"
	}
	if c.Clam.InfectedDir == "" {
		c.Clam.InfectedDir = "/var/lib/cfm/scanner/infected"
	}

	// --- MaxMind defaults ---
	if c.MaxMind.Source == "" {
		c.MaxMind.Source = "auto"
	}
	if c.MaxMind.Dir == "" {
		c.MaxMind.Dir = "/var/lib/cfm/maxmind"
	}
	if c.MaxMind.CheckEvery <= 0 {
		c.MaxMind.CheckEvery = 24 * time.Hour
	}
	if c.MaxMind.MinAgeBetweenDL <= 0 {
		c.MaxMind.MinAgeBetweenDL = 72 * time.Hour
	}
	if c.MaxMind.HTTPTimeout <= 0 {
		c.MaxMind.HTTPTimeout = 30 * time.Second
	}
	// Editions: no hard default; user may choose ASN or City or both

	c.Throttle.Mode = strings.ToLower(c.Throttle.Mode)
	switch c.Throttle.Mode {
	case "permanent", "ttl", "dryrun", "alert":
		// ok
	default:
		c.Throttle.Mode = "permanent"
	}
	if c.Throttle.TTLSeconds == 0 {
		c.Throttle.TTLSeconds = 24 * 3600
	}
	if c.Throttle.SetTTL == 0 {
		c.Throttle.SetTTL = 60
	}
	// Cooldown: avoid duplicate autoblocks/logs/notifications for the same IP
	if c.Throttle.CooldownSec == 0 {
		c.Throttle.CooldownSec = 180
	}
	// Portscan
	if c.Portscan.Interval == 0 {
		c.Portscan.Interval = 60
	}
	if c.Portscan.Mode == "" {
		c.Portscan.Mode = "ttl"
	}
	if c.Portscan.TTLSeconds == 0 {
		c.Portscan.TTLSeconds = 3600
	}
	if c.Portscan.Limit == 0 {
		c.Portscan.Limit = 10
	}
	if c.Portscan.Diversity == 0 {
		c.Portscan.Diversity = 1
	}
	// If PS_ENABLED not set explicitly, infer from interval>0
	if !c.Portscan.Enabled && c.Portscan.Interval > 0 {
		c.Portscan.Enabled = true
	}

	// SMTPBlock defaults
	if len(c.SMTPBlock.Ports) == 0 {
		c.SMTPBlock.Ports = []uint16{25, 465, 587}
	}
	if c.SMTPBlock.RedirectPort == 0 {
		c.SMTPBlock.RedirectPort = 25
	}
	if c.SMTPBlock.LogEnabled && c.SMTPBlock.LogBurst == 0 {
		c.SMTPBlock.LogBurst = 20
	}
	// default SMTP log file if enabled and not set explicitly
	if c.SMTPBlock.LogEnabled && c.Logging.SMTPFile == "" {
		c.Logging.SMTPFile = "/var/log/cfm.smtp.log"
	}

	// Outbound Abuse Sentinel defaults (phase 1: observe + warn)
	if c.Outbound.WindowSec <= 0 {
		c.Outbound.WindowSec = 60
	}
	if c.Outbound.SMTPPerMin <= 0 {
		c.Outbound.SMTPPerMin = 30
	}
	if c.Outbound.UniqueDstPerMin <= 0 {
		c.Outbound.UniqueDstPerMin = 50
	}
	if c.Outbound.HTTPPerMin <= 0 {
		c.Outbound.HTTPPerMin = 200
	}
	if len(c.Outbound.SMTPPorts) == 0 {
		c.Outbound.SMTPPorts = []uint16{25, 465, 587}
	}
	if len(c.Outbound.ScanPorts) == 0 {
		c.Outbound.ScanPorts = []uint16{22, 23, 3389}
	}
	if len(c.Outbound.HTTPPorts) == 0 {
		c.Outbound.HTTPPorts = []uint16{80, 443, 8080, 8443}
	}
	if c.Outbound.LogDedupSec <= 0 {
		c.Outbound.LogDedupSec = 300
	}
	if c.Outbound.NotifySeverity == "" {
		c.Outbound.NotifySeverity = "warning"
	}
	if c.Outbound.QueueSamples <= 0 {
		c.Outbound.QueueSamples = 5
	}
	// Outbound shares the SMTP log file (operator preference: keep one place
	// for outbound abuse signals).
	if c.Outbound.Enabled && c.Logging.SMTPFile == "" {
		c.Logging.SMTPFile = "/var/log/cfm.smtp.log"
	}

	// Hardening
	if c.Hardening.NewRate < 0 {
		c.Hardening.NewRate = 0
	}
	if c.Hardening.NewBurst < 0 {
		c.Hardening.NewBurst = 0
	}
	if c.Hardening.ICMPRate < 0 {
		c.Hardening.ICMPRate = 0
	}
	if c.Hardening.ICMPBurst < 0 {
		c.Hardening.ICMPBurst = 0
	}

	// SSLCollector unix socket defaults
	if c.SSLCollectorSock.SockPath == "" {
		c.SSLCollectorSock.SockPath = "/var/run/sslcollector.sock"
	}
	if c.SSLCollectorSock.LuaTokenPath == "" {
		c.SSLCollectorSock.LuaTokenPath = "/var/lib/cfm/lua/cfm_token.lua"
	}
	if c.SSLCollectorSock.PEMTTL <= 0 {
		c.SSLCollectorSock.PEMTTL = 10 * time.Minute
	}
	if c.SSLCollectorSock.PEMMax <= 0 {
		c.SSLCollectorSock.PEMMax = 50000
	}

	c.Debug.DebugCaptureEnabled = true
	if c.Debug.DebugCaptureDir == "" {
		c.Debug.DebugCaptureDir = "/var/lib/cfm/debug-captures"
	}
	if c.Debug.DebugCaptureCooldown <= 0 {
		c.Debug.DebugCaptureCooldown = 30 * time.Second
	}
	if c.Debug.DebugCaptureMaxDuration <= 0 {
		c.Debug.DebugCaptureMaxDuration = 60 * time.Second
	}
	if c.Debug.DebugCaptureRetentionCount <= 0 {
		c.Debug.DebugCaptureRetentionCount = 32
	}
	if c.Debug.DebugCaptureRetentionAge <= 0 {
		c.Debug.DebugCaptureRetentionAge = 24 * time.Hour
	}

}

// Validate clamps, normalizes and ensures cross-field coherence.
func (c *Config) Validate() error {
	c.NFT.InputPriority = clamp(c.NFT.InputPriority, -300, 300)
	if c.NFT.DNATPriority == 0 {
		c.NFT.DNATPriority = -99
	}
	c.NFT.DNATPriority = clamp(c.NFT.DNATPriority, -300, 300)
	if c.PacketRate.Mode != "syn" && c.PacketRate.Mode != "all" {
		c.PacketRate.Mode = "syn"
	}
	if c.Throttle.Hits < 0 || c.Throttle.WindowSec < 0 || c.Throttle.TTLSeconds < 0 || c.Throttle.SetTTL < 0 || c.Throttle.CooldownSec < 0 {
		return errors.New("negative values not allowed in Throttle config")
	}
	if c.Portscan.Interval < 0 || c.Portscan.TTLSeconds < 0 || c.Portscan.Limit < 0 || c.Portscan.Diversity < 0 {
		return errors.New("negative values not allowed in Portscan config")
	}
	// Normalize mode
	if c.Portscan.Mode != "temporary" && c.Portscan.Mode != "permanent" && c.Portscan.Mode != "alert" {
		c.Portscan.Mode = "ttl" // backwards-compat alias; will be interpreted by code that treats ttl/permanent
	}

	// Clamp SMTPBlock ports
	if len(c.SMTPBlock.Ports) > 0 {
		out := make([]uint16, 0, len(c.SMTPBlock.Ports))
		for _, p := range c.SMTPBlock.Ports {
			if p <= 0 {
				continue
			}
			if p > 65535 {
				p = 65535
			}
			out = append(out, uint16(p))
		}
		c.SMTPBlock.Ports = out
	}

	// Outbound: NFLOG group must not collide with SMTP_LOG_NFLOG (different
	// callbacks would be wired to the same group and packets would be split).
	if c.Outbound.Enabled && c.Outbound.NFLOGGroup > 0 &&
		c.SMTPBlock.LogNFLOG > 0 && c.Outbound.NFLOGGroup == c.SMTPBlock.LogNFLOG {
		return fmt.Errorf("OUTBOUND_NFLOG (%d) must differ from SMTP_LOG_NFLOG (%d)",
			c.Outbound.NFLOGGroup, c.SMTPBlock.LogNFLOG)
	}
	// MaxMind sanity
	c.MaxMind.Source = strings.ToLower(strings.TrimSpace(c.MaxMind.Source))
	switch c.MaxMind.Source {
	case "", "auto", "maxmind", "iplocate":
		if c.MaxMind.Source == "" {
			c.MaxMind.Source = "auto"
		}
	default:
		return fmt.Errorf("invalid MAXMIND_SOURCE %q (must be auto|maxmind|iplocate)", c.MaxMind.Source)
	}
	if c.MaxMind.CheckEvery < 0 || c.MaxMind.MinAgeBetweenDL < 0 || c.MaxMind.HTTPTimeout < 0 {
		return errors.New("negative durations are not allowed in MaxMind config")
	}
	// Normalize editions (trim spaces)
	if len(c.MaxMind.Editions) > 0 {
		eds := make([]string, 0, len(c.MaxMind.Editions))
		for _, e := range c.MaxMind.Editions {
			e = strings.TrimSpace(e)
			if e != "" {
				eds = append(eds, e)
			}
		}
		c.MaxMind.Editions = eds
	}

	return nil
}

// ParseCFMConf parses a flat key=value configuration from r into Config.
// Lines starting with '#' or ';' or '//' are treated as comments.
func ParseCFMConf(r io.Reader) (*Config, error) {
	s := bufio.NewScanner(r)
	cfg := &Config{}
	cfg.Debug.AuthMFALoginVerifyEnabled = true
	// Clam pipeline knobs that default to true: ParseCFMConf only flips
	// them when the key is present, so initialise here.
	cfg.Clam.NginxHookEnabled = true
	// CLAM_SCAN_DEFAULT defaults ON: the async (notify-only) scanner has run
	// fleet-wide for months, so an absent key must preserve that — not silently
	// stop scanning on upgrade. Operators opt individual vhosts OUT via the
	// per-vhost override; set CLAM_SCAN_DEFAULT = 0 to disable server-wide.
	cfg.Clam.ScanDefault = true
	// CLAM_SCAN_SCOPE defaults to archives — a DELIBERATE coverage change
	// (announced in the CHANGELOG): fleet-scale scanning of every image/video/pdf
	// upload is not viable on shared hosting, and the class the WAF can't inspect
	// is compressed containers. "all" restores full coverage.
	cfg.Clam.ScanScope = "archives"
	// CLAM_SIG_IGNORE defaults to downgrading hunting-grade YARA verdicts
	// (log-only, no notify/quarantine): signature-base "Hunting" rules are
	// FP-prone by design (observed: Brooxml_Hunting on a legitimate docx).
	// An explicit empty key acts on everything.
	cfg.Clam.SigIgnore = []string{"*_Hunting.UNOFFICIAL"}
	// Inline mode defaults OFF (async) with a 3s fail-open cap — arming
	// blocking is a deliberate operator opt-in, never an upgrade side effect.
	cfg.Clam.ScanMode = "async"
	cfg.Clam.InlineTimeout = 3 * time.Second
	outboundDNSDeprecatedSeen := false
	lineNo := 0
	for s.Scan() {
		lineNo++
		line := strings.TrimSpace(s.Text())
		if line == "" || isComment(line) {
			continue
		}
		k, v, ok := splitKV(line)
		if !ok {
			return nil, fmt.Errorf("config: invalid line %d: %q", lineNo, line)
		}
		key := strings.ToUpper(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		val = stripInlineComment(val)
		val = trimQuotes(val)

		switch key {
		// API
		case "API_URL":
			cfg.API.URL = val
		case "AUTH_TOKEN", "TOKEN":
			cfg.API.AuthToken = val
		case "MCP_TOKEN":
			cfg.API.MCPToken = val

		case "AUTOBLOCK_SEND_TO_API":
			cfg.API.AutoBlockSend = parseBool(val)
		case "MANUAL_BLOCK_SEND_TO_API":
			cfg.API.ManualBlockSend = parseBool(val)
		case "UNBLOCK_SEND_TO_API":
			cfg.API.UnblockSend = parseBool(val)
		case "DETECTORS_SEND_TO_API":
			cfg.API.DetectorsSend = parseBool(val)
		// Firewall
		case "FIREWALL_ENGINE", "CFM_FIREWALL_ENGINE":
			cfg.Firewall.Engine = val

		// Logging
		case "LOG_STDOUT":
			cfg.Logging.Stdout = parseBool(val)
		case "LOG_FILE":
			cfg.Logging.File = val

		// NEW:
		case "API_LOG_STDOUT":
			cfg.Logging.APIStdout = parseBool(val)
		case "API_LOG_FILE":
			cfg.Logging.APIFile = val

		case "DETECTOR_LOG_STDOUT":
			cfg.Logging.DETECTORStdout = parseBool(val)
		case "DETECTOR_LOG_FILE":
			cfg.Logging.DETECTORFile = val

		case "CHALLENGES_LOG_STDOUT":
			cfg.Logging.CHALLENGESStdout = parseBool(val)
		case "CHALLENGES_LOG_FILE":
			cfg.Logging.CHALLENGESFile = val

		// SMTP log sink (file/stdout) — CSF-like flat keys
		case "SMTP_LOG_STDOUT":
			cfg.Logging.SMTPStdout = parseBool(val)
		case "SMTP_LOG_FILE":
			cfg.Logging.SMTPFile = val

		// NFT
		case "NFT_INPUT_PRIORITY":
			cfg.NFT.InputPriority = clamp(parseInt(val), -300, 300)
		case "NFT_DNAT_PRIORITY":
			cfg.NFT.DNATPriority = clamp(parseInt(val), -300, 300)

		// CHALLENGE_HTTP(S)_LISTEN in cfm.conf are legacy no-ops (the challenge
		// listener is configured in detectors.conf; the HTTPS one is retired) —
		// still accepted by IsKnownKey so old configs don't warn.

		// Ports
		case "TCP_IN":
			cfg.Ports.TCPIn = append(cfg.Ports.TCPIn, parsePorts(val)...)
		case "TCP_OUT":
			cfg.Ports.TCPOut = append(cfg.Ports.TCPOut, parsePorts(val)...)
		case "UDP_IN":
			cfg.Ports.UDPIn = append(cfg.Ports.UDPIn, parsePorts(val)...)
		case "UDP_OUT":
			cfg.Ports.UDPOut = append(cfg.Ports.UDPOut, parsePorts(val)...)

		// Connlimit & PortFlood
		case "CONNLIMIT":
			cfg.Connlimit.Rules = append(cfg.Connlimit.Rules, parseConnlimit(val)...)

		case "PORTFLOOD":
			cfg.PortFlood.Rules = append(cfg.PortFlood.Rules, parsePortFlood(val)...)

		// PacketRate
		case "PKT_RATE":
			cfg.PacketRate.Rate = parseInt(val)
		case "PKT_BURST":
			cfg.PacketRate.Burst = parseInt(val)
		case "PKT_MODE":
			cfg.PacketRate.Mode = val

		// Throttle
		case "THROTTLE_ENABLED":
			cfg.Throttle.Enabled = parseBool(val)
		case "THROTTLE_WINDOW":
			cfg.Throttle.WindowSec = parseInt(val)
		case "THROTTLE_HITS":
			cfg.Throttle.Hits = parseInt(val)
		case "THROTTLE_MODE":
			cfg.Throttle.Mode = val
		case "THROTTLE_TTL":
			cfg.Throttle.TTLSeconds = parseInt(val)
		case "THROTTLE_SOURCES":
			cfg.Throttle.Sources = splitCSV(val)
		case "THROTTLE_SET_TTL":
			cfg.Throttle.SetTTL = parseInt(val)
		case "THROTTLE_COOLDOWN":
			cfg.Throttle.CooldownSec = parseInt(val)

		// Portscan
		case "PS_ENABLED":
			cfg.Portscan.Enabled = parseBool(val)
		case "PS_INTERVAL":
			cfg.Portscan.Interval = parseInt(val)
		case "PS_MODE":
			cfg.Portscan.Mode = val
		case "PS_TTL":
			cfg.Portscan.TTLSeconds = parseInt(val)
		case "PS_LIMIT":
			cfg.Portscan.Limit = parseInt(val)
		case "PS_DIVERSITY":
			cfg.Portscan.Diversity = parseInt(val)
		case "PS_TRACK_TCP":
			cfg.Portscan.TrackTCP = parseBool(val)
		case "PS_TRACK_UDP":
			cfg.Portscan.TrackUDP = parseBool(val)
		case "PS_ONLY_PORTS":
			cfg.Portscan.OnlyPorts = parsePorts(val)
		case "PS_PORTS":
			cfg.Portscan.Ports = parseIntCSV(val)

		// --- SMTPBlock (CSF-like keys only) ---
		case "SMTP_BLOCK":
			cfg.SMTPBlock.Enabled = parseBool(val)
		case "SMTP_PORTS":
			cfg.SMTPBlock.Ports = append(cfg.SMTPBlock.Ports, parseUint16CSV(val)...)
		case "SMTP_ALLOWLOCAL":
			cfg.SMTPBlock.AllowLocal = parseBool(val)
		case "SMTP_REDIRECT":
			cfg.SMTPBlock.Redirect = parseBool(val)
		case "SMTP_REDIRECT_PORT":
			if n := parseInt(val); n > 0 && n <= 65535 {
				cfg.SMTPBlock.RedirectPort = uint16(n)
			}
		case "SMTP_ALLOWUSER":
			cfg.SMTPBlock.AllowUsers = append(cfg.SMTPBlock.AllowUsers, splitCSV(val)...)
		case "SMTP_ALLOWGROUP":
			cfg.SMTPBlock.AllowGroups = append(cfg.SMTPBlock.AllowGroups, splitCSV(val)...)
		case "SMTP_ALLOW_UIDS":
			cfg.SMTPBlock.AllowUIDs = append(cfg.SMTPBlock.AllowUIDs, parseUint32CSV(val)...)
		case "SMTP_ALLOW_GIDS":
			cfg.SMTPBlock.AllowGIDs = append(cfg.SMTPBlock.AllowGIDs, parseUint32CSV(val)...)
		case "SMTP_LOG":
			cfg.SMTPBlock.LogEnabled = parseBool(val)
		case "SMTP_LOG_LIMIT":
			cfg.SMTPBlock.LogLimit = val
		case "SMTP_LOG_BURST":
			cfg.SMTPBlock.LogBurst = parseInt(val)
		case "SMTP_LOG_NFLOG":
			cfg.SMTPBlock.LogNFLOG = parseInt(val)
		case "SMTP_LOG_ENRICH":
			cfg.SMTPBlock.LogEnrich = parseBool(val)

		// --- Outbound Abuse Sentinel (phase 1) ---
		case "OUTBOUND_ENABLED":
			cfg.Outbound.Enabled = parseBool(val)
		case "OUTBOUND_NFLOG":
			cfg.Outbound.NFLOGGroup = parseInt(val)
		case "OUTBOUND_WINDOW_SECONDS":
			cfg.Outbound.WindowSec = parseInt(val)
		case "OUTBOUND_SMTP_CONN_PER_MIN":
			cfg.Outbound.SMTPPerMin = parseInt(val)
		case "OUTBOUND_SCAN_UNIQUE_DST_PER_MIN":
			cfg.Outbound.UniqueDstPerMin = parseInt(val)
		case "OUTBOUND_HTTP_RATE_PER_MIN":
			cfg.Outbound.HTTPPerMin = parseInt(val)
		case "OUTBOUND_DNS_PER_MIN":
			outboundDNSDeprecatedSeen = true
		case "OUTBOUND_SMTP_PORTS":
			cfg.Outbound.SMTPPorts = append(cfg.Outbound.SMTPPorts, parseUint16CSV(val)...)
		case "OUTBOUND_SCAN_PORTS":
			cfg.Outbound.ScanPorts = append(cfg.Outbound.ScanPorts, parseUint16CSV(val)...)
		case "OUTBOUND_HTTP_PORTS":
			cfg.Outbound.HTTPPorts = append(cfg.Outbound.HTTPPorts, parseUint16CSV(val)...)
		case "OUTBOUND_LOG_DEDUP_SECONDS":
			cfg.Outbound.LogDedupSec = parseInt(val)
		case "OUTBOUND_NOTIFY_SEVERITY":
			cfg.Outbound.NotifySeverity = val
		case "OUTBOUND_QUEUE_SAMPLES":
			cfg.Outbound.QueueSamples = parseInt(val)
		case "OUTBOUND_ALLOW_USERS":
			cfg.Outbound.AllowUsers = append(cfg.Outbound.AllowUsers, splitCSV(val)...)
		case "OUTBOUND_ALLOW_GROUPS":
			cfg.Outbound.AllowGroups = append(cfg.Outbound.AllowGroups, splitCSV(val)...)
		case "OUTBOUND_ALLOW_UIDS":
			cfg.Outbound.AllowUIDs = append(cfg.Outbound.AllowUIDs, parseUint32CSV(val)...)
		case "OUTBOUND_ALLOW_GIDS":
			cfg.Outbound.AllowGIDs = append(cfg.Outbound.AllowGIDs, parseUint32CSV(val)...)
		case "OUTBOUND_LOG_ENRICH":
			cfg.Outbound.Enrich = parseBool(val)
		case "OUTBOUND_HTTP_ATTRIBUTION_ENABLED":
			cfg.Outbound.HTTPAttributionEnabled = parseBool(val)
		case "OUTBOUND_DNS_DEBUG_ENABLED":
			outboundDNSDeprecatedSeen = true
		case "OUTBOUND_DNS_DEBUG_SAMPLE_COUNT":
			outboundDNSDeprecatedSeen = true
		case "OUTBOUND_DNS_DEBUG_DURATION_SEC":
			outboundDNSDeprecatedSeen = true
		case "OUTBOUND_DNS_DEBUG_DIR":
			outboundDNSDeprecatedSeen = true

		// --- Debug / HTTP listen ---
		case "LISTEN_ADDRESS":
			cfg.Debug.ListenAddress = val
		case "PORT":
			if n := parseInt(val); n > 0 && n <= 65535 {
				cfg.Debug.Port = n
			}
			// if invalid, keep zero; defaults will fill
		case "TLS_PORT":
			if n, err := strconv.Atoi(val); err == nil {
				cfg.Debug.TLSPort = n
			}
		case "TLS_LISTEN_ADDRESS":
			cfg.Debug.TLSAddress = val
		case "AUTH_DB_PATH":
			cfg.Debug.AuthDBPath = val
		case "AUTH_SESSION_DB_PATH":
			cfg.Debug.AuthSessionDBPath = val
		case "AUTH_MFA_ENCRYPTION_KEY":
			cfg.Debug.AuthMFAEncryptionKey = val
		case "AUTH_MFA_LOGIN_VERIFY_ENABLED":
			cfg.Debug.AuthMFALoginVerifyEnabled = parseBool(val)
		case "AUTH_MFA_TOTP_ENROLL_ENABLED":
			cfg.Debug.AuthMFATOTPEnrollEnabled = parseBool(val)
		case "AUTH_MFA_TOTP_PILOT_USERS":
			cfg.Debug.AuthMFATOTPPilotUsers = append(cfg.Debug.AuthMFATOTPPilotUsers, splitCSV(val)...)
		case "AUTH_SESSION_TTL":
			if d, err := time.ParseDuration(val); err == nil {
				cfg.Debug.SessionTTL = d
			}
		case "AUTH_SECURE_COOKIE":
			cfg.Debug.SecureCookie = val == "1" || strings.EqualFold(val, "true")
		case "AUTH_COOKIE_NAME":
			cfg.Debug.CookieName = val
		case "DEBUG_CAPTURE_ENABLED":
			cfg.Debug.DebugCaptureEnabled = parseBool(val)
		case "DEBUG_CAPTURE_DIR":
			cfg.Debug.DebugCaptureDir = val
		case "DEBUG_CAPTURE_COOLDOWN":
			if d := parseDuration(val); d > 0 {
				cfg.Debug.DebugCaptureCooldown = d
			}
		case "DEBUG_CAPTURE_MAX_DURATION":
			if d := parseDuration(val); d > 0 {
				cfg.Debug.DebugCaptureMaxDuration = d
			}
		case "DEBUG_CAPTURE_RETENTION_COUNT":
			if n := parseInt(val); n > 0 {
				cfg.Debug.DebugCaptureRetentionCount = n
			}
		case "DEBUG_CAPTURE_RETENTION_AGE":
			if d := parseDuration(val); d > 0 {
				cfg.Debug.DebugCaptureRetentionAge = d
			}

		// --- MaxMind (GeoLite/GeoIP2 updater) ---
		case "MAXMIND_ENABLED":
			cfg.MaxMind.Enabled = parseBool(val)
		case "MAXMIND_SOURCE":
			cfg.MaxMind.Source = val
		case "MAXMIND_ACCOUNT_ID":
			cfg.MaxMind.AccountID = val
		case "MAXMIND_LICENSE_KEY":
			cfg.MaxMind.LicenseKey = val
		case "MAXMIND_EDITIONS":
			// e.g. GeoLite2-ASN,GeoLite2-City
			cfg.MaxMind.Editions = append(cfg.MaxMind.Editions, splitCSV(val)...)
		case "MAXMIND_DIR":
			cfg.MaxMind.Dir = val
		case "MAXMIND_CHECK_EVERY":
			if d := parseDuration(val); d > 0 {
				cfg.MaxMind.CheckEvery = d
			}
		case "MAXMIND_MIN_AGE":
			if d := parseDuration(val); d > 0 {
				cfg.MaxMind.MinAgeBetweenDL = d
			}
		case "MAXMIND_HTTP_TIMEOUT":
			if d := parseDuration(val); d > 0 {
				cfg.MaxMind.HTTPTimeout = d
			}
		case "MAXMIND_PERMALINKS_JSON":
			if m := parseStringMapJSON(val); m != nil {
				cfg.MaxMind.Permalinks = m
			}

		// SSLCollector unix socket (OpenResty ssl_certificate_by_lua)
		case "SSLCOLLECTOR_SOCK_ENABLE":
			cfg.SSLCollectorSock.Enabled = parseBool(val)
		case "SSLCOLLECTOR_SOCK_PATH":
			cfg.SSLCollectorSock.SockPath = val
		case "SSLCOLLECTOR_SOCK_TOKEN":
			cfg.SSLCollectorSock.Token = val
		case "SSLCOLLECTOR_LUA_TOKEN_PATH":
			cfg.SSLCollectorSock.LuaTokenPath = val
		case "SSLCOLLECTOR_SOCK_PEM_TTL":
			if d := parseDuration(val); d > 0 {
				cfg.SSLCollectorSock.PEMTTL = d
			}
		case "SSLCOLLECTOR_SOCK_PEM_MAX":
			cfg.SSLCollectorSock.PEMMax = parseInt(val)
		case "SSLCOLLECTOR_OFFLINE_CACHE":
			b := parseBool(val)
			cfg.SSLCollectorSock.OfflineCache = &b

		case "WAF_LOG_STDOUT":
			cfg.Logging.WAFStdout = parseBool(val)
		case "WAF_LOG_FILE":
			cfg.Logging.WAFFile = val

		case "MYSQL_LOG_STDOUT":
			cfg.Logging.MYSQLStdout = parseBool(val)
		case "MYSQL_LOG_FILE":
			cfg.Logging.MYSQLFile = val

			//CLAMAV
		case "CLAM_LOG_STDOUT":
			cfg.Logging.CLAMStdout = parseBool(val)
		case "CLAM_LOG_FILE":
			cfg.Logging.CLAMFile = val
		case "SOCKET_LOG_STDOUT":
			cfg.Logging.SOCKETStdout = parseBool(val)
		case "SOCKET_LOG_FILE":
			cfg.Logging.SOCKETFile = val
		case "LSM_LOG_STDOUT":
			cfg.Logging.LSMStdout = parseBool(val)
		case "LSM_LOG_FILE":
			cfg.Logging.LSMFile = val

		case "CLAMD_ENABLED":
			cfg.Clam.Enabled = parseBool(val)
		case "CLAM_SCAN_DEFAULT":
			cfg.Clam.ScanDefault = parseBool(val)
		case "CLAM_SCAN_SCOPE":
			// Only the two known values are accepted; anything else keeps the
			// archives default rather than silently disabling the gate.
			if s := strings.ToLower(strings.TrimSpace(val)); s == "archives" || s == "all" {
				cfg.Clam.ScanScope = s
			}
		case "CLAM_SCAN_MODE":
			// Only the two known values; anything else keeps the async default
			// (blocking must never arm via a typo).
			if s := strings.ToLower(strings.TrimSpace(val)); s == "async" || s == "inline" {
				cfg.Clam.ScanMode = s
			}
		case "CLAM_INLINE_TIMEOUT":
			if d, err := time.ParseDuration(strings.TrimSpace(val)); err == nil && d > 0 {
				cfg.Clam.InlineTimeout = d
			}
		case "CLAM_INLINE_DRY_RUN":
			cfg.Clam.InlineDryRun = parseBool(val)
		case "CLAM_SIG_IGNORE":
			// Comma-separated globs on the signature name. An explicit empty
			// value clears the default (act on every verdict).
			pats := make([]string, 0, 4)
			for _, p := range strings.Split(val, ",") {
				if p = strings.TrimSpace(p); p != "" {
					pats = append(pats, p)
				}
			}
			cfg.Clam.SigIgnore = pats
		case "CLAMD_NGINX_HOOK_ENABLED":
			cfg.Clam.NginxHookEnabled = parseBool(val)
		case "CLAMD_NETWORK":
			cfg.Clam.Network = strings.ToLower(strings.TrimSpace(val))
		case "CLAMD_SOCKET", "CLAMD_ADDRESS":
			cfg.Clam.Address = val
		case "CLAMD_TIMEOUT":
			if d, err := time.ParseDuration(strings.TrimSpace(val)); err == nil {
				cfg.Clam.Timeout = d
			}

		case "CLAMD_MAX_WORKERS":
			cfg.Clam.MaxWorkers = parseInt(val)
		case "CLAMD_QUEUE_SIZE":
			cfg.Clam.QueueSize = parseInt(val)

		case "CLAMD_PENDING_DIR":
			cfg.Clam.PendingDir = val
		case "CLAMD_INFECTED_DIR":
			cfg.Clam.InfectedDir = val

		// Hardening
		case "BLOCK_BAD_TCP_FLAGS":
			cfg.Hardening.BlockBadTCPFlags = parseBool(val)
		case "NEW_RATE":
			cfg.Hardening.NewRate = parseInt(val)
		case "NEW_BURST":
			cfg.Hardening.NewBurst = parseInt(val)
		case "ICMP_RATE_LIMIT":
			cfg.Hardening.ICMPRate = parseInt(val)
		case "ICMP_RATE_BURST":
			cfg.Hardening.ICMPBurst = parseInt(val)

		// System / Kernel Tweaks
		case "SYS_TWEAKS_ENABLE":
			cfg.SystemTweaks.Enable = parseBool(val)
		case "SYS_TWEAKS_PERSIST":
			cfg.SystemTweaks.Persist = parseBool(val)

		case "SYS_CT_PER_GB":
			cfg.SystemTweaks.CTPerGB = parseInt(val)
		case "SYS_CT_MIN":
			cfg.SystemTweaks.CTMin = parseInt(val)
		case "SYS_CT_MAX":
			cfg.SystemTweaks.CTMax = parseInt(val)

		case "SYS_TCP_LOOSE_STRICT":
			cfg.SystemTweaks.TCPLooseStrict = parseBool(val)
		case "SYS_TCP_SYN_RETRIES":
			cfg.SystemTweaks.TCPSynRetries = parseInt(val)
		case "SYS_TCP_SYNACK_RETRIES":
			cfg.SystemTweaks.TCPSynAckRetries = parseInt(val)
		case "SYS_TCP_FIN_TIMEOUT":
			cfg.SystemTweaks.TCPFinTimeout = parseInt(val)
		case "SYS_CT_TIMEWAIT":
			cfg.SystemTweaks.CTTimeWait = parseInt(val)
		case "SYS_CT_FINWAIT":
			cfg.SystemTweaks.CTFinWait = parseInt(val)
		case "SYS_CT_CLOSEWAIT":
			cfg.SystemTweaks.CTCloseWait = parseInt(val)

		case "SYS_RP_FILTER":
			cfg.SystemTweaks.RPFilter = parseInt(val)
		case "SYS_ACCEPT_REDIRECTS":
			cfg.SystemTweaks.AcceptRedirects = parseBool(val)
		case "SYS_SEND_REDIRECTS":
			cfg.SystemTweaks.SendRedirects = parseBool(val)
		case "SYS_ROUTE_LOCALNET":
			cfg.SystemTweaks.RouteLocalnet = parseBool(val)
		case "SYS_ROUTE_LOCALNET_IF":
			cfg.SystemTweaks.RouteLocalnetIF = val

		default:
			// Unknown key: keep forward-compat behavior, but warn for engine-like keys
			// so users don't silently misspell/rename firewall engine settings.
			if strings.Contains(key, "ENGINE") {
				log.Printf("config: warning: unrecognized engine-like key %q at line %d", key, lineNo)
			}
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if outboundDNSDeprecatedSeen {
		log.Printf("OUTBOUND_DNS_* is deprecated and ignored; DNS outbound detector has been removed")
	}
	cfg.SetDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// IsKnownKey reports whether key is currently recognized by cfm.conf parser.
func IsKnownKey(key string) bool {
	key = strings.ToUpper(strings.TrimSpace(key))
	switch key {
	case "API_URL", "AUTH_TOKEN", "TOKEN", "MCP_TOKEN", "AUTOBLOCK_SEND_TO_API", "MANUAL_BLOCK_SEND_TO_API", "UNBLOCK_SEND_TO_API", "DETECTORS_SEND_TO_API",
		"FIREWALL_ENGINE", "CFM_FIREWALL_ENGINE",
		"LOG_STDOUT", "LOG_FILE", "API_LOG_STDOUT", "API_LOG_FILE", "DETECTOR_LOG_STDOUT", "DETECTOR_LOG_FILE", "CHALLENGES_LOG_STDOUT", "CHALLENGES_LOG_FILE",
		"SMTP_LOG_STDOUT", "SMTP_LOG_FILE", "WAF_LOG_STDOUT", "WAF_LOG_FILE", "MYSQL_LOG_STDOUT", "MYSQL_LOG_FILE",
		"NFT_INPUT_PRIORITY", "NFT_DNAT_PRIORITY", "CHALLENGE_HTTP_LISTEN", "CHALLENGE_HTTPS_LISTEN", "TCP_IN", "TCP_OUT", "UDP_IN", "UDP_OUT", "CONNLIMIT", "PORTFLOOD", "PKT_RATE", "PKT_BURST", "PKT_MODE",
		"THROTTLE_ENABLED", "THROTTLE_WINDOW", "THROTTLE_HITS", "THROTTLE_MODE", "THROTTLE_TTL", "THROTTLE_SOURCES", "THROTTLE_SET_TTL", "THROTTLE_COOLDOWN",
		"PS_ENABLED", "PS_INTERVAL", "PS_MODE", "PS_TTL", "PS_LIMIT", "PS_DIVERSITY", "PS_TRACK_TCP", "PS_TRACK_UDP", "PS_ONLY_PORTS", "PS_PORTS",
		"SMTP_BLOCK", "SMTP_PORTS", "SMTP_ALLOWLOCAL", "SMTP_REDIRECT", "SMTP_REDIRECT_PORT", "SMTP_ALLOWUSER", "SMTP_ALLOWGROUP", "SMTP_ALLOW_UIDS", "SMTP_ALLOW_GIDS",
		"SMTP_LOG", "SMTP_LOG_LIMIT", "SMTP_LOG_BURST", "SMTP_LOG_NFLOG", "SMTP_LOG_ENRICH",
		"OUTBOUND_ENABLED", "OUTBOUND_NFLOG", "OUTBOUND_WINDOW_SECONDS", "OUTBOUND_SMTP_CONN_PER_MIN", "OUTBOUND_SCAN_UNIQUE_DST_PER_MIN", "OUTBOUND_HTTP_RATE_PER_MIN", "OUTBOUND_SMTP_PORTS", "OUTBOUND_SCAN_PORTS", "OUTBOUND_HTTP_PORTS", "OUTBOUND_LOG_DEDUP_SECONDS", "OUTBOUND_NOTIFY_SEVERITY", "OUTBOUND_QUEUE_SAMPLES", "OUTBOUND_ALLOW_USERS", "OUTBOUND_ALLOW_GROUPS", "OUTBOUND_ALLOW_UIDS", "OUTBOUND_ALLOW_GIDS", "OUTBOUND_LOG_ENRICH", "OUTBOUND_HTTP_ATTRIBUTION_ENABLED", "OUTBOUND_DNS_PER_MIN", "OUTBOUND_DNS_DEBUG_ENABLED", "OUTBOUND_DNS_DEBUG_SAMPLE_COUNT", "OUTBOUND_DNS_DEBUG_DURATION_SEC", "OUTBOUND_DNS_DEBUG_DIR",
		"LISTEN_ADDRESS", "PORT", "TLS_PORT", "TLS_LISTEN_ADDRESS",
		"AUTH_DB_PATH", "AUTH_SESSION_DB_PATH", "AUTH_MFA_ENCRYPTION_KEY", "AUTH_MFA_LOGIN_VERIFY_ENABLED", "AUTH_MFA_TOTP_ENROLL_ENABLED", "AUTH_MFA_TOTP_PILOT_USERS", "AUTH_SESSION_TTL", "AUTH_SECURE_COOKIE", "AUTH_COOKIE_NAME",
		"DEBUG_CAPTURE_ENABLED", "DEBUG_CAPTURE_DIR", "DEBUG_CAPTURE_COOLDOWN", "DEBUG_CAPTURE_MAX_DURATION", "DEBUG_CAPTURE_RETENTION_COUNT", "DEBUG_CAPTURE_RETENTION_AGE",
		"MAXMIND_ENABLED", "MAXMIND_SOURCE", "MAXMIND_ACCOUNT_ID", "MAXMIND_LICENSE_KEY", "MAXMIND_EDITIONS", "MAXMIND_DIR", "MAXMIND_CHECK_EVERY", "MAXMIND_MIN_AGE", "MAXMIND_HTTP_TIMEOUT", "MAXMIND_PERMALINKS_JSON",
		"SSLCOLLECTOR_SOCK_ENABLE", "SSLCOLLECTOR_SOCK_PATH", "SSLCOLLECTOR_SOCK_TOKEN", "SSLCOLLECTOR_SOCK_PEM_TTL", "SSLCOLLECTOR_SOCK_PEM_MAX", "SSLCOLLECTOR_OFFLINE_CACHE",
		"BLOCK_BAD_TCP_FLAGS", "NEW_RATE", "NEW_BURST", "ICMP_RATE_LIMIT", "ICMP_RATE_BURST",
		"CLAM_LOG_STDOUT", "CLAM_LOG_FILE", "SOCKET_LOG_STDOUT", "SOCKET_LOG_FILE",
		"LSM_LOG_STDOUT", "LSM_LOG_FILE",
		"CLAMD_ENABLED", "CLAMD_NGINX_HOOK_ENABLED", "CLAMD_NETWORK", "CLAMD_SOCKET", "CLAMD_ADDRESS", "CLAMD_TIMEOUT", "CLAMD_MAX_WORKERS", "CLAMD_QUEUE_SIZE",
		"SYS_TWEAKS_ENABLE", "SYS_TWEAKS_PERSIST", "SYS_CT_PER_GB", "SYS_CT_MIN", "SYS_CT_MAX", "SYS_TCP_LOOSE_STRICT", "SYS_TCP_SYN_RETRIES", "SYS_TCP_SYNACK_RETRIES", "SYS_TCP_FIN_TIMEOUT", "SYS_CT_TIMEWAIT", "SYS_CT_FINWAIT", "SYS_CT_CLOSEWAIT", "SYS_RP_FILTER", "SYS_ACCEPT_REDIRECTS", "SYS_SEND_REDIRECTS", "SYS_ROUTE_LOCALNET", "SYS_ROUTE_LOCALNET_IF":
		return true
	default:
		return false
	}
}

// --- Helpers (parsing & small utils) ---

func isComment(line string) bool {
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return true
	}
	// allow leading whitespace before //
	trim := strings.TrimSpace(line)
	return strings.HasPrefix(trim, "//")
}

func splitKV(line string) (k, v string, ok bool) {
	// Accept KEY=VALUE or KEY: VALUE
	if strings.Contains(line, "=") {
		parts := strings.SplitN(line, "=", 2)
		return parts[0], parts[1], true
	}
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		return parts[0], parts[1], true
	}
	return "", "", false
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func parseBool(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return false
	}
}

func parseInt(s string) int {
	i, _ := strconv.Atoi(strings.TrimSpace(s))
	return i
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = trimQuotes(stripInlineComment(strings.TrimSpace(p)))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseIntCSV parses comma-separated integers, ignoring blanks.
func parseIntCSV(s string) []int {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = trimQuotes(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if v, err := strconv.Atoi(p); err == nil {
			out = append(out, v)
		}
	}
	return out
}

// parseUint16CSV: "25,465,587"
// Parses as unsigned 16-bit directly to avoid int→uint16 narrowing.
// Skips zero (keeps your original <=0 skip) and invalid/out-of-range values.
func parseUint16CSV(s string) []uint16 {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]uint16, 0, len(parts))
	for _, p := range parts {
		p = trimQuotes(stripInlineComment(strings.TrimSpace(p)))
		if p == "" {
			continue
		}
		v, err := strconv.ParseUint(p, 10, 16) // only accept values that fit in 16 bits
		if err != nil || v == 0 {
			continue
		}
		out = append(out, uint16(v))
	}
	return out
}

// parseUint32CSV: "0,1001,1002"
func parseUint32CSV(s string) []uint32 {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]uint32, 0, len(parts))
	for _, p := range parts {
		p = trimQuotes(stripInlineComment(strings.TrimSpace(p)))
		if p == "" {
			continue
		}
		if v, err := strconv.ParseUint(p, 10, 32); err == nil {
			out = append(out, uint32(v))
		}
	}
	return out
}

// parsePorts understands formats like:
//
//	"22"            -> 22-22
//	"80-90" or "80:90" -> 80-90
//	"80;tcp, 53;udp" -> ignored here (proto handled elsewhere) — this function only parses numeric ranges
//
// If the value is a composite list like "22,80-90", it returns both entries.
// replace parsePorts with a 0..65535-friendly version
func parsePorts(s string) []PortRange {
	clamp16 := func(x int) int {
		if x < 0 {
			return 0
		}
		if x > 65535 {
			return 65535
		}
		return x
	}
	var out []PortRange
	for _, token := range strings.Split(s, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if i := strings.IndexByte(token, ';'); i >= 0 {
			token = token[:i]
		} // drop proto part

		sep := "-"
		if strings.Contains(token, ":") && !strings.Contains(token, "-") {
			sep = ":"
		}

		if strings.Contains(token, sep) {
			ab := strings.SplitN(token, sep, 2)
			if len(ab) == 2 {
				a := clamp16(parseInt(strings.TrimSpace(ab[0])))
				b := clamp16(parseInt(strings.TrimSpace(ab[1])))
				// now allow 0..65535
				if a > b {
					a, b = b, a
				}
				out = append(out, PortRange{From: a, To: b})
			}
		} else {
			p := clamp16(parseInt(token))
			out = append(out, PortRange{From: p, To: p})
		}
	}
	return out
}

// parseConnlimit parses rules like: "80;100" (legacy TCP-only) or "80;tcp;60"
func parseConnlimit(s string) []ConnlimitRule {
	var out []ConnlimitRule
	for _, token := range strings.Split(s, ",") {
		t := strings.TrimSpace(token)
		if t == "" {
			continue
		}
		fields := strings.Split(t, ";")
		// Support both: port;limit  (TCP-only, legacy)  and port;proto;limit
		if len(fields) == 2 {
			port := parseInt(fields[0])
			limit := parseInt(fields[1])
			if port > 0 && limit > 0 {
				out = append(out, ConnlimitRule{Proto: "tcp", Port: port, Limit: limit})
			}
			continue
		}
		if len(fields) >= 3 {
			port := parseInt(fields[0])
			proto := strings.ToLower(strings.TrimSpace(fields[1]))
			limit := parseInt(fields[2])
			if (proto == "tcp" || proto == "udp") && port > 0 && limit > 0 {
				out = append(out, ConnlimitRule{Proto: proto, Port: port, Limit: limit})
			}
		}
	}
	return out
}

// parsePortFlood parses rules like: "80;tcp;60;200" (port;proto;window;packets)
func parsePortFlood(s string) []PortFloodRule {
	var out []PortFloodRule
	for _, token := range strings.Split(s, ",") {
		t := strings.TrimSpace(token)
		if t == "" {
			continue
		}
		fields := strings.Split(t, ";")
		if len(fields) < 4 {
			// expect port;proto;window;packets
			continue
		}
		port := parseInt(fields[0])
		proto := strings.ToLower(strings.TrimSpace(fields[1]))
		window := parseInt(fields[2])
		pkts := parseInt(fields[3])
		if port <= 0 || window <= 0 || pkts <= 0 {
			continue
		}
		if proto != "tcp" && proto != "udp" {
			continue
		}
		out = append(out, PortFloodRule{Proto: proto, Port: port, WindowSec: window, Packets: pkts})
	}
	return out
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// κόβει inline σχόλια που ξεκινούν μετά από κενό: " # ..." ή " // ..."
// (δεν πειράζει "http://..." γιατί απαιτούμε προηγούμενο space)
func stripInlineComment(s string) string {
	cut := func(txt, token string) string {
		for {
			i := strings.Index(txt, token)
			if i < 0 {
				return txt
			}
			if i == 0 || txt[i-1] == ' ' || txt[i-1] == '\t' {
				return strings.TrimSpace(txt[:i])
			}
			// βρες επόμενο
			j := strings.Index(txt[i+len(token):], token)
			if j < 0 {
				return txt
			}
			txt = txt[:i+len(token)+j] + txt[i+len(token)+j:]
		}
	}
	// πρώτα " #", μετά " //"
	s = cut(s, " #")
	s = cut(s, " //")
	return strings.TrimSpace(s)
}

func (c *SystemTweaksConfig) SetDefaults() {
	if c.CTPerGB == 0 {
		c.CTPerGB = 12288
	}
	if c.CTMin == 0 {
		c.CTMin = 262144
	}
	if c.CTMax == 0 {
		c.CTMax = 16777216
	}
	if c.TCPSynRetries == 0 {
		c.TCPSynRetries = 3
	}
	if c.TCPSynAckRetries == 0 {
		c.TCPSynAckRetries = 3
	}
	if c.TCPFinTimeout == 0 {
		c.TCPFinTimeout = 20
	}
	if c.CTTimeWait == 0 {
		c.CTTimeWait = 30
	}
	if c.CTFinWait == 0 {
		c.CTFinWait = 45
	}
	if c.CTCloseWait == 0 {
		c.CTCloseWait = 60
	}
	// RPFilter default = 1
	if c.RPFilter == 0 {
		c.RPFilter = 1
	}
	// RouteLocalnet default: ON (safe + required for DNAT->127.0.0.1 patterns)
	// Only applied when SYS_TWEAKS_ENABLE=1.
	c.RouteLocalnet = true

}

// parseDuration parses Go-style durations like "24h", "30s", "168h".
// Returns 0 on error (caller decides on defaulting).
func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	if d < 0 {
		return 0
	}
	return d
}

// parseStringMapJSON parses a JSON object into map[string]string; returns nil on error.
func parseStringMapJSON(s string) map[string]string {
	var m map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(s)), &m); err != nil {
		return nil
	}
	return m
}
