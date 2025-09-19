package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Config is flat-by-category: one struct per logical area.
type Config struct {
	API        APIConfig
	Logging    LoggingConfig
	NFT        NFTConfig
	Ports      PortsConfig
	Connlimit  ConnlimitConfig
	PortFlood  PortFloodConfig
	PacketRate PacketRateConfig
	Throttle   ThrottleConfig
	Portscan   PortscanConfig
	SystemTweaks SystemTweaksConfig
	Hardening  HardeningConfig
	AckGuard AckGuardConfig
}

// --- Categories ---


type AckGuardConfig struct {
    Enabled bool            `conf:"ACKGUARD_ENABLED"`        // 1/0
    Rate    int             `conf:"ACKGUARD_RATE"`           // packets per second
    Burst   int             `conf:"ACKGUARD_BURST"`          // packets
    Ports   []PortRange     `conf:"ACKGUARD_PORTS"`          // same PortRange you use elsewhere

   // NEW toggles (all apply only to the Ports above)
    MatchInvalid    bool `conf:"ACKGUARD_MATCH_INVALID"`     // count+drop INVALID+ACK
    DropNonSynNew   bool `conf:"ACKGUARD_DROP_NONSYN_NEW"`   // drop NEW without SYN
    DropSynAckNew   bool `conf:"ACKGUARD_DROP_SYNACK_NEW"`   // drop unsolicited SYN-ACK
    RSTGuard        bool `conf:"ACKGUARD_RST_GUARD"`         // enable RST rules below
    RSTRate         int  `conf:"ACKGUARD_RST_RATE"`          // per-source RST rate (established)
    RSTBurst        int  `conf:"ACKGUARD_RST_BURST"`         // per-source RST burst
    FragGuard       bool `conf:"ACKGUARD_FRAG_GUARD"`        // drop TCP fragments to ports

  // Recent (tracking)
    RecentMode string // "dryrun"|"ttl"|"permanent"
    RecentTTL  int    // seconds when RecentMode == "ttl"

    // Action (blocking decision now)
    ActionMode string // "off"|"dryrun"|"ttl"|"permanent"
    ActionTTL  int    // seconds when ActionMode == "ttl"
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
}


type APIConfig struct {
	URL       string
	AuthToken string
	AutoBlockSend     bool // AUTOBLOCK_SEND_TO_API
	ManualBlockSend   bool // MANUAL_BLOCK_SEND_TO_API
	UnblockSend       bool // UNBLOCK_SEND_TO_API
}

type LoggingConfig struct {
	Stdout bool   // true = log to stdout (LOG_STDOUT)
	File   string // path to logfile, "" = disabled (LOG_FILE)
	APIStdout bool   // API_LOG_STDOUT: αν δεν οριστεί, θα κληρονομήσει το Stdout
	APIFile   string // API_LOG_FILE: path για API log, "" = derive από File (π.χ. /var/log/cfm.api.log)
        DETECTORStdout bool
        DETECTORFile   string

}

type NFTConfig struct {
	InputPriority int // clamped -300..+300
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
	Enabled    bool
	WindowSec  int
	Hits       int
	Mode       string   // "permanent" | "ttl"
	TTLSeconds int
	Sources    []string // e.g. ["syn","portflood","pps"]
	SetTTL     int      // seconds for nft set timeout (tracking)
}

type PortscanConfig struct {
	Enabled    bool
	Interval   int    // seconds between scans/rotations; 0 disables if Enabled not set explicitly
	Mode       string // "temporary" | "permanent" | "alert"
	TTLSeconds int
	Limit      int    // distinct ports threshold
	Diversity  int    // >=1 persistent port presence
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
	// NFT
	c.NFT.InputPriority = clamp(c.NFT.InputPriority, -300, 300)
	// PacketRate
	if c.PacketRate.Mode == "" { c.PacketRate.Mode = "syn" }
	if c.PacketRate.Burst < 0 { c.PacketRate.Burst = 0 }
	if c.PacketRate.Rate < 0 { c.PacketRate.Rate = 0 }
	// Throttle
	if c.Throttle.WindowSec == 0 { c.Throttle.WindowSec = 120 }
	if c.Throttle.Hits == 0 { c.Throttle.Hits = 3 }
	if c.Throttle.Mode == "" { c.Throttle.Mode = "permanent" }

c.Throttle.Mode = strings.ToLower(c.Throttle.Mode)
 switch c.Throttle.Mode {
 case "permanent", "ttl", "dryrun", "alert":
     // ok
 default:
     c.Throttle.Mode = "permanent"
 }
	if c.Throttle.TTLSeconds == 0 { c.Throttle.TTLSeconds = 24 * 3600 }
	if c.Throttle.SetTTL == 0 { c.Throttle.SetTTL = 60 }
	// Portscan
	if c.Portscan.Interval == 0 { c.Portscan.Interval = 60 }
	if c.Portscan.Mode == "" { c.Portscan.Mode = "ttl" }
	if c.Portscan.TTLSeconds == 0 { c.Portscan.TTLSeconds = 3600 }
	if c.Portscan.Limit == 0 { c.Portscan.Limit = 10 }
	if c.Portscan.Diversity == 0 { c.Portscan.Diversity = 1 }
	// If PS_ENABLED not set explicitly, infer from interval>0
	if !c.Portscan.Enabled && c.Portscan.Interval > 0 { c.Portscan.Enabled = true }

// Hardening
if c.Hardening.NewRate < 0 { c.Hardening.NewRate = 0 }
if c.Hardening.NewBurst < 0 { c.Hardening.NewBurst = 0 }
if c.Hardening.ICMPRate < 0 { c.Hardening.ICMPRate = 0 }
if c.Hardening.ICMPBurst < 0 { c.Hardening.ICMPBurst = 0 }



  // AckGuard defaults
    if c.AckGuard.RecentMode == "" {
        c.AckGuard.RecentMode = "ttl"
    }
    switch c.AckGuard.RecentMode {
    case "dryrun", "ttl", "permanent":
        // ok
    default:
        c.AckGuard.RecentMode = "ttl"
    }
    if c.AckGuard.RecentMode == "ttl" && c.AckGuard.RecentTTL <= 0 {
        c.AckGuard.RecentTTL = 3600
    }

    if c.AckGuard.ActionMode == "" {
        c.AckGuard.ActionMode = "off"
    }
    switch c.AckGuard.ActionMode {
    case "off", "dryrun", "ttl", "permanent":
        // ok
    default:
        c.AckGuard.ActionMode = "off"
    }
    if c.AckGuard.ActionMode == "ttl" && c.AckGuard.ActionTTL <= 0 {
        c.AckGuard.ActionTTL = 86400
    }



}

// Validate clamps, normalizes and ensures cross-field coherence.
func (c *Config) Validate() error {
	c.NFT.InputPriority = clamp(c.NFT.InputPriority, -300, 300)
	if c.PacketRate.Mode != "syn" && c.PacketRate.Mode != "all" {
		c.PacketRate.Mode = "syn"
	}
	if c.Throttle.Hits < 0 || c.Throttle.WindowSec < 0 || c.Throttle.TTLSeconds < 0 || c.Throttle.SetTTL < 0 {
		return errors.New("negative values not allowed in Throttle config")
	}
	if c.Portscan.Interval < 0 || c.Portscan.TTLSeconds < 0 || c.Portscan.Limit < 0 || c.Portscan.Diversity < 0 {
		return errors.New("negative values not allowed in Portscan config")
	}
	// Normalize mode
	if c.Portscan.Mode != "temporary" && c.Portscan.Mode != "permanent" && c.Portscan.Mode != "alert" {
		c.Portscan.Mode = "ttl" // backwards-compat alias; will be interpreted by code that treats ttl/permanent
	}
	return nil
}

// ParseCFMConf parses a flat key=value configuration from r into Config.
// Lines starting with '#' or ';' or '//' are treated as comments.
func ParseCFMConf(r io.Reader) (*Config, error) {
	s := bufio.NewScanner(r)
	cfg := &Config{}
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

case "AUTOBLOCK_SEND_TO_API":
    cfg.API.AutoBlockSend = parseBool(val)
case "MANUAL_BLOCK_SEND_TO_API":
    cfg.API.ManualBlockSend = parseBool(val)
case "UNBLOCK_SEND_TO_API":
    cfg.API.UnblockSend = parseBool(val)

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


		// NFT
		case "NFT_INPUT_PRIORITY":
			cfg.NFT.InputPriority = clamp(parseInt(val), -300, 300)


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





    // --- ACKGUARD ---
    case "ACKGUARD_ENABLED":
        cfg.AckGuard.Enabled = (val == "1" || strings.ToLower(val) == "true")
    case "ACKGUARD_RATE":
        if n, err := strconv.Atoi(val); err == nil {
            cfg.AckGuard.Rate = n
        }
    case "ACKGUARD_BURST":
        if n, err := strconv.Atoi(val); err == nil {
            cfg.AckGuard.Burst = n
        }
    case "ACKGUARD_PORTS":
        cfg.AckGuard.Ports = append(cfg.AckGuard.Ports, parsePorts(val)...)
    case "ACKGUARD_MATCH_INVALID":
        cfg.AckGuard.MatchInvalid = (val == "1" || strings.ToLower(val) == "true")

    case "ACKGUARD_DROP_NONSYN_NEW":
        cfg.AckGuard.DropNonSynNew = (val == "1" || strings.ToLower(val) == "true")

    case "ACKGUARD_DROP_SYNACK_NEW":
        cfg.AckGuard.DropSynAckNew = (val == "1" || strings.ToLower(val) == "true")

    case "ACKGUARD_RST_GUARD":
        cfg.AckGuard.RSTGuard = (val == "1" || strings.ToLower(val) == "true")

    case "ACKGUARD_RST_RATE":
        if n, err := strconv.Atoi(val); err == nil {
            cfg.AckGuard.RSTRate = n
        }

    case "ACKGUARD_RST_BURST":
        if n, err := strconv.Atoi(val); err == nil {
            cfg.AckGuard.RSTBurst = n
        }

    case "ACKGUARD_FRAG_GUARD":
        cfg.AckGuard.FragGuard = (val == "1" || strings.ToLower(val) == "true")





  // --- ACKGUARD (modes & ttls) ---
    case "ACKGUARD_RECENT_MODE":
        v := strings.ToLower(val)
        switch v {
        case "dryrun", "ttl", "permanent":
            cfg.AckGuard.RecentMode = v
        default:
            cfg.AckGuard.RecentMode = "ttl"
        }

    case "ACKGUARD_RECENT_TTL":
        cfg.AckGuard.RecentTTL = parseInt(val)

    case "ACKGUARD_ACTION_MODE":
        v := strings.ToLower(val)
        switch v {
        case "off", "dryrun", "ttl", "permanent":
            cfg.AckGuard.ActionMode = v
        default:
            cfg.AckGuard.ActionMode = "off"
        }

    case "ACKGUARD_ACTION_TTL":
        cfg.AckGuard.ActionTTL = parseInt(val)







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



		default:
			// Unknown key: ignore (forward-compat) or return error if you prefer
			// fmt.Printf("config: warning: unknown key %q at line %d", key, lineNo)
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	cfg.SetDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
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

// parsePorts understands formats like:
//   "22"            -> 22-22
//   "80-90" or "80:90" -> 80-90
//   "80;tcp, 53;udp" -> ignored here (proto handled elsewhere) — this function only parses numeric ranges
// If the value is a composite list like "22,80-90", it returns both entries.
// replace parsePorts with a 0..65535-friendly version
func parsePorts(s string) []PortRange {
    clamp16 := func(x int) int {
        if x < 0 { return 0 }
        if x > 65535 { return 65535 }
        return x
    }
    var out []PortRange
    for _, token := range strings.Split(s, ",") {
        token = strings.TrimSpace(token)
        if token == "" { continue }
        if i := strings.IndexByte(token, ';'); i >= 0 { token = token[:i] } // drop proto part

        sep := "-"
        if strings.Contains(token, ":") && !strings.Contains(token, "-") { sep = ":" }

        if strings.Contains(token, sep) {
            ab := strings.SplitN(token, sep, 2)
            if len(ab) == 2 {
                a := clamp16(parseInt(strings.TrimSpace(ab[0])))
                b := clamp16(parseInt(strings.TrimSpace(ab[1])))
                // now allow 0..65535
                if a > b { a, b = b, a }
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
		if t == "" { continue }
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
            if i < 0 { return txt }
            if i == 0 || txt[i-1] == ' ' || txt[i-1] == '\t' {
                return strings.TrimSpace(txt[:i])
            }
            // βρες επόμενο
            j := strings.Index(txt[i+len(token):], token)
            if j < 0 { return txt }
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

}


