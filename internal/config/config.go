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
	Synproxy   SynproxyConfig
}

// --- Categories ---
type SynproxyConfig struct {
	Enable    bool   // SYNPROXY_ENABLE
	AutoTCPIn bool   // SYNPROXY_AUTO_TCP_IN
	Ports     []int  // SYNPROXY_PORTS (comma-separated)
	MSS       int    // SYNPROXY_MSS
	WScale    int    // SYNPROXY_WSCALE
	SACK      bool   // SYNPROXY_SACK
	TStamp    bool   // SYNPROXY_TSTAMP
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
}

type LoggingConfig struct {
	Stdout bool   // true = log to stdout (LOG_STDOUT)
	File   string // path to logfile, "" = disabled (LOG_FILE)
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
	if c.Throttle.Mode != "permanent" && c.Throttle.Mode != "ttl" { c.Throttle.Mode = "permanent" }
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

		// Logging
		case "LOG_STDOUT":
			cfg.Logging.Stdout = parseBool(val)
		case "LOG_FILE":
			cfg.Logging.File = val

		// NFT
		case "NFT_INPUT_PRIORITY":
			cfg.NFT.InputPriority = clamp(parseInt(val), -300, 300)

		// Ports
		case "TCP_IN":
			cfg.Ports.TCPIn = parsePorts(val)
		case "TCP_OUT":
			cfg.Ports.TCPOut = parsePorts(val)
		case "UDP_IN":
			cfg.Ports.UDPIn = parsePorts(val)
		case "UDP_OUT":
			cfg.Ports.UDPOut = parsePorts(val)

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


case "SYNPROXY_ENABLE":
	cfg.Synproxy.Enable = parseBool(val)
case "SYNPROXY_AUTO_TCP_IN":
	cfg.Synproxy.AutoTCPIn = parseBool(val)
case "SYNPROXY_PORTS":
	// parse comma-separated ints
	if strings.TrimSpace(val) != "" {
		var out []int
		for _, t := range strings.Split(val, ",") {
			if p := parseInt(strings.TrimSpace(t)); p > 0 { out = append(out, p) }
		}
		cfg.Synproxy.Ports = out
	}
case "SYNPROXY_MSS":
	cfg.Synproxy.MSS = parseInt(val)
case "SYNPROXY_WSCALE":
	cfg.Synproxy.WScale = parseInt(val)
case "SYNPROXY_SACK":
	cfg.Synproxy.SACK = parseBool(val)
case "SYNPROXY_TSTAMP":
	cfg.Synproxy.TStamp = parseBool(val)

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


func (s *SynproxyConfig) SetDefaults() {
	if s.MSS == 0 { s.MSS = 1440 }
	if s.WScale == 0 { s.WScale = 7 }
	// Αν δεν οριστούν, θεώρησε enabled για SACK/TStamp (σύμφωνα με το πρότυπο μας)
	// αλλά ΜΟΝΟ αν έχουν ενεργοποιηθεί γενικά τα synproxy rules.
	if s.Enable {
		// keep explicit false if user set "0"
		if !s.SACK && !s.TStamp {
			s.SACK, s.TStamp = true, true
		}
	}
}




