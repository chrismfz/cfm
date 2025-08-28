package config

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type PortRange struct{ From, To int }
type PortsConfig struct {
	TCPIn  []PortRange
	TCPOut []PortRange
	UDPIn  []PortRange
	UDPOut []PortRange

	Flood  FloodConfig
}

// ConnlimitRule = "limit;port"
type ConnlimitRule struct {
	Port  int
	Proto string
	Limit int
}

type PortFloodRule struct {
	Port     int
	Proto    string
	Interval int // seconds
	Max      int // max new conns per interval
}

type FloodConfig struct {
	Connlimit []ConnlimitRule
	PortFlood []PortFloodRule
}


// default: "0:65535" = όλα
func defaultAny() []PortRange { return []PortRange{{0, 65535}} }

func ParseCFMConf(r io.Reader) (*PortsConfig, error) {
	cfg := &PortsConfig{
		TCPIn:  defaultAny(),
		TCPOut: defaultAny(),
		UDPIn:  defaultAny(),
		UDPOut: defaultAny(),

	}
	sc := bufio.NewScanner(r)
	ln := 0
	for sc.Scan() {
		ln++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") { continue }
		// μορφή: KEY = "val"  ή  KEY = val
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 { continue }
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"`) // βγάλε προαιρετικά quotes




        switch strings.ToUpper(key) {
        case "TCP_IN", "TCP_OUT", "UDP_IN", "UDP_OUT":
                prs, err := parsePortsList(val)
                if err != nil { return nil, fmt.Errorf("line %d: %w", ln, err) }
                switch strings.ToUpper(key) {
                case "TCP_IN":
                        cfg.TCPIn = prs
                case "TCP_OUT":
                        cfg.TCPOut = prs
                case "UDP_IN":
                        cfg.UDPIn = prs
                case "UDP_OUT":
                        cfg.UDPOut = prs
                }

case "CONNLIMIT":
    cfg.Flood.Connlimit = append(cfg.Flood.Connlimit, parseConnlimit(val)...)
case "PORTFLOOD":
    cfg.Flood.PortFlood = append(cfg.Flood.PortFlood, parsePortFlood(val)...)

        default:
                // αγνόησέ το (future keys)
        }




	}
	return cfg, sc.Err()
}

func parsePortsList(s string) ([]PortRange, error) {
	if strings.TrimSpace(s) == "" {
		return []PortRange{}, nil
	}
	var out []PortRange
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" { continue }
		// δέξου "80", "0:65535", "7770:7800"
		var from, to int
		if strings.Contains(tok, ":") || strings.Contains(tok, "-") {
			sep := ":"
			if strings.Contains(tok, "-") { sep = "-" }
			parts := strings.SplitN(tok, sep, 2)
			if len(parts) != 2 { return nil, fmt.Errorf("bad range %q", tok) }
			f, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			t, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil || f < 0 || t < 0 || f > 65535 || t > 65535 || f > t {
				return nil, fmt.Errorf("bad range %q", tok)
			}
			from, to = f, t
		} else {
			// single port
			p, err := strconv.Atoi(tok)
			if err != nil || p < 0 || p > 65535 { return nil, fmt.Errorf("bad port %q", tok) }
			from, to = p, p
		}
		out = append(out, PortRange{From: from, To: to})
	}
	return out, nil
}


//connlimit helpers
func parseConnlimit(s string) []ConnlimitRule {
	var out []ConnlimitRule
	for _, tok := range strings.Split(s, ",") {
		parts := strings.Split(tok, ";")
		if len(parts) != 2 { continue }
		lim, _ := strconv.Atoi(parts[0])
		port, _ := strconv.Atoi(parts[1])
		out = append(out, ConnlimitRule{Port: port, Proto: "tcp", Limit: lim})
	}
	return out
}

func parsePortFlood(s string) []PortFloodRule {
	var out []PortFloodRule
	for _, tok := range strings.Split(s, ",") {
		parts := strings.Split(tok, ";")
		if len(parts) != 4 { continue }
		port, _ := strconv.Atoi(parts[0])
		proto := parts[1]
		interval, _ := strconv.Atoi(parts[2])
		limit, _ := strconv.Atoi(parts[3])
		out = append(out, PortFloodRule{Port: port, Proto: proto, Interval: interval, Max: limit})
	}
	return out
}

//for debugging//
