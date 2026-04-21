package traffic

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	nfConntrackPath = "/proc/net/nf_conntrack"
	ipConntrackPath = "/proc/net/ip_conntrack"
)

// ConntrackCollector reads kernel conntrack flow state from procfs.
type ConntrackCollector struct {
	path string
	now  func() time.Time
}

// NewConntrackCollector initializes a conntrack-backed collector.
func NewConntrackCollector() (*ConntrackCollector, error) {
	for _, p := range []string{nfConntrackPath, ipConntrackPath} {
		if _, err := os.Stat(p); err == nil {
			return &ConntrackCollector{path: p, now: time.Now}, nil
		}
	}
	return nil, fmt.Errorf("conntrack procfs not found (checked %s and %s)", nfConntrackPath, ipConntrackPath)
}

func (c *ConntrackCollector) Collect(ctx context.Context) ([]FlowSample, error) {
	f, err := os.Open(c.path)
	if err != nil {
		if c.path == nfConntrackPath {
			if _, stErr := os.Stat(ipConntrackPath); stErr == nil {
				c.path = ipConntrackPath
				f, err = os.Open(c.path)
			}
		}
		if err != nil {
			return nil, err
		}
	}
	defer f.Close()

	nowUnix := c.now().Unix()
	flows := make([]FlowSample, 0, 256)
	s := bufio.NewScanner(f)
	for s.Scan() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		flow, ok := parseConntrackLine(s.Text(), nowUnix)
		if ok {
			flows = append(flows, flow)
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return flows, nil
}

func parseConntrackLine(line string, nowUnix int64) (FlowSample, bool) {
	fields := strings.Fields(line)
	if len(fields) < 7 {
		return FlowSample{}, false
	}

	protocol := strings.ToLower(fields[2])
	state := fields[5]
	if strings.HasPrefix(state, "[") {
		state = strings.Trim(state, "[]")
	}

	attrs := map[string][]string{}
	for _, f := range fields[6:] {
		eq := strings.IndexByte(f, '=')
		if eq <= 0 || eq == len(f)-1 {
			continue
		}
		k := f[:eq]
		v := f[eq+1:]
		attrs[k] = append(attrs[k], v)
	}

	src := firstAttr(attrs, "src", 0)
	dst := firstAttr(attrs, "dst", 0)
	if src == "" || dst == "" {
		return FlowSample{}, false
	}

	sport := parseUint16(firstAttr(attrs, "sport", 0))
	dport := parseUint16(firstAttr(attrs, "dport", 0))
	inBytes := parseUint64(firstAttr(attrs, "bytes", 0))
	outBytes := parseUint64(firstAttr(attrs, "bytes", 1))

	flowID := fmt.Sprintf("%s|%s:%d|%s:%d|%s", protocol, src, sport, dst, dport, state)

	return FlowSample{
		FlowID:         flowID,
		Protocol:       protocol,
		SrcIP:          src,
		SrcPort:        sport,
		DstIP:          dst,
		DstPort:        dport,
		State:          state,
		InBytes:        inBytes,
		OutBytes:       outBytes,
		ProcessName:    "unknown",
		PID:            0,
		LastSeenUnix:   nowUnix,
		ConnectionUnit: 1,
	}, true
}

func firstAttr(attrs map[string][]string, key string, idx int) string {
	vals := attrs[key]
	if idx < 0 || idx >= len(vals) {
		return ""
	}
	return vals[idx]
}

func parseUint16(s string) uint16 {
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(v)
}

func parseUint64(s string) uint64 {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}
