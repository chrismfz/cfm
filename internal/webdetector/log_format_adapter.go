package webdetector

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LogFormatAdapter converts various formats into LogRec.
type LogFormatAdapter interface {
	Parse(line string) (LogRec, bool)
}

// AutoDetectAdapter tries TSV first, then Combined.
type AutoDetectAdapter struct {
	combined *CombinedAdapter
}

func NewAutoDetectAdapter() *AutoDetectAdapter {
	return &AutoDetectAdapter{
		combined: NewCombinedAdapter(),
	}
}

// stripHostPrefix extracts "@host=example.com\t" if present.
func stripHostPrefix(line string) (host string, rest string) {
	if strings.HasPrefix(line, "@host=") {
		// @host=<h>\t<rest>
		if i := strings.IndexByte(line, '\t'); i > 6 {
			host = strings.TrimPrefix(line[:i], "@host=")
			rest = line[i+1:]
			return host, rest
		}
	}
	return "", line
}

func (a *AutoDetectAdapter) Parse(line string) (LogRec, bool) {
	hostHint, raw := stripHostPrefix(line)

	// cheap TSV check: lots of tabs
	if strings.Count(raw, "\t") >= 6 {
		if rec, ok := parseTSV(raw); ok {
			return rec, true
		}
	}

	// combined fallback
	rec, ok := a.combined.Parse(raw)
	if !ok {
		return LogRec{}, false
	}
	if rec.Host == "" && hostHint != "" {
		rec.Host = hostHint
	}
	return rec, true
}

// CombinedAdapter parses Apache/nginx combined format:
// IP - - [timestamp] "METHOD URI PROTO" STATUS BYTES "REFERER" "UA"
type CombinedAdapter struct {
	pattern *regexp.Regexp
}

func NewCombinedAdapter() *CombinedAdapter {
	// groups:
	// 1 ip
	// 2 ts
	// 3 method
	// 4 uri
	// 5 proto (optional)
	// 6 status
	// 7 bytes (- allowed)
	// 8 referer
	// 9 ua
	p := regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)(?:\s+(\S+))?"\s+(\d{3})\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"`)
	return &CombinedAdapter{pattern: p}
}

func (a *CombinedAdapter) Parse(line string) (LogRec, bool) {
	m := a.pattern.FindStringSubmatch(line)
	if m == nil || len(m) < 10 {
		return LogRec{}, false
	}

	ip := m[1]
	tsRaw := m[2]
	method := m[3]
	uri := m[4]
	proto := m[5]
	statusStr := m[6]
	bytesStr := m[7]
	ref := m[8]
	ua := m[9]

	ts := parseApacheTimestamp(tsRaw)
	status, _ := strconv.Atoi(statusStr)

	var bytes int64
	if bytesStr != "-" {
		bytes, _ = strconv.ParseInt(bytesStr, 10, 64)
	}

	return LogRec{
		TS:     ts,
		IP:     ip,
		Host:   "", // filled by host prefix when available
		Method: strings.ToLower(method),
		URI:    strings.ToLower(uri),
		Proto:  strings.ToLower(proto),
		Status: status,
		Bytes:  bytes,
		RT:     0,
		URT:    0,
		UA:     strings.ToLower(ua),
		Ref:    strings.ToLower(ref),
	}, true
}

// Apache timestamp: 09/Feb/2026:16:01:54 -0800
func parseApacheTimestamp(ts string) float64 {
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", ts)
	if err != nil {
		return float64(time.Now().Unix())
	}
	return float64(t.Unix()) + float64(t.Nanosecond())/1e9
}
