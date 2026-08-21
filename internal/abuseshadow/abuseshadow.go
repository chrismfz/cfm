// Package abuseshadow reads and aggregates the LOG-ONLY abuse-shadow log
// (/var/log/cfm/cfm.abuse_shadow.log) that the web detector's entity-abuse
// signals write (Signal C rate outliers, …; see docs/webdetector-refactor.md).
// It backs the read-only `abuse_shadow` MCP tool: a bounded on-demand tail +
// pure aggregation that answers "what would the shadow signals have challenged,
// and how much of it is verified good-bot / datacenter?" during burn-in, before
// any of it is promoted to a real challenge.
//
// Same cost discipline as the other on-demand log readers (maillog/mysqllog/
// edgelog): nothing retained, a call reads only the last N lines via `tail -n N`
// under a timeout. Parsing is pure and unit-tested.
package abuseshadow

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// LogPath is the fixed abuse-shadow log location (matches internal/logging).
const LogPath = "/var/log/cfm/cfm.abuse_shadow.log"

const (
	defaultLines = 5000
	maxLines     = 200000
	scanTimeout  = 20 * time.Second
	readerBuf    = 1024 * 1024
)

// Entry is one parsed shadow line.
type Entry struct {
	Signal   string  `json:"signal"`
	Host     string  `json:"host"`
	IP       string  `json:"ip"`
	RPS      float64 `json:"rps"`
	Ratio    float64 `json:"ratio"`
	Reqs     int     `json:"reqs"`
	ASN      uint    `json:"asn"`
	Provider string  `json:"provider"`
	GoodBot  string  `json:"good_bot"`
	Verdict  string  `json:"verdict"`
}

// Parse extracts an Entry from one log line. Returns ok=false for a line that
// isn't an abuse-shadow marker. The marker's values contain no spaces (host/ip/
// tags/numbers only), so a simple space-split of the `key=value` tail is exact.
func Parse(line string) (Entry, bool) {
	i := strings.Index(line, "[abuse-shadow] ")
	if i < 0 {
		return Entry{}, false
	}
	fields := strings.Fields(line[i+len("[abuse-shadow] "):])
	var e Entry
	got := false
	for _, f := range fields {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		got = true
		switch k {
		case "signal":
			e.Signal = v
		case "host":
			e.Host = v
		case "ip":
			e.IP = v
		case "rps":
			e.RPS, _ = strconv.ParseFloat(v, 64)
		case "ratio":
			e.Ratio, _ = strconv.ParseFloat(v, 64)
		case "reqs":
			e.Reqs, _ = strconv.Atoi(v)
		case "asn":
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				e.ASN = uint(n)
			}
		case "provider":
			e.Provider = dash(v)
		case "good_bot":
			e.GoodBot = dash(v)
		case "verdict":
			e.Verdict = v
		}
	}
	if !got || e.Signal == "" {
		return Entry{}, false
	}
	return e, true
}

func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// kv is a {key,count} pair for the top-N breakdowns.
type kv struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// topEntity is one would-challenge target with its peak observed strength.
type topEntity struct {
	Host     string  `json:"host"`
	IP       string  `json:"ip"`
	Hits     int     `json:"hits"`      // shadow log lines for this (host,ip)
	MaxRatio float64 `json:"max_ratio"` // peak rps/median seen
	MaxReqs  int     `json:"max_reqs"`
	Provider string  `json:"provider,omitempty"`
	GoodBot  string  `json:"good_bot,omitempty"`
}

// Summary is the aggregate the endpoint returns.
type Summary struct {
	Total          int         `json:"total"`
	WouldChallenge int         `json:"would_challenge"`
	ExemptGoodbot  int         `json:"exempt_goodbot"`
	UniqueHosts    int         `json:"unique_hosts"`
	UniqueIPs      int         `json:"unique_ips"`
	BySignal       []kv        `json:"by_signal"`
	ByVerdict      []kv        `json:"by_verdict"`
	ByProvider     []kv        `json:"by_provider"` // datacenter tag distribution (would_challenge only)
	ByGoodbot      []kv        `json:"by_good_bot"` // which good bots were exempted
	TopWouldBlock  []topEntity `json:"top_would_challenge"`
}

// Summarize aggregates parsed lines. It ranks the top would_challenge entities
// by peak ratio (the strongest outliers), and keeps the provider/good-bot splits
// so an operator can see how much of the shadow is datacenter or verified bots.
func Summarize(lines []string) Summary {
	var s Summary
	bySignal := map[string]int{}
	byVerdict := map[string]int{}
	byProvider := map[string]int{}
	byGoodbot := map[string]int{}
	hosts := map[string]struct{}{}
	ips := map[string]struct{}{}
	ent := map[string]*topEntity{} // key host|ip, would_challenge only

	for _, ln := range lines {
		e, ok := Parse(ln)
		if !ok {
			continue
		}
		s.Total++
		bySignal[e.Signal]++
		byVerdict[e.Verdict]++
		if e.Host != "" {
			hosts[e.Host] = struct{}{}
		}
		if e.IP != "" {
			ips[e.IP] = struct{}{}
		}
		switch e.Verdict {
		case "would_challenge":
			s.WouldChallenge++
			if e.Provider != "" {
				byProvider[e.Provider]++
			}
			k := e.Host + "|" + e.IP
			t := ent[k]
			if t == nil {
				t = &topEntity{Host: e.Host, IP: e.IP, Provider: e.Provider}
				ent[k] = t
			}
			t.Hits++
			if e.Ratio > t.MaxRatio {
				t.MaxRatio = e.Ratio
			}
			if e.Reqs > t.MaxReqs {
				t.MaxReqs = e.Reqs
			}
		case "exempt_goodbot":
			s.ExemptGoodbot++
			if e.GoodBot != "" {
				byGoodbot[e.GoodBot]++
			}
		}
	}
	s.UniqueHosts = len(hosts)
	s.UniqueIPs = len(ips)
	s.BySignal = topKV(bySignal, 20)
	s.ByVerdict = topKV(byVerdict, 20)
	s.ByProvider = topKV(byProvider, 20)
	s.ByGoodbot = topKV(byGoodbot, 20)

	tops := make([]topEntity, 0, len(ent))
	for _, t := range ent {
		tops = append(tops, *t)
	}
	sort.Slice(tops, func(i, j int) bool {
		if tops[i].MaxRatio != tops[j].MaxRatio {
			return tops[i].MaxRatio > tops[j].MaxRatio
		}
		return tops[i].MaxReqs > tops[j].MaxReqs
	})
	if len(tops) > 25 {
		tops = tops[:25]
	}
	s.TopWouldBlock = tops
	return s
}

func topKV(m map[string]int, limit int) []kv {
	out := make([]kv, 0, len(m))
	for k, c := range m {
		out = append(out, kv{Key: k, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ScanTail streams the last `lines` lines of the abuse-shadow log to fn. Returns
// the resolved log file ("" when it doesn't exist — not an error), the number of
// lines scanned, and any error. Bounded `tail -n N` backward read + timeout.
func ScanTail(ctx context.Context, lines int, fn func(string)) (logFile string, scanned int, err error) {
	if lines <= 0 {
		lines = defaultLines
	}
	if lines > maxLines {
		lines = maxLines
	}
	if fi, e := os.Stat(LogPath); e != nil || !fi.Mode().IsRegular() {
		return "", 0, nil // no log yet (feature off / never fired) → not an error
	}
	cctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, tailPath(), "-n", fmt.Sprintf("%d", lines), LogPath)
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		return LogPath, 0, e
	}
	if e := cmd.Start(); e != nil {
		stdout.Close()
		return LogPath, 0, e
	}
	r := bufio.NewReaderSize(stdout, readerBuf)
	for {
		chunk, rerr := r.ReadSlice('\n')
		if len(chunk) > 0 {
			scanned++
			fn(strings.TrimRight(string(chunk), "\r\n"))
		}
		if rerr != nil {
			if rerr == bufio.ErrBufferFull {
				// over-long line: drain to next newline, keep going
				for rerr == bufio.ErrBufferFull {
					_, rerr = r.ReadSlice('\n')
				}
				if rerr == nil {
					continue
				}
			}
			break
		}
	}
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if cctx.Err() != nil {
		return LogPath, scanned, fmt.Errorf("scan timed out after %s", scanTimeout)
	}
	if waitErr != nil {
		return LogPath, scanned, fmt.Errorf("tail failed: %v", waitErr)
	}
	return LogPath, scanned, nil
}

func tailPath() string {
	if p, err := exec.LookPath("tail"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/bin/tail", "/bin/tail"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "tail"
}
