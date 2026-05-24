// internal/webdetector/ua_top.go
//
// Aggregation methods for the bot-top control surface. Mirrors the per-host
// and per-IP aggregations elsewhere in this package, but keyed on the
// normalized User-Agent (see ua_norm.go). All data comes from the short
// window already maintained by ingest().
package webdetector

import (
	"sort"
	"strings"
	"time"
)

// UATopRow is one row in the bot-top live view.
type UATopRow struct {
	UA        string  `json:"ua"`
	Reqs      int     `json:"reqs"`
	RPS       float64 `json:"rps"`
	UniqueIPs int     `json:"unique_ips"`
	Vhosts    int     `json:"vhosts"`
}

// UADetail is the drill-down view for a single normalized UA.
type UADetail struct {
	UA        string  `json:"ua"`
	WindowSec float64 `json:"window_sec"`
	Reqs      int     `json:"reqs"`
	RPS       float64 `json:"rps"`
	UniqueIPs int     `json:"unique_ips"`
	Vhosts    int     `json:"vhosts"`

	// Top breakdowns within the window.
	TopIPs    []TopKV `json:"top_ips"`
	TopHosts  []TopKV `json:"top_hosts"`
	TopRawUAs []TopKV `json:"top_raw_uas"` // raw UA variants that collapsed to this normalized key
}

// UATop returns the top normalized-UA rows within the short window, sorted
// by request count descending. The limit caps the number of returned rows.
func (e *Engine) UATop(limit int) []UATopRow {
	if limit <= 0 {
		limit = 20
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// Aggregate across all hosts and buckets.
	type agg struct {
		reqs   int
		ips    map[string]struct{}
		hosts  map[string]struct{}
		first  time.Time
		last   time.Time
		seen   bool
	}
	tally := make(map[string]*agg)

	for host, hs := range e.hosts {
		if hs == nil {
			continue
		}
		for i := range hs.buckets {
			b := &hs.buckets[i]
			if len(b.uasNormReqs) == 0 {
				continue
			}
			for ua, n := range b.uasNormReqs {
				a := tally[ua]
				if a == nil {
					a = &agg{
						ips:   make(map[string]struct{}),
						hosts: make(map[string]struct{}),
					}
					tally[ua] = a
				}
				a.reqs += n
				a.hosts[host] = struct{}{}
				if ipSet := b.uasNormIPs[ua]; ipSet != nil {
					for ip := range ipSet {
						a.ips[ip] = struct{}{}
					}
				}
				if !a.seen || b.from.Before(a.first) {
					a.first = b.from
				}
				if !a.seen || b.to.After(a.last) {
					a.last = b.to
				}
				a.seen = true
			}
		}
	}

	rows := make([]UATopRow, 0, len(tally))
	for ua, a := range tally {
		span := a.last.Sub(a.first).Seconds()
		if span <= 0 {
			span = e.cfg.Window.Seconds()
		}
		var rps float64
		if span > 0 {
			rps = float64(a.reqs) / span
		}
		rows = append(rows, UATopRow{
			UA:        ua,
			Reqs:      a.reqs,
			RPS:       rps,
			UniqueIPs: len(a.ips),
			Vhosts:    len(a.hosts),
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Reqs != rows[j].Reqs {
			return rows[i].Reqs > rows[j].Reqs
		}
		return rows[i].UA < rows[j].UA
	})

	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// UADrill returns a drill-down view for a single normalized UA. The input is
// normalized via NormalizeUA so callers can pass either the canonical form
// or a raw UA string.
func (e *Engine) UADrill(ua string) UADetail {
	norm := NormalizeUA(ua)
	d := UADetail{
		UA:        norm,
		WindowSec: e.cfg.Window.Seconds(),
	}
	if norm == "" || norm == "-" {
		return d
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	ipCounts := make(map[string]int)
	hostCounts := make(map[string]int)
	rawUACounts := make(map[string]int)
	var first, last time.Time
	var seen bool

	for host, hs := range e.hosts {
		if hs == nil {
			continue
		}
		for i := range hs.buckets {
			b := &hs.buckets[i]
			n, ok := b.uasNormReqs[norm]
			if !ok || n == 0 {
				continue
			}
			d.Reqs += n
			hostCounts[host] += n
			if !seen || b.from.Before(first) {
				first = b.from
			}
			if !seen || b.to.After(last) {
				last = b.to
			}
			seen = true

			if ipSet := b.uasNormIPs[norm]; ipSet != nil {
				for ip := range ipSet {
					// We only have set membership in the bucket, not counts.
					// Use 1 per (ip, bucket) appearance as the weight.
					ipCounts[ip]++
				}
			}

			// Collect raw UA variants that normalize to this key.
			for rawUA, c := range b.uas {
				if NormalizeUA(rawUA) == norm {
					rawUACounts[rawUA] += c
				}
			}
		}
	}

	d.UniqueIPs = len(ipCounts)
	d.Vhosts = len(hostCounts)

	if seen {
		span := last.Sub(first).Seconds()
		if span <= 0 {
			span = e.cfg.Window.Seconds()
		}
		if span > 0 {
			d.RPS = float64(d.Reqs) / span
		}
	}

	d.TopIPs = topNFromMap(ipCounts, 20)
	d.TopHosts = topNFromMap(hostCounts, 20)
	d.TopRawUAs = topNFromMap(rawUACounts, 10)
	return d
}

// topNFromMap returns the top-N entries from a string→int map, sorted by
// count descending then key ascending.
func topNFromMap(m map[string]int, n int) []TopKV {
	out := make([]TopKV, 0, len(m))
	for k, v := range m {
		out = append(out, TopKV{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// IsGoogleVerifiedBot returns true for the normalized-UA strings that the
// emergency control surface treats as "verified Google crawlers requiring
// confirmation". This is consulted by the POST handler before applying a
// throttle/block.
func IsGoogleVerifiedBot(ua string) bool {
	switch strings.ToLower(strings.TrimSpace(ua)) {
	case "googlebot",
		"googlebot-image",
		"googlebot-news",
		"googlebot-video",
		"adsbot-google",
		"adsbot-google-mobile",
		"mediapartners-google",
		"storebot-google",
		"feedfetcher-google",
		"googleother":
		return true
	}
	return false
}
