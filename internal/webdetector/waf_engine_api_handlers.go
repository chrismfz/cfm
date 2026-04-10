package webdetector

import (
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type wafEngineEvent struct {
	TsUnix   int64  `json:"ts_unix"`
	Host     string `json:"host"`
	IP       string `json:"ip"`
	URI      string `json:"uri"`
	Method   string `json:"method"`
	Status   int    `json:"status"`
	Reason   string `json:"reason"`
	Rule     string `json:"rule"`
	RuleBase string `json:"rule_base"`
	Result   string `json:"result"`
	Country  string `json:"country,omitempty"`
	ASN      uint   `json:"asn,omitempty"`
	ASNName  string `json:"asn_name,omitempty"`
}

type wafTopValue struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type wafTopIPValue struct {
	Key     string `json:"key"`
	Count   int    `json:"count"`
	PTR     string `json:"ptr,omitempty"`
	Country string `json:"country,omitempty"`
	ASN     uint   `json:"asn,omitempty"`
	ASNName string `json:"asn_name,omitempty"`
}

type wafEngineSummary struct {
	FromUnix      int64            `json:"from_unix"`
	ToUnix        int64            `json:"to_unix"`
	Hours         int              `json:"hours"`
	TotalEvents   int              `json:"total_events"`
	UniqueHosts   int              `json:"unique_hosts"`
	UniqueIPs     int              `json:"unique_ips"`
	BlockedEvents int              `json:"blocked_events"`
	TopRules      []wafTopValue    `json:"top_rules"`
	TopRuleBases  []wafTopValue    `json:"top_rule_bases"`
	TopHosts      []wafTopValue    `json:"top_hosts"`
	TopIPs        []wafTopIPValue  `json:"top_ips"`
	Rows          []wafEngineEvent `json:"rows"`
}

func (e *Engine) handleWAFEngineSummary(w http.ResponseWriter, r *http.Request) {
	if !IsAdminRequest(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin access required"})
		return
	}
	res := wafEngineSummary{}
	if e == nil || e.history == nil {
		writeJSON(w, http.StatusOK, res)
		return
	}

	q := r.URL.Query()
	hours, _ := strconv.Atoi(q.Get("hours"))
	if hours <= 0 {
		hours = 24
	}
	if hours > 24*30 {
		hours = 24 * 30
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}
	topN, _ := strconv.Atoi(q.Get("top"))
	if topN <= 0 {
		topN = 10
	}
	if topN > 100 {
		topN = 100
	}
	enrichEnabled := strings.EqualFold(strings.TrimSpace(q.Get("enrich")), "1") || strings.EqualFold(strings.TrimSpace(q.Get("enrich")), "true")

	to := time.Now()
	from := to.Add(-time.Duration(hours) * time.Hour)
	res.FromUnix = from.Unix()
	res.ToUnix = to.Unix()
	res.Hours = hours

	e.history.mu.Lock()
	all, err := e.history.readAllLocked()
	e.history.mu.Unlock()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	sort.Slice(all, func(i, j int) bool { return all[i].TsUnix > all[j].TsUnix })

	hosts := map[string]struct{}{}
	ips := map[string]struct{}{}
	ruleCount := map[string]int{}
	ruleBaseCount := map[string]int{}
	hostCount := map[string]int{}
	ipCount := map[string]int{}
	rows := make([]wafEngineEvent, 0, limit)
	enrichCache := map[string]wafEngineEvent{}

	for _, ev := range all {
		if ev.TsUnix < res.FromUnix || ev.TsUnix > res.ToUnix {
			continue
		}
		if ev.Type != "waf_observe" && ev.Type != "waf_trigger" {
			continue
		}
		rule := strings.TrimSpace(ev.Reason)
		ruleBase := rule
		if i := strings.IndexByte(ruleBase, ':'); i >= 0 {
			ruleBase = ruleBase[:i]
		}
		if rule == "" {
			rule = "WAF_UNKNOWN"
			ruleBase = "WAF_UNKNOWN"
		}
		var method, uri string
		if ev.Payload != nil {
			method, _ = ev.Payload["method"].(string)
			uri, _ = ev.Payload["uri"].(string)
		}
		row := wafEngineEvent{
			TsUnix:   ev.TsUnix,
			Host:     ev.Host,
			IP:       ev.IP,
			URI:      uri,
			Method:   method,
			Status:   ev.Status,
			Reason:   rule,
			Rule:     rule,
			RuleBase: ruleBase,
			Result:   "observed",
		}
		if ev.Type == "waf_trigger" {
			if mode := strings.TrimSpace(ev.Mode); mode != "" {
				row.Result = mode + "_triggered"
			} else {
				row.Result = "triggered"
			}
		} else if ev.Status == http.StatusForbidden {
			row.Result = "blocked"
		}
		if ev.Status == http.StatusForbidden || strings.EqualFold(ev.Mode, "block") {
			res.BlockedEvents++
		}
		if ev.Payload != nil {
			if c, ok := ev.Payload["country"].(string); ok && strings.TrimSpace(c) != "" {
				row.Country = c
			}
			if n, ok := ev.Payload["asn_name"].(string); ok && strings.TrimSpace(n) != "" {
				row.ASNName = n
			}
			if av, ok := ev.Payload["asn"]; ok {
				switch v := av.(type) {
				case float64:
					row.ASN = uint(v)
				case int:
					row.ASN = uint(v)
				case uint:
					row.ASN = v
				}
			}
		}
		if enrichEnabled && (row.Country == "" || row.ASN == 0 || row.ASNName == "") {
			if info, ok := enrichCache[row.IP]; ok {
				row.Country = info.Country
				row.ASN = info.ASN
				row.ASNName = info.ASNName
			} else if row.IP != "" && e.enr != nil {
				r := e.enr.Lookup(row.IP)
				row.Country = r.Country
				row.ASN = r.ASN
				row.ASNName = r.ASNName
				enrichCache[row.IP] = wafEngineEvent{Country: row.Country, ASN: row.ASN, ASNName: row.ASNName}
			}
		}

		res.TotalEvents++
		if h := cleanHost(row.Host); h != "" {
			hosts[h] = struct{}{}
			hostCount[h]++
		}
		if ip := strings.TrimSpace(row.IP); ip != "" {
			ips[ip] = struct{}{}
			ipCount[ip]++
		}
		ruleCount[rule]++
		ruleBaseCount[ruleBase]++

		if len(rows) < limit {
			rows = append(rows, row)
		}
	}

	res.UniqueHosts = len(hosts)
	res.UniqueIPs = len(ips)
	res.TopRules = toSortedTop(ruleCount, topN)
	res.TopRuleBases = toSortedTop(ruleBaseCount, topN)
	res.TopHosts = toSortedTop(hostCount, topN)
	res.TopIPs = toSortedTopIPs(ipCount, topN, enrichEnabled, e)
	res.Rows = rows

	writeJSON(w, http.StatusOK, res)
}

func toSortedTopIPs(m map[string]int, n int, enrichEnabled bool, e *Engine) []wafTopIPValue {
	out := make([]wafTopIPValue, 0, len(m))
	for k, v := range m {
		ip := strings.TrimSpace(k)
		if ip == "" {
			continue
		}
		row := wafTopIPValue{Key: ip, Count: v}
		if enrichEnabled && e != nil && e.enr != nil && net.ParseIP(ip) != nil {
			geo := e.enr.Lookup(ip)
			if geo.PTR != "" {
				row.PTR = geo.PTR
			}
			if geo.Country != "" {
				row.Country = geo.Country
			}
			if geo.ASN != 0 {
				row.ASN = geo.ASN
			}
			if geo.ASNName != "" {
				row.ASNName = geo.ASNName
			}
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	if n <= 0 || len(out) <= n {
		return out
	}
	return out[:n]
}

func toSortedTop(m map[string]int, n int) []wafTopValue {
	out := make([]wafTopValue, 0, len(m))
	for k, v := range m {
		if strings.TrimSpace(k) == "" {
			continue
		}
		out = append(out, wafTopValue{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	if n <= 0 || len(out) <= n {
		return out
	}
	return out[:n]
}
