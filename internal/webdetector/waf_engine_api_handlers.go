package webdetector

import (
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type wafEngineEvent struct {
	TsUnix      int64  `json:"ts_unix"`
	EventType   string `json:"event_type"`
	Host        string `json:"host"`
	IP          string `json:"ip"`
	URI         string `json:"uri"`
	Method      string `json:"method"`
	Status      int    `json:"status"`
	Reason      string `json:"reason"`
	Rule        string `json:"rule"`
	RuleBase    string `json:"rule_base"`
	WAFRuleID   int    `json:"waf_rule_id,omitempty"`
	Action      string `json:"action,omitempty"`
	Result      string `json:"result"`
	Country     string `json:"country,omitempty"`
	CountryISO  string `json:"country_iso,omitempty"`
	ASN         uint   `json:"asn,omitempty"`
	ASNName     string `json:"asn_name,omitempty"`
	UA          string `json:"ua,omitempty"`
	Referer     string `json:"referer,omitempty"`
	ContentType string `json:"content_type,omitempty"`
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

type wafHistBucket struct {
	TsUnix  int64 `json:"ts_unix"` // bucket start
	Count   int   `json:"count"`
	Blocked int   `json:"blocked"`
}

type wafEngineSummary struct {
	FromUnix      int64           `json:"from_unix"`
	ToUnix        int64           `json:"to_unix"`
	Hours         int             `json:"hours"`
	TotalEvents   int             `json:"total_events"`
	UniqueHosts   int             `json:"unique_hosts"`
	UniqueIPs     int             `json:"unique_ips"`
	BlockedEvents int             `json:"blocked_events"`
	TopRules      []wafTopValue   `json:"top_rules"`
	TopRuleBases  []wafTopValue   `json:"top_rule_bases"`
	TopHosts      []wafTopValue   `json:"top_hosts"`
	TopIPs        []wafTopIPValue `json:"top_ips"`
	TopCountries  []wafTopValue   `json:"top_countries,omitempty"`
	// Histogram buckets the (filtered) events per hour across the window,
	// oldest first — feeds the hits-over-time chart in the UI.
	Histogram []wafHistBucket  `json:"histogram,omitempty"`
	Rows      []wafEngineEvent `json:"rows"`
	// Echo of the applied filters so the UI can show what the numbers cover.
	CountryFilter []string `json:"country_filter,omitempty"`
	RuleFilter    string   `json:"rule_filter,omitempty"`
	IPFilter      string   `json:"ip_filter,omitempty"`
	HostFilter    string   `json:"host_filter,omitempty"`
	PathFilter    string   `json:"path_filter,omitempty"`
	UAFilter      string   `json:"ua_filter,omitempty"`
}

func (e *Engine) handleWAFEngineSummary(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
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

	// Optional filters, applied BEFORE aggregation so totals and every top-N
	// list reflect them — that's what makes them useful for false-positive
	// hunting ("show me everything rule X did to visitors from country Y").
	countryFilter := map[string]struct{}{}
	for _, c := range strings.Split(q.Get("country"), ",") {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c != "" {
			countryFilter[c] = struct{}{}
			res.CountryFilter = append(res.CountryFilter, c)
		}
	}
	ruleFilter := strings.ToLower(strings.TrimSpace(q.Get("rule")))
	res.RuleFilter = ruleFilter
	ruleIDFilter, numericRuleFilter := 0, false
	if ruleFilter != "" {
		if n, err := strconv.Atoi(ruleFilter); err == nil {
			if n <= 0 {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "numeric rule ID must be positive"})
				return
			}
			ruleIDFilter, numericRuleFilter = n, true
		}
	}
	ipFilter := strings.TrimSpace(q.Get("ip"))
	hostFilter := strings.ToLower(cleanHost(q.Get("host")))
	pathFilter := strings.ToLower(strings.TrimSpace(q.Get("path")))
	uaFilter := strings.ToLower(strings.TrimSpace(q.Get("ua")))
	res.IPFilter = ipFilter
	res.HostFilter = hostFilter
	res.PathFilter = pathFilter
	res.UAFilter = uaFilter
	// Country filtering needs the country even when the caller didn't ask
	// for enriched rows.
	needCountry := enrichEnabled || len(countryFilter) > 0

	to := time.Now()
	from := to.Add(-time.Duration(hours) * time.Hour)
	res.FromUnix = from.Unix()
	res.ToUnix = to.Unix()
	res.Hours = hours

	// Windowed + type-filtered in SQL (already ordered ts DESC) — see
	// readWAFEventsSinceLocked for why this must never become a full-table
	// read again.
	e.history.mu.Lock()
	all, err := e.history.readWAFEventsSinceLocked(res.FromUnix)
	e.history.mu.Unlock()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	scope := vhostScopeFromContext(r.Context())

	hosts := map[string]struct{}{}
	ips := map[string]struct{}{}
	ruleCount := map[string]int{}
	ruleBaseCount := map[string]int{}
	hostCount := map[string]int{}
	ipCount := map[string]int{}
	countryCount := map[string]int{}
	// One bucket per hour across the window (hours is clamped to <=720).
	hist := make([]wafHistBucket, hours)
	for i := range hist {
		hist[i].TsUnix = res.FromUnix + int64(i)*3600
	}
	rows := make([]wafEngineEvent, 0, limit) // limit is clamped to a maximum of 2000 above before this allocation.
	enrichCache := map[string]wafEngineEvent{}

	for _, ev := range all {
		if ev.TsUnix < res.FromUnix || ev.TsUnix > res.ToUnix {
			continue
		}
		if ev.Type != "waf_observe" && ev.Type != "waf_trigger" {
			continue
		}
		if !vhostAllowed(ev.Host, scope) {
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
		var method, uri, ua, referer, contentType, action string
		var wafRuleID int
		if ev.Payload != nil {
			method, _ = ev.Payload["method"].(string)
			uri, _ = ev.Payload["uri"].(string)
			ua, _ = ev.Payload["ua"].(string)
			referer, _ = ev.Payload["referer"].(string)
			contentType, _ = ev.Payload["ct"].(string)
			action, _ = ev.Payload["action"].(string)
			if id, ok := ev.Payload["waf_rule_id"]; ok {
				switch v := id.(type) {
				case float64:
					wafRuleID = int(v)
				case int:
					wafRuleID = v
				}
			}
		}
		if action = strings.TrimSpace(action); action == "" {
			action = strings.TrimSpace(ev.Mode)
		}
		if action == "" && ev.Type == "waf_observe" && ev.Status == http.StatusForbidden {
			action = "block"
		}
		row := wafEngineEvent{
			TsUnix:    ev.TsUnix,
			EventType: ev.Type,
			Host:      ev.Host,
			IP:        ev.IP,
			URI:       uri,
			Method:    method,
			Status:    ev.Status,
			Reason:    rule,
			Rule:      rule,
			RuleBase:  ruleBase,
			WAFRuleID: wafRuleID,
			Action:    action,
			Result:    "observed",
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
		if ev.Payload != nil {
			if c, ok := ev.Payload["country"].(string); ok && strings.TrimSpace(c) != "" {
				row.Country = c
			}
			if c, ok := ev.Payload["country_iso"].(string); ok && strings.TrimSpace(c) != "" {
				row.CountryISO = strings.ToUpper(strings.TrimSpace(c))
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
		if needCountry && (row.Country == "" || row.CountryISO == "" || row.ASN == 0 || row.ASNName == "") {
			if info, ok := enrichCache[row.IP]; ok {
				mergeWAFEnrichment(&row, info)
			} else if row.IP != "" && e.enr != nil {
				// LookupGeoFast, NOT Lookup: this per-row branch reads only
				// Country/ASN/ASNName (mmdb, microseconds) and discards PTR, but
				// Lookup() does a blocking reverse-DNS (up to dnsTimeout=1s) per
				// distinct IP. Over a busy window that is hundreds of 1s rDNS
				// calls — the reason /api/v1/waf/engine/summary?enrich=1 timed out
				// (>60s) while the PTR-free CLI overview returned in ~1.5s. The
				// country filter and enriched rows come purely from the mmdb, so
				// the fast path is behaviour-identical here. (top_ips still uses
				// Lookup in toSortedTopIPs, where PTR IS shown and is bounded to N.)
				r := e.enr.LookupGeoFast(row.IP)
				info := wafEngineEvent{Country: r.Country, CountryISO: r.CountryISO, ASN: r.ASN, ASNName: r.ASNName}
				enrichCache[row.IP] = info
				mergeWAFEnrichment(&row, info)
			}
		}
		if len(countryFilter) > 0 {
			_, nameMatch := countryFilter[strings.ToUpper(strings.TrimSpace(row.Country))]
			_, isoMatch := countryFilter[strings.ToUpper(strings.TrimSpace(row.CountryISO))]
			if !nameMatch && !isoMatch {
				continue
			}
		}
		if ruleFilter != "" {
			if numericRuleFilter && wafRuleID != ruleIDFilter {
				continue
			}
			if !numericRuleFilter &&
				!strings.Contains(strings.ToLower(rule), ruleFilter) &&
				!strings.Contains(strings.ToLower(ruleBase), ruleFilter) {
				continue
			}
		}
		if ipFilter != "" && !sameIP(row.IP, ipFilter) {
			continue
		}
		if hostFilter != "" && !strings.EqualFold(cleanHost(row.Host), hostFilter) {
			continue
		}
		if pathFilter != "" && !strings.Contains(strings.ToLower(row.URI), pathFilter) {
			continue
		}
		if uaFilter != "" {
			filterUA := ua
			if len(filterUA) > accessMaxUA {
				filterUA = filterUA[:accessMaxUA]
			}
			if !strings.Contains(strings.ToLower(filterUA), uaFilter) {
				continue
			}
		}

		res.TotalEvents++
		// Counted after the filters so a filtered summary's blocked count
		// matches the events it actually covers.
		blocked := ev.Status == http.StatusForbidden || strings.EqualFold(ev.Mode, "block")
		if blocked {
			res.BlockedEvents++
		}
		if bi := int((ev.TsUnix - res.FromUnix) / 3600); bi >= 0 && len(hist) > 0 {
			// An event at exactly ToUnix computes to index==len; it belongs
			// to the last bucket.
			if bi >= len(hist) {
				bi = len(hist) - 1
			}
			hist[bi].Count++
			if blocked {
				hist[bi].Blocked++
			}
		}
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
		if c := strings.TrimSpace(row.Country); c != "" {
			countryCount[c]++
		} else if c := strings.ToUpper(strings.TrimSpace(row.CountryISO)); c != "" {
			countryCount[c]++
		}

		if len(rows) < limit {
			row.UA = boundStr(ua, accessMaxUA)
			row.Referer = boundStr(redactForensicQuery(referer), accessMaxRef)
			row.ContentType = boundStr(contentType, accessMaxUA)
			rows = append(rows, row)
		}
	}

	res.UniqueHosts = len(hosts)
	res.UniqueIPs = len(ips)
	res.TopRules = toSortedTop(ruleCount, topN)
	res.TopRuleBases = toSortedTop(ruleBaseCount, topN)
	res.TopHosts = toSortedTop(hostCount, topN)
	res.TopIPs = toSortedTopIPs(ipCount, topN, enrichEnabled, e)
	res.TopCountries = toSortedTop(countryCount, topN)
	res.Histogram = hist
	res.Rows = rows

	writeJSON(w, http.StatusOK, res)
}

func sameIP(a, b string) bool {
	aIP, bIP := net.ParseIP(strings.TrimSpace(a)), net.ParseIP(strings.TrimSpace(b))
	if aIP != nil && bIP != nil {
		return aIP.Equal(bIP)
	}
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func mergeWAFEnrichment(row *wafEngineEvent, info wafEngineEvent) {
	if row.Country == "" {
		row.Country = info.Country
	}
	if row.CountryISO == "" {
		row.CountryISO = info.CountryISO
	}
	if row.ASN == 0 {
		row.ASN = info.ASN
	}
	if row.ASNName == "" {
		row.ASNName = info.ASNName
	}
}

// redactForensicQuery preserves the referer's case while hiding values whose
// parameter names look secret-bearing. Unlike the hot access-ingest helper,
// this runs only on bounded summary output, so it can favor robust mixed-case
// matching over an allocation-free fast path.
func redactForensicQuery(uri string) string {
	q := strings.IndexByte(uri, '?')
	if q < 0 || q == len(uri)-1 {
		return uri
	}
	parts := strings.Split(uri[q+1:], "&")
	for i, p := range parts {
		eq := strings.IndexByte(p, '=')
		if eq <= 0 {
			continue
		}
		key, err := url.QueryUnescape(p[:eq])
		if err != nil {
			key = p[:eq]
		}
		key = strings.ToLower(key)
		for _, hint := range secretParamHints {
			if strings.Contains(key, hint) {
				parts[i] = p[:eq+1] + "[redacted]"
				break
			}
		}
	}
	return uri[:q+1] + strings.Join(parts, "&")
}

func toSortedTopIPs(m map[string]int, n int, enrichEnabled bool, e *Engine) []wafTopIPValue {
	out := make([]wafTopIPValue, 0, len(m))
	for k, v := range m {
		ip := strings.TrimSpace(k)
		if ip == "" {
			continue
		}
		out = append(out, wafTopIPValue{Key: ip, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	// Enrich only the top-N survivors. PTR reverse-DNS is up to ~1s per IP, so
	// enriching before truncation paid that cost for every unique IP in the
	// window and then discarded most of the rows. top_ips genuinely displays the
	// PTR, so we keep the full Lookup here — but only for the handful we return.
	if enrichEnabled && e != nil && e.enr != nil {
		for i := range out {
			if net.ParseIP(out[i].Key) == nil {
				continue
			}
			geo := e.enr.Lookup(out[i].Key)
			if geo.PTR != "" {
				out[i].PTR = geo.PTR
			}
			if geo.Country != "" {
				out[i].Country = geo.Country
			}
			if geo.ASN != 0 {
				out[i].ASN = geo.ASN
			}
			if geo.ASNName != "" {
				out[i].ASNName = geo.ASNName
			}
		}
	}
	return out
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
