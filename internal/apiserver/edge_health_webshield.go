package apiserver

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"cfm/internal/firewall/netfilterdiag"
	"cfm/internal/firewall/nft"
)

// Check H: does web traffic reach the CFM edge, or does another DNAT take it
// first? A connection is NAT'd once, by the first nat chain that rewrites it.
// Imunify360 DNATs its sets to WebShield at priority -100 (dstnat); CFM's web
// redirect defaults to -99 ("Imunify first"). On a cPanel node that sends every
// Cloudflare visitor to WebShield, because i360.ipv4.remote_proxy_static holds
// Cloudflare's ranges: earth (2026-11-17) sent ~29% of its web requests past
// the edge, its WAF, challenge and edge bans, with only 235 Cloudflare requests
// an hour left for the edge. The order alone is a documented choice, so the
// warning needs WebShield to be serving real traffic too: its access log,
// counted over a recent window (rule counters are cumulative and would keep
// warning after the fix).

var (
	edgeHealthNATReport = func(ctx context.Context) (netfilterdiag.Report, error) {
		return netfilterdiag.Collect(ctx, netfilterdiag.EffectiveExpected(0, 0, 0), nft.ListRulesetJSON)
	}
	edgeHealthWebShieldLog = "/var/log/imunify360-webshield/access.log"
)

const (
	// edgeHealthWebShieldWindow is how far back the WebShield log is counted.
	edgeHealthWebShieldWindow = 15 * 60
	// edgeHealthWebShieldWarnMin is the WebShield requests in that window that
	// make an Imunify-first order a warning. The CFM-first nodes log 2-10 (panel
	// ports, stragglers); earth logged ~7 500.
	edgeHealthWebShieldWarnMin = 100
	// edgeHealthWebShieldTailBytes bounds the read (earth: ~2.6 MB in 15 min).
	edgeHealthWebShieldTailBytes = 8 << 20
)

// webShieldCount is the WebShield access log over the window: requests, how
// many a proxy relayed (XFF set: Cloudflare and the like), and whether the
// read reached back past the window start (false: the count is a floor).
type webShieldCount struct {
	read, complete bool
	total, proxied int
}

func countWebShield(path string, now, window int64) webShieldCount {
	f, err := os.Open(path) // #nosec G304 -- fixed system log path
	if err != nil {
		return webShieldCount{}
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return webShieldCount{}
	}
	start := fi.Size() - edgeHealthWebShieldTailBytes
	c := webShieldCount{read: true, complete: start <= 0}
	if start > 0 {
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			return webShieldCount{}
		}
	}
	from := now - window
	// A line longer than the buffer (a scanner's huge URI) is still counted,
	// and never ends the count: bufio.Scanner stopped there, and the partial
	// count read as complete.
	rd := bufio.NewReaderSize(f, 64<<10)
	first := start > 0 // the first line after a seek is partial
	for {
		line, err := rd.ReadSlice('\n')
		long := false
		if err == bufio.ErrBufferFull {
			// Its timestamp is near the start: count it from the first chunk
			// (XFF, at the end, stays unread), and drop the rest of the line.
			// ReadSlice's buffer is reused, so copy what is kept.
			line, long = append([]byte(nil), line...), true
			for err == bufio.ErrBufferFull {
				_, err = rd.ReadSlice('\n')
			}
		}
		if err != nil && len(line) == 0 {
			break
		}
		if first {
			first = false
			continue
		}
		ts, ok := webShieldTime(line)
		if !ok {
			continue
		}
		if ts < from {
			c.complete = true
			continue
		}
		if ts > now+60 {
			continue
		}
		c.total++
		if long {
			continue
		}
		if i := bytes.Index(line, []byte(`XFF:"`)); i >= 0 && !bytes.HasPrefix(line[i+5:], []byte(`-"`)) {
			c.proxied++
		}
	}
	return c
}

// webShieldTime reads the [17/Nov/2026:10:11:24 +0200] stamp.
func webShieldTime(line []byte) (int64, bool) {
	i := bytes.IndexByte(line, '[')
	if i < 0 {
		return 0, false
	}
	j := bytes.IndexByte(line[i:], ']')
	if j < 0 {
		return 0, false
	}
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", string(line[i+1:i+j]))
	if err != nil {
		return 0, false
	}
	return t.Unix(), true
}

func webDNATOrderFinding(ctx context.Context, sev *severityTracker) map[string]any {
	const check = "web-dnat-order"
	report, err := edgeHealthNATReport(ctx)
	if err != nil {
		return sev.add(check, "unknown", "could not read the nft ruleset to see which NAT chain takes web traffic first: "+err.Error(), nil, "")
	}
	cfmPrio, found, ahead := netfilterdiag.WebDNATAhead(report)
	if !found {
		return sev.add(check, "ok", "web DNAT is off: no CFM web redirect to be preceded", map[string]any{"web_dnat": false}, "")
	}
	ws := countWebShield(edgeHealthWebShieldLog, edgeHealthNow(), edgeHealthWebShieldWindow)
	ev := map[string]any{"web_dnat": true, "cfm_priority": cfmPrio, "window_sec": edgeHealthWebShieldWindow}
	if ws.read {
		ev["webshield_requests"], ev["webshield_proxied"], ev["webshield_count_complete"] = ws.total, ws.proxied, ws.complete
	}
	if len(ahead) == 0 {
		return sev.add(check, "ok", "CFM's web redirect (priority "+itoa(cfmPrio)+") runs before every other DNAT of tcp/80 and tcp/443", ev, "")
	}
	owners, minPrio := map[string]bool{}, ahead[0].Priority
	var rules []string
	for _, n := range ahead {
		owners[n.Owner] = true
		if n.Priority < minPrio {
			minPrio = n.Priority
		}
		if len(rules) < 5 {
			rules = append(rules, n.Family+" "+n.Table+"/"+n.Chain+": "+n.Summary+" (priority "+itoa(n.Priority)+")")
		}
	}
	var who []string
	for o := range owners {
		who = append(who, o)
	}
	sort.Strings(who) // a stable summary: whats_wrong compares runs
	ev["ahead_rules"], ev["ahead_count"], ev["ahead_owners"] = rules, len(ahead), strings.Join(who, ",")
	order := strings.Join(who, "/") + " DNATs tcp/80 or tcp/443 at priority " + itoa(minPrio) +
		", before CFM's web redirect at " + itoa(cfmPrio) + ", so the connections it matches never reach the CFM edge (WAF, challenge, edge bans)"
	want := minPrio - 1
	// Imunify's filter accepts its graylist / captcha sets only on WebShield's
	// own ports and drops them on every other (9080/9043 included): with CFM
	// first, a graylisted direct visitor is dropped, not challenged
	// (docs/imunify-webshield-parity.md, P3).
	next := "set NFT_DNAT_PRIORITY = " + itoa(want) + " in /etc/cfm/cfm.conf and run `cfm dnat on --priority " + itoa(want) +
		"` (one transaction; the redirect never lapses). Clients on Imunify's graylist then get no WebShield captcha: " +
		"Imunify's own filter drops their new connections to the edge's ports"
	if want <= -200 {
		// nft refuses a nat chain at -200 or below (dnat.minNATChainPriority).
		next = "CFM's web redirect cannot run ahead of a nat chain at priority " + itoa(minPrio) +
			" (nft refuses a nat chain at -200 or below): that chain has to move later"
	}
	// WebShield's log measures Imunify's diversion only. Another tool's DNAT
	// ahead (Docker publishing :443, a hand rule) is a warning on the order
	// alone: nothing here can say how much it takes, and the edge is bypassed
	// for whatever it matches.
	if len(owners) > 1 || !owners["imunify"] {
		return sev.add(check, "warn", order+" (not Imunify360's WebShield: its log cannot measure this)", ev,
			"move that DNAT after CFM's web redirect, or set NFT_DNAT_PRIORITY below its priority")
	}
	switch {
	case !ws.read:
		return sev.add(check, "unknown", order+"; no WebShield access log to measure how much", ev, next)
	case ws.total >= edgeHealthWebShieldWarnMin:
		floor := ""
		if !ws.complete {
			floor = "at least "
		}
		return sev.add(check, "warn", order+": WebShield served "+floor+strconv.Itoa(ws.total)+" requests in the last "+
			itoa(edgeHealthWebShieldWindow/60)+" min, "+strconv.Itoa(ws.proxied)+" of them relayed by a proxy (Cloudflare)", ev, next)
	default:
		return sev.add(check, "ok", order+"; WebShield served only "+strconv.Itoa(ws.total)+" requests in the last "+
			itoa(edgeHealthWebShieldWindow/60)+" min", ev, "")
	}
}
