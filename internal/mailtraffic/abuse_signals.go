package mailtraffic

// abuse_signals.go — the mail-abuse findings that are not a sender's volume
// (abuse.go): bounces per sender, one sender holding the queue, and the node's
// IPs on DNS blocklists (docs/mail-abuse.md).

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/firewall/selfip"
	"cfm/internal/logging"
	"cfm/internal/mailmeter"
	"cfm/internal/mailqueue"
)

const (
	// a sender's mail bounces in bulk: at least bounceMinCount bounces in the
	// recent window and at least bounceMinShare of its remote outcomes;
	// critical from bounceCritCount and bounceCritShare. It stays open while
	// above half of each (a fading wave does not reopen and close on every check).
	bounceMinCount  = 20
	bounceMinShare  = 0.25
	bounceCritCount = 100
	bounceCritShare = 0.5
	maxOwners       = 100000 // message ids remembered (a flood must not grow memory)
	maxOutcomes     = 2000   // per sender

	// one sender holds the queue: a queue of at least queueHogMin messages of
	// which one sender holds queueHogShare and at least queueHogMin, with at
	// least queueHogStuck of them frozen or stuck over an hour (a campaign
	// going out fine is not a clogged queue); critical from queueHogCrit.
	// Stays open above queueHogKeepShare / queueHogKeepMin.
	queueHogMin       = 100
	queueHogStuck     = 50
	queueHogShare     = 0.5
	queueHogCrit      = 1000
	queueHogKeepMin   = 50
	queueHogKeepShare = 0.3
	queueStale        = 10 * time.Minute

	rblEvery   = 30 * time.Minute
	rblTimeout = 20 * time.Second
	rblMaxIPs  = 32
)

// ---- bounces per sender ----

type owner struct {
	key string
	at  time.Time
}

type outcome struct {
	at      time.Time
	bounced bool
	reason  string
}

// addOwner remembers which sender submitted a message, to attribute its
// delivery outcomes (an exim `**` line does not name the sender).
func (t *tracker) addOwner(id, key string, at time.Time) {
	if _, ok := t.owners[id]; !ok && len(t.owners) >= maxOwners {
		return
	}
	t.owners[id] = owner{key: key, at: at}
}

func (t *tracker) addOutcome(id string, d mailmeter.Delivery, at time.Time) {
	o, ok := t.owners[id]
	if !ok || (d.Outcome != mailmeter.Delivered && d.Outcome != mailmeter.Bounced) {
		return // not ours, or a deferral (retried; the final bounce is what counts)
	}
	if _, ok := t.outcomes[o.key]; !ok && len(t.outcomes) >= maxTrackedUsers {
		return
	}
	os := append(t.outcomes[o.key], outcome{at: at, bounced: d.Outcome == mailmeter.Bounced, reason: d.Reason})
	if len(os) > maxOutcomes {
		os = os[len(os)-maxOutcomes:]
	}
	t.outcomes[o.key] = os
}

func (t *tracker) pruneOutcomes(now time.Time) {
	for id, o := range t.owners {
		if now.Sub(o.at) > contextWindow {
			delete(t.owners, id)
		}
	}
	for k, os := range t.outcomes {
		i := 0
		for i < len(os) && now.Sub(os[i].at) > contextWindow {
			i++
		}
		if i == len(os) {
			delete(t.outcomes, k)
		} else {
			t.outcomes[k] = os[i:]
		}
	}
}

func (t *tracker) bounceFindings(now time.Time, open map[string]bool) []AbuseView {
	var out []AbuseView
	for key, os := range t.outcomes {
		bounced, reasons := 0, map[string]int{}
		for _, o := range os {
			if o.bounced {
				bounced++
				if o.reason != "" {
					reasons[o.reason]++
				}
			}
		}
		share := float64(bounced) / float64(len(os))
		user := key[strings.IndexByte(key, ':')+1:]
		if systemLocalUsers[user] {
			continue
		}
		fkey := "mail:bounce:" + user
		minN, minShare := bounceMinCount, bounceMinShare
		if open[fkey] {
			minN, minShare = bounceMinCount/2, bounceMinShare/2
		}
		if bounced < minN || share < minShare {
			continue
		}
		sev := "warning"
		if bounced >= bounceCritCount && share >= bounceCritShare {
			sev = "critical"
		}
		self := ""
		if strings.HasPrefix(key, "auth:") {
			self = user
		}
		c := t.context(key, self)
		head := fmt.Sprintf("%s: %d of %d messages bounced in %dh (%.0f%%)", user, bounced, len(os), anomalyRecentHours, share*100)
		if r := topKey(reasons); r != "" {
			head += " · mostly " + r
		}
		msg := clip(c.describe(head))
		out = append(out, AbuseView{Type: TypeBounceSpike, Severity: sev, Key: fkey, Message: msg, Subject: user, Recent: int64(bounced), Context: &c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// ---- one sender holding the queue ----

// queueReport is the latest queue snapshot the exim / postfix queue detector
// published (a var so tests stub it).
var queueReport = mailqueue.Latest

func queueFindings(now time.Time, open, held map[string]bool) []AbuseView {
	rep, ok := queueReport()
	if !ok || now.Sub(rep.MeasuredAt) > queueStale {
		// no fresh reading (the queue detector is off or failing): an open
		// finding can be neither confirmed nor resolved
		for k := range open {
			if strings.HasPrefix(k, "mail:queue:") {
				held[k] = true
			}
		}
		return nil
	}
	parsed := rep.Parsed
	if parsed == 0 {
		return nil
	}
	var out []AbuseView
	for _, s := range rep.TopSenders {
		share := float64(s.Total) / float64(parsed)
		key := "mail:queue:" + s.Sender
		if open[key] {
			if s.Total < queueHogKeepMin || share < queueHogKeepShare {
				continue
			}
		} else if rep.Total < queueHogMin || s.Total < queueHogMin || share < queueHogShare || s.Frozen+s.Deferred < queueHogStuck {
			continue
		}
		sev := "warning"
		if s.Total >= queueHogCrit {
			sev = "critical"
		}
		who := s.Sender
		if who == "<>" || who == "" {
			who = "bounce messages (null sender <>)"
		}
		msg := fmt.Sprintf("%s: %d of %d queued messages (%.0f%%)", who, s.Total, rep.Total, share*100)
		if s.Frozen > 0 {
			msg += fmt.Sprintf(", %d frozen", s.Frozen)
		}
		if s.Deferred > 0 {
			msg += fmt.Sprintf(", %d stuck over 1h", s.Deferred)
		}
		out = append(out, AbuseView{Type: TypeQueueHog, Severity: sev, Key: key, Message: clip(msg), Subject: s.Sender, Recent: int64(s.Total)})
	}
	return out
}

// ---- the node's IPs on DNS blocklists ----

// rblList is one DNS blocklist and how to read its answers.
type rblList struct {
	zone string
	// label names a listing from its 127.0.0.x answer ("" = not a listing:
	// the list refuses this resolver, e.g. Spamhaus behind a public resolver).
	label func(last byte) string
	// severe listings make the finding critical (the big receivers use them).
	severe func(last byte) bool
}

func plainLabel(last byte) string {
	if last >= 2 && last < 255 {
		return "listed"
	}
	return ""
}

var rblLists = []rblList{
	{zone: "zen.spamhaus.org", label: func(b byte) string {
		switch {
		case b == 2 || b == 3 || b == 9:
			return "SBL"
		case b >= 4 && b <= 7:
			return "XBL"
		case b == 10 || b == 11:
			return "PBL"
		}
		return ""
	}, severe: func(b byte) bool { return b >= 2 && b <= 9 }},
	{zone: "bl.spamcop.net", label: plainLabel},
	{zone: "b.barracudacentral.org", label: plainLabel},
	{zone: "psbl.surriel.com", label: plainLabel},
}

type rblResult struct {
	listed []string // "zen.spamhaus.org (SBL)"
	severe bool
	failed bool // a list did not answer cleanly: the IP is not judged
}

// rblChecker looks the node's public IPv4 addresses up on the blocklists every
// rblEvery, off the collector's poll (DNS can be slow).
type rblChecker struct {
	running atomic.Bool
	mu      sync.Mutex
	last    time.Time
	results map[string]rblResult
}

var (
	// rblIPs lists the node's public IPv4 addresses; rblLookup resolves a
	// DNSBL query name. Vars so tests stub them.
	rblIPs    = defaultRBLIPs
	rblLookup = func(ctx context.Context, name string) ([]string, error) {
		return net.DefaultResolver.LookupHost(ctx, name)
	}
	rblSelf     *selfip.Resolver
	rblSelfOnce sync.Once
)

func defaultRBLIPs() []string {
	rblSelfOnce.Do(func() { rblSelf = selfip.New() })
	rblSelf.Refresh()
	var out []string
	for _, s := range rblSelf.LocalIPs() {
		ip := net.ParseIP(s).To4()
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || (ip[0] == 100 && ip[1]&0xc0 == 64) {
			continue // IPv6 (few lists), private, CGNAT
		}
		out = append(out, ip.String())
	}
	sort.Strings(out)
	if len(out) > rblMaxIPs {
		out = out[:rblMaxIPs]
	}
	return out
}

// maybeRun starts a check in the background when one is due.
func (r *rblChecker) maybeRun(now time.Time) {
	r.mu.Lock()
	due := now.Sub(r.last) >= rblEvery
	r.mu.Unlock()
	if !due || !r.running.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer r.running.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), rblTimeout)
		defer cancel()
		r.check(ctx, now)
	}()
}

func (r *rblChecker) check(ctx context.Context, now time.Time) {
	ips := rblIPs()
	if len(ips) == 0 {
		return // nothing to check (or the addresses could not be read): judge nothing
	}
	res := make(map[string]rblResult, len(ips))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, ip := range ips {
		rev := reverseIPv4(ip)
		if rev == "" {
			continue
		}
		for _, l := range rblLists {
			wg.Add(1)
			go func(ip, rev string, l rblList) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				label, severe, failed := queryRBL(ctx, rev, l)
				mu.Lock()
				defer mu.Unlock()
				cur := res[ip]
				if failed {
					cur.failed = true
				}
				if label != "" {
					name := l.zone
					if label != "listed" {
						name += " (" + label + ")"
					}
					cur.listed = append(cur.listed, name)
					cur.severe = cur.severe || severe
				}
				res[ip] = cur
			}(ip, rev, l)
		}
	}
	wg.Wait()
	for ip, v := range res {
		sort.Strings(v.listed)
		res[ip] = v
	}
	r.mu.Lock()
	r.results, r.last = res, now
	r.mu.Unlock()
}

// queryRBL asks one list about one address. NXDOMAIN is a clean "not listed";
// any other error, or an answer that is not a listing (the list refusing this
// resolver), is a failure that leaves the address unjudged.
func queryRBL(ctx context.Context, rev string, l rblList) (label string, severe, failed bool) {
	addrs, err := rblLookup(ctx, rev+"."+l.zone)
	if err != nil {
		if de, ok := err.(*net.DNSError); ok && de.IsNotFound {
			return "", false, false
		}
		return "", false, true
	}
	for _, a := range addrs {
		ip := net.ParseIP(a).To4()
		if ip == nil || ip[0] != 127 {
			continue
		}
		if ip[1] != 0 || ip[2] != 0 {
			// 127.255.255.x: Spamhaus (and others) refusing an open / public
			// resolver — the answer says nothing about the address
			logRBLRefusal(l.zone, a)
			return "", false, true
		}
		if lb := l.label(ip[3]); lb != "" {
			return lb, l.severe != nil && l.severe(ip[3]), false
		}
	}
	return "", false, len(addrs) > 0
}

var rblRefusalLogged sync.Map

func logRBLRefusal(zone, answer string) {
	if _, dup := rblRefusalLogged.LoadOrStore(zone, true); !dup {
		logging.Logf("[mailtraffic] %s answered %s: it refuses this node's DNS resolver, so its listings cannot be checked", zone, answer)
	}
}

func reverseIPv4(s string) string {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0])
}

func rblFindings(r *rblChecker, open, held map[string]bool) []AbuseView {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.results == nil { // no check has finished yet
		for k := range open {
			if strings.HasPrefix(k, "mail:rbl:") {
				held[k] = true
			}
		}
		return nil
	}
	var out []AbuseView
	for ip, v := range r.results {
		key := "mail:rbl:" + ip
		if len(v.listed) == 0 {
			if v.failed && open[key] {
				held[key] = true
			}
			continue
		}
		sev := "warning"
		if v.severe || len(v.listed) >= 2 {
			sev = "critical"
		}
		msg := clip(fmt.Sprintf("%s is on %s — mail sent from it is rejected or junked", ip, strings.Join(v.listed, ", ")))
		out = append(out, AbuseView{Type: TypeRBLListed, Severity: sev, Key: key, Message: msg, Subject: ip})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
