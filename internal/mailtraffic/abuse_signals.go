package mailtraffic

// abuse_signals.go — the mail-abuse findings that are not a sender's volume
// (abuse.go): bounces per sender, one sender holding the queue, and the node's
// IPs on DNS blocklists (docs/mail-abuse.md).

import (
	"context"
	"fmt"
	"net"
	"regexp"
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
	queueHoldMax      = time.Hour // a reading this old (detector off) no longer holds anything

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

func (t *tracker) bounceFindings(now time.Time, open, held map[string]bool) []AbuseView {
	if now.Sub(t.started) < contextWindow {
		// after a restart the window is still filling (outcomes live in memory):
		// an open finding can be neither confirmed nor resolved yet
		for k := range open {
			if strings.HasPrefix(k, "mail:bounce:") {
				held[k] = true
			}
		}
	}
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
		fkey := "mail:bounce:" + key // mail:bounce:local:<user> / mail:bounce:auth:<mailbox> — a cPanel user can be both
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
		head := fmt.Sprintf("%s: %d of %d deliveries bounced in %dh (%.0f%%)", user, bounced, len(os), anomalyRecentHours, share*100)
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
	hold := func() {
		for k := range open {
			if strings.HasPrefix(k, "mail:queue:") {
				held[k] = true
			}
		}
	}
	if !ok || now.Sub(rep.MeasuredAt) > queueStale {
		// no fresh reading (the queue detector failing): an open finding can be
		// neither confirmed nor resolved — for a while; a detector switched off
		// for good must not hold it forever
		if ok && now.Sub(rep.MeasuredAt) <= queueHoldMax {
			hold()
		}
		return nil
	}
	parsed := rep.Parsed
	if parsed == 0 {
		if rep.Total > 0 {
			hold() // the count worked but the listing did not (a big queue is slow to list)
		}
		return nil
	}
	var out []AbuseView
	for _, s := range rep.TopSenders {
		if s.Sender == "<>" || s.Sender == "" {
			// bounces (null sender): frozen undeliverable bounces piling up is
			// the normal state of a cPanel queue, not one sender's doing
			continue
		}
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
		msg := fmt.Sprintf("%s: %d of %d queued messages (%.0f%%)", s.Sender, s.Total, parsed, share*100)
		if parsed < rep.Total {
			msg += fmt.Sprintf(" of the %d listed, %d in the queue", parsed, rep.Total)
		}
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
	zone string // the list's name in findings, logs and state (never the DQS key)
	// dqs: the list is reachable through Spamhaus DQS when a key is set
	dqs bool
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
	{zone: "zen.spamhaus.org", dqs: true, label: func(b byte) string {
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

// spamhausDQSKey is the Spamhaus DQS key (cfm.conf MAIL_RBL_SPAMHAUS_DQS_KEY);
// "" queries the public zone.
var spamhausDQSKey atomic.Value

var reDQSKey = regexp.MustCompile(`^[a-z0-9]{20,40}$`)

// SetSpamhausDQSKey sets the Spamhaus DQS key. A malformed one is ignored
// (and said so, without echoing it).
func SetSpamhausDQSKey(key string) {
	key = strings.ToLower(strings.TrimSpace(key))
	if key != "" && !reDQSKey.MatchString(key) {
		logging.Logf("[mailtraffic] MAIL_RBL_SPAMHAUS_DQS_KEY is not a DQS key (expected 20-40 letters/digits): ignored")
		key = ""
	}
	if old, _ := spamhausDQSKey.Swap(key).(string); old != key {
		// a new key (or none) deserves its own "refused" line if it is refused
		for _, l := range rblLists {
			if l.dqs {
				rblRefusalLogged.Delete(l.zone)
			}
		}
	}
}

// queryZone is the zone actually asked: through DQS for Spamhaus when a key
// is set. Everything else (findings, logs, state) names the list by zone.
func (l rblList) queryZone() string {
	if l.dqs {
		if k, _ := spamhausDQSKey.Load().(string); k != "" {
			return k + ".zen.dq.spamhaus.net"
		}
	}
	return l.zone
}

// rblListing is one list's listing of an address.
type rblListing struct {
	label  string // "SBL", "listed"
	severe bool
}

// rblStatus is what one list said about one address.
type rblStatus int

const (
	rblClean   rblStatus = iota // not listed (NXDOMAIN / NODATA)
	rblListed                   // a listing
	rblRefused                  // the list refuses this resolver (127.255.255.x): it says nothing
	rblFailed                   // no clean answer this time (timeout, SERVFAIL)
)

// rblChecker looks the node's public IPv4 addresses up on the blocklists every
// rblEvery, off the collector's poll (DNS can be slow).
type rblChecker struct {
	running atomic.Bool
	wg      sync.WaitGroup // the in-flight check, joined on Shutdown
	mu      sync.Mutex
	last    time.Time
	results map[string]map[string]rblListing // ip → zone → listing; nil before the first check
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

// selfResolver is the node's own addresses, shared by the RBL check and the
// hijack check (refreshed at most every selfRefresh: interfaces rarely change).
func selfResolver() *selfip.Resolver {
	rblSelfOnce.Do(func() { rblSelf = selfip.New() })
	if now := time.Now().Unix(); now-selfRefreshedAt.Load() >= int64(selfRefresh/time.Second) {
		selfRefreshedAt.Store(now)
		rblSelf.Refresh()
	}
	return rblSelf
}

const selfRefresh = 10 * time.Minute

var (
	selfRefreshedAt atomic.Int64
	// isSelfIP reports an address of this node (a var so tests stub it).
	isSelfIP = func(ip string) bool { return selfResolver().Contains(ip) }
)

func defaultRBLIPs() []string {
	var out []string
	for _, s := range selfResolver().LocalIPs() {
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

// maybeRun starts a check in the background when one is due; parent cancels it
// (the collector stopping).
func (r *rblChecker) maybeRun(parent context.Context, now time.Time) {
	r.mu.Lock()
	due := now.Sub(r.last) >= rblEvery
	r.mu.Unlock()
	if !due || !r.running.CompareAndSwap(false, true) {
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer r.running.Store(false)
		ctx, cancel := context.WithTimeout(parent, rblTimeout)
		defer cancel()
		r.check(ctx, now)
	}()
}

func (r *rblChecker) check(ctx context.Context, now time.Time) {
	ips := rblIPs()
	if len(ips) == 0 || ctx.Err() != nil {
		return // nothing to check (or the addresses could not be read): judge nothing
	}
	r.mu.Lock()
	prev := r.results
	r.mu.Unlock()
	res := make(map[string]map[string]rblListing, len(ips))
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
				st, listing := queryRBL(ctx, rev, l)
				mu.Lock()
				defer mu.Unlock()
				if res[ip] == nil {
					res[ip] = map[string]rblListing{}
				}
				switch st {
				case rblListed:
					res[ip][l.zone] = listing
				case rblFailed, rblRefused:
					// one list not answering must neither delist the address
					// nor hold its other lists' verdicts: keep this list's last word
					if old, ok := prev[ip][l.zone]; ok {
						res[ip][l.zone] = old
					}
				}
			}(ip, rev, l)
		}
	}
	wg.Wait()
	r.mu.Lock()
	r.results, r.last = res, now
	r.mu.Unlock()
}

// queryRBL asks one list about one address. NXDOMAIN / NODATA is a clean "not
// listed". 127.255.255.x is the list refusing this node's resolver (Spamhaus
// behind a public resolver, logged once). Neither a refusal nor a failure (any
// other error or unexpected answer) changes that list's previous verdict, and
// neither holds the other lists' verdicts.
func queryRBL(ctx context.Context, rev string, l rblList) (rblStatus, rblListing) {
	// the trailing dot keeps the resolver from also trying the search domains
	zone := l.queryZone() // once: the key can change while this lookup is in flight
	addrs, err := rblLookup(ctx, rev+"."+zone+".")
	if err != nil {
		if de, ok := err.(*net.DNSError); ok && de.IsNotFound {
			return rblClean, rblListing{}
		}
		return rblFailed, rblListing{}
	}
	for _, a := range addrs {
		ip := net.ParseIP(a).To4()
		if ip == nil || ip[0] != 127 {
			continue
		}
		if ip[1] != 0 || ip[2] != 0 {
			logRBLRefusal(l, zone, a)
			return rblRefused, rblListing{}
		}
		if lb := l.label(ip[3]); lb != "" {
			return rblListed, rblListing{label: lb, severe: l.severe != nil && l.severe(ip[3])}
		}
	}
	if len(addrs) == 0 {
		return rblClean, rblListing{}
	}
	return rblFailed, rblListing{}
}

var rblRefusalLogged sync.Map

func logRBLRefusal(l rblList, asked, answer string) {
	if l.queryZone() != asked {
		return // the key changed while this lookup was in flight: its answer says nothing about the new one
	}
	if _, dup := rblRefusalLogged.LoadOrStore(l.zone, true); dup {
		return
	}
	if asked != l.zone { // through DQS: the key, not the resolver (never log the key)
		logging.Logf("[mailtraffic] %s (DQS) answered %s: the MAIL_RBL_SPAMHAUS_DQS_KEY was refused (wrong, expired or over quota), so its listings cannot be checked", l.zone, answer)
		return
	}
	logging.Logf("[mailtraffic] %s answered %s: it refuses this node's DNS resolver, so its listings cannot be checked (set MAIL_RBL_SPAMHAUS_DQS_KEY)", l.zone, answer)
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
	for ip, zones := range r.results {
		if len(zones) == 0 {
			continue
		}
		key := "mail:rbl:" + ip
		var listed []string
		severe := false
		for zone, l := range zones {
			name := zone
			if l.label != "listed" {
				name += " (" + l.label + ")"
			}
			listed = append(listed, name)
			severe = severe || l.severe
		}
		sort.Strings(listed)
		sev := "warning"
		if severe || len(listed) >= 2 {
			sev = "critical"
		}
		msg := clip(fmt.Sprintf("%s is on %s — mail sent from it is rejected or junked", ip, strings.Join(listed, ", ")))
		out = append(out, AbuseView{Type: TypeRBLListed, Severity: sev, Key: key, Message: msg, Subject: ip})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
