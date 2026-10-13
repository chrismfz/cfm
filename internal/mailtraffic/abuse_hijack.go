package mailtraffic

// abuse_hijack.go — judging a mail_hijack (docs/mail-abuse.md "Hijack
// severity"). Logins from many countries are a CANDIDATE; what makes it a
// page is the mailbox doing something with the stolen password: sending mail
// from abroad, sending or bouncing in bulk, or a forwarder or filter set up on
// it. A mailbox only READ from three countries is usually its owner travelling
// or behind a VPN or a corporate proxy (Oct 2026: 33 critical hijacks in a
// week on 10 mailboxes, every one of them IMAP-only and none of them sending
// mail from abroad) — a warning, still shown, never a page.

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cfm/internal/panelmap"
)

const (
	// hijackRulesWindow: a forwarder or filter on the mailbox changed this
	// recently confirms a hijack (a thief keeps a copy of the mail coming).
	hijackRulesWindow = 24 * time.Hour
	// hijackQuiet: a resolved hijack seen again within this long, from no new
	// country and no more severe, is not published again (the owner on the
	// same trip, or behind the same VPN, every day).
	hijackQuiet = 7 * 24 * time.Hour
)

var (
	// cpanelEtc holds cPanel's forwarders (valiases). A var so tests keep the
	// host's files out (the domain owners come from panelmap).
	cpanelEtc = "/etc"
	// mailboxHome is a unix user's home directory ("" when unknown).
	mailboxHome = func(name string) string {
		u, err := user.Lookup(name)
		if err != nil {
			return ""
		}
		return u.HomeDir
	}
)

// hijackCand is a mailbox that logged in from many places within the window.
type hijackCand struct {
	user      string
	sources   int
	countries []string // sorted
	vias      []string // the protocols seen within the window, sorted
	// sentFrom: the countries it SENT mail from (SMTP AUTH) within the window;
	// sentUnread: those of them it was not READ from (IMAP/POP3) within it.
	// The owner's mail app sends from where it reads; a thief submitting spam
	// sends from where nobody reads. No "home country" is guessed: within an
	// hour the majority is whoever has more addresses, and a thief behind a
	// proxy pool has more than the owner.
	sentFrom, sentUnread []string
}

// hijackCandidates lists the mailboxes logged in from hijackMinCountries
// countries, or from hijackMinIPs sources of which hijackMinAbroad are
// outside its main country, within hijackWindow.
func (t *tracker) hijackCandidates(now time.Time) []hijackCand {
	cutoff := now.Add(-hijackWindow)
	var out []hijackCand
	for user, ips := range t.authIPs {
		countries, sources, vias := map[string]bool{}, map[string]string{}, map[string]bool{}
		sent, read := map[string]bool{}, map[string]bool{}
		for ip, a := range ips {
			src, cc := authSource(ip)
			if src == "" {
				continue
			}
			sources[src] = cc
			for _, v := range a.within(cutoff) {
				vias[v] = true
				if cc == "" {
					continue // a fetcher or a corporate gateway: no place to judge
				}
				if v == "smtp" {
					sent[cc] = true
				} else {
					read[cc] = true
				}
			}
			if cc != "" {
				countries[cc] = true
			}
		}
		perCountry := map[string]int{}
		for _, cc := range sources {
			if cc != "" {
				perCountry[cc]++
			}
		}
		abroad := 0
		if top := topN(perCountry, 1); len(top) == 1 {
			for _, cc := range sources {
				if cc != "" && cc != top[0].k {
					abroad++
				}
			}
		}
		if len(countries) < hijackMinCountries && (len(sources) < hijackMinIPs || abroad < hijackMinAbroad) {
			continue
		}
		h := hijackCand{user: user, sources: len(sources), countries: sortedKeys(countries), vias: sortedKeys(vias), sentFrom: sortedKeys(sent)}
		for _, cc := range h.sentFrom {
			if !read[cc] {
				h.sentUnread = append(h.sentUnread, cc)
			}
		}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].user < out[j].user })
	return out
}

// used lists what this check saw done with the mailbox's password: mail sent
// from a country it was not read from, or from two countries or more (owner
// and thief both sending), or a spike / bounce FINDING of its own this check
// (not one only held open on volume: that is no news about this hour).
func (h hijackCand) used(found map[string]bool) []string {
	var did []string
	switch {
	case len(h.sentUnread) > 0:
		did = append(did, "sent mail from "+strings.Join(h.sentUnread, ", "))
	case len(h.sentFrom) >= 2:
		did = append(did, "sent mail from "+strings.Join(h.sentFrom, ", "))
	}
	if found["mail:out:"+h.user] {
		did = append(did, "is sending far above its usual")
	}
	if found["mail:bounce:auth:"+h.user] {
		did = append(did, "its mail bounces in bulk")
	}
	return did
}

// finding judges a candidate: critical when the mailbox is being used (used,
// or a forwarder / filter changed: rules, from rulesChanged), else a warning.
func (h hijackCand) finding(found map[string]bool, rules map[string]string) abuseFinding {
	did := h.used(found)
	if r := rules[h.user]; len(did) == 0 && r != "" {
		did = append(did, r+" changed in the last 24 h")
	}
	head := fmt.Sprintf("%s: logged in (%s) from %d IPs in %d countries (%s) within an hour",
		h.user, strings.Join(h.vias, "/"), h.sources, len(h.countries), strings.Join(h.countries, ", "))
	f := abuseFinding{Type: TypeHijack, Key: "mail:hijack:" + h.user, Countries: h.countries}
	if len(did) > 0 {
		f.Severity = "critical"
		f.Message = clip(head + " and " + strings.Join(did, ", ") + " — likely a stolen password")
		return f
	}
	what := "reading only"
	if len(h.sentFrom) > 0 {
		what = "sent mail only from " + h.sentFrom[0] + ", where it is also read"
	}
	f.Severity = "warning"
	f.Message = clip(head + " · " + what + " — ask the owner (travel, a VPN?); if not them, a stolen password")
	return f
}

// rulesSeen is one mailbox's forwarder / filter answer, reused for
// hijackRulesRecheck: a candidate is judged every check (5 min), and the
// answer costs file reads under the tracker lock.
type rulesSeen struct {
	at   time.Time
	what string
}

const hijackRulesRecheck = 10 * time.Minute

// rulesChanged answers rulesFor for each address, from the cache when fresh;
// the owners of the domains still to look up are read once (panelmap).
func (t *tracker) rulesChanged(addrs []string, now time.Time) map[string]string {
	out := map[string]string{}
	if t.rules == nil {
		t.rules = map[string]rulesSeen{}
	}
	var ask, doms []string
	for _, a := range addrs {
		if r, ok := t.rules[a]; ok && now.Sub(r.at) >= 0 && now.Sub(r.at) < hijackRulesRecheck {
			out[a] = r.what
			continue
		}
		ask = append(ask, a)
		if i := strings.LastIndex(a, "@"); i > 0 {
			doms = append(doms, a[i+1:])
		}
	}
	if len(ask) == 0 {
		return out
	}
	owners := panelmap.HostOwners(doms)
	for _, a := range ask {
		w := rulesFor(a, owners, now)
		t.rules[a] = rulesSeen{at: now, what: w}
		out[a] = w
	}
	for a, r := range t.rules {
		if now.Sub(r.at) >= hijackRulesRecheck || now.Sub(r.at) < 0 {
			delete(t.rules, a)
		}
	}
	return out
}

// rulesFor names what was changed on a mailbox within hijackRulesWindow: its
// forwarder (cPanel /etc/valiases/<domain> changed, and holds a line for the
// address) or its own mail filter (~/etc/<domain>/<local>/filter, what
// webmail's "Email Filters" writes). "" when nothing changed, or not cPanel.
// The forwarder file is the domain's: a change to ANY forwarder of the domain
// counts for an address that has one (the line's own history is not kept).
// owners maps a domain to its cPanel account.
func rulesFor(addr string, owners map[string]string, now time.Time) string {
	i := strings.LastIndex(addr, "@")
	if i <= 0 || i == len(addr)-1 || strings.ContainsAny(addr, "/\\\x00") || strings.Contains(addr, "..") {
		return ""
	}
	local, dom := addr[:i], strings.ToLower(addr[i+1:])
	var changed []string
	if p := filepath.Join(cpanelEtc, "valiases", dom); recentlyChanged(p, now) && hasLinePrefix(p, addr+":") {
		changed = append(changed, "its forwarder")
	}
	if owner := owners[dom]; owner != "" {
		if home := mailboxHome(owner); home != "" && recentlyChanged(filepath.Join(home, "etc", dom, local, "filter"), now) {
			changed = append(changed, "its mail filter")
		}
	}
	return strings.Join(changed, " and ")
}

func recentlyChanged(path string, now time.Time) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && now.Sub(fi.ModTime()) < hijackRulesWindow
}

// hasLinePrefix reports a line starting with prefix (case-insensitive).
func hasLinePrefix(path, prefix string) bool {
	found := false
	scanLines(path, func(l string) bool {
		found = strings.HasPrefix(strings.ToLower(l), strings.ToLower(prefix))
		return !found
	})
	return found
}

// scanLines calls fn for each trimmed line until it returns false.
func scanLines(path string, fn func(string) bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20) // a forwarder to many recipients is one long line
	for sc.Scan() {
		if !fn(strings.TrimSpace(sc.Text())) {
			return
		}
	}
}
