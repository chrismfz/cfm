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
	// cpanelEtc holds cPanel's mail config (valiases, userdomains). A var so
	// tests keep the host's files out.
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
	// smtpAbroad: the countries it SENT mail from (SMTP AUTH) other than its
	// home country — the country most of its sources are in. With no single
	// such country (a tie: three countries, one address each, is the common
	// shape), a country counts only for a source that sent without reading:
	// a spammer submits, the owner's mail app does both from one address.
	smtpAbroad []string
}

// hijackCandidates lists the mailboxes logged in from hijackMinCountries
// countries, or from hijackMinIPs sources of which hijackMinAbroad are
// outside its main country, within hijackWindow.
func (t *tracker) hijackCandidates(now time.Time) []hijackCand {
	cutoff := now.Add(-hijackWindow)
	var out []hijackCand
	for user, ips := range t.authIPs {
		countries, sources, vias := map[string]bool{}, map[string]string{}, map[string]bool{}
		smtpFrom := map[string]bool{} // country → some source there sent WITHOUT reading
		for ip, a := range ips {
			src, cc := authSource(ip)
			if src == "" {
				continue
			}
			sources[src] = cc
			w := a.within(cutoff)
			for _, v := range w {
				vias[v] = true
			}
			if cc != "" && len(w) > 0 && w[len(w)-1] == "smtp" { // authVias order: smtp is last
				smtpFrom[cc] = smtpFrom[cc] || len(w) == 1
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
		home := ""
		if top := topN(perCountry, 2); len(top) >= 1 && (len(top) == 1 || top[0].n > top[1].n) {
			home = top[0].k
		}
		h := hijackCand{user: user, sources: len(sources), countries: sortedKeys(countries), vias: sortedKeys(vias)}
		for cc, only := range smtpFrom {
			if cc != home && (home != "" || only) {
				h.smtpAbroad = append(h.smtpAbroad, cc)
			}
		}
		sort.Strings(h.smtpAbroad)
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].user < out[j].user })
	return out
}

// finding judges a candidate: critical when the mailbox is being used (mail
// sent from abroad, a spike or bounce finding of its own, new or still open,
// a forwarder or filter changed), else a warning. rules may be nil (no
// forwarder/filter check); it is only asked when nothing else confirmed it.
func (h hijackCand) finding(found, open map[string]bool, rules *rulesCheck, now time.Time) abuseFinding {
	var did []string
	if len(h.smtpAbroad) > 0 {
		did = append(did, "sent mail from "+strings.Join(h.smtpAbroad, ", "))
	}
	if k := "mail:out:" + h.user; found[k] || open[k] {
		did = append(did, "is sending far above its usual")
	}
	if k := "mail:bounce:auth:" + h.user; found[k] || open[k] {
		did = append(did, "its mail bounces in bulk")
	}
	if len(did) == 0 && rules != nil {
		if r := rules.changed(h.user, now); r != "" {
			did = append(did, r+" changed in the last 24 h")
		}
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
	for _, v := range h.vias {
		if v == "smtp" {
			what = "no mail sent from abroad"
		}
	}
	f.Severity = "warning"
	f.Message = clip(head + " · " + what + " — ask the owner (travel, a VPN?); if not them, a stolen password")
	return f
}

// rulesCheck answers whether a mailbox's forwarder or filter changed, for one check, reading cPanel's
// userdomains (thousands of lines on a big host) at most once.
type rulesCheck struct {
	owners map[string]string // domain → cPanel user; nil until read
}

// changed names what was changed on a mailbox within hijackRulesWindow: its
// forwarder (cPanel /etc/valiases/<domain> changed, and holds a line for the
// address) or its own mail filter (~/etc/<domain>/<local>/filter, what
// webmail's "Email Filters" writes). "" when nothing changed, or not cPanel.
// The forwarder file is the domain's: a change to ANY forwarder of the domain
// counts for an address that has one (the line's own history is not kept).
func (r *rulesCheck) changed(addr string, now time.Time) string {
	i := strings.LastIndex(addr, "@")
	if i <= 0 || i == len(addr)-1 || strings.ContainsAny(addr, "/\\\x00") || strings.Contains(addr, "..") {
		return ""
	}
	local, dom := addr[:i], strings.ToLower(addr[i+1:])
	var changed []string
	if p := filepath.Join(cpanelEtc, "valiases", dom); recentlyChanged(p, now) && hasLinePrefix(p, addr+":") {
		changed = append(changed, "its forwarder")
	}
	if r.owners == nil {
		r.owners = map[string]string{}
		scanLines(filepath.Join(cpanelEtc, "userdomains"), func(l string) bool {
			if k, v, ok := strings.Cut(l, ":"); ok {
				r.owners[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
			}
			return true
		})
	}
	if owner := r.owners[dom]; owner != "" {
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
