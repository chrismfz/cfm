// Package maildns is a read-only checker for the DNS records that decide mail
// authentication and deliverability: SPF, DMARC, DKIM, plus MX and the sending
// IP's reverse DNS (PTR / forward-confirmed rDNS). It answers "does this domain
// even have SPF/DMARC, what do they say, and does SPF list our sending IP?" —
// the DNS half of a deliverability diagnosis (the mail log's
// `421-4.7.27 SPF did not pass` is the authoritative runtime verdict; this
// explains why).
//
// It performs live DNS lookups on demand (no caching, no background work) and
// changes nothing. The resolver is an interface so the evaluation logic is
// unit-testable without touching the network.
package maildns

import (
	"context"
	"net"
	"strings"
)

// Resolver is the subset of *net.Resolver this package needs; net.DefaultResolver
// satisfies it, and tests inject a fake.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// SPF reports the domain's Sender Policy Framework record and a best-effort
// check of whether it authorizes the server's sending IP.
type SPF struct {
	Present      bool     `json:"present"`
	Records      []string `json:"records,omitempty"` // every v=spf1 TXT found (>1 is RFC-invalid)
	Record       string   `json:"record,omitempty"`  // the record, when exactly one
	Multiple     bool     `json:"multiple"`          // more than one v=spf1 record → invalid
	AllQualifier string   `json:"all_qualifier,omitempty"`
	// AuthorizesServerIP: "yes" (a direct ip4:/ip6: mechanism lists a server IP),
	// "no" (only direct mechanisms, none match), or "unknown" (the record relies
	// on include:/a/mx/redirect/exists/ptr, which this checker does not expand —
	// the mail log's SPF verdict is authoritative there).
	AuthorizesServerIP string `json:"authorizes_server_ip"`
	Note               string `json:"note,omitempty"`
}

// DMARC reports the domain's DMARC policy record.
type DMARC struct {
	Present bool   `json:"present"`
	Record  string `json:"record,omitempty"`
	Policy  string `json:"policy,omitempty"` // none | quarantine | reject
	Pct     string `json:"pct,omitempty"`
	Note    string `json:"note,omitempty"`
}

// DKIM reports whether a public key exists at one selector._domainkey.<domain>.
type DKIM struct {
	Selector string `json:"selector"`
	Present  bool   `json:"present"`
	Note     string `json:"note,omitempty"`
}

// PTR reports one sending IP's reverse DNS and whether it forward-confirms.
type PTR struct {
	IP     string `json:"ip"`
	Name   string `json:"name,omitempty"`
	FCrDNS bool   `json:"fcrdns"` // the PTR name resolves back to this IP
	Note   string `json:"note,omitempty"`
}

// Report is the full DNS mail-auth picture for one domain.
type Report struct {
	Domain    string   `json:"domain"`
	SPF       SPF      `json:"spf"`
	DMARC     DMARC    `json:"dmarc"`
	DKIM      []DKIM   `json:"dkim"`
	MX        []string `json:"mx,omitempty"`
	PTR       []PTR    `json:"ptr,omitempty"`
	ServerIPs []string `json:"server_ips,omitempty"`
	Findings  []string `json:"findings,omitempty"` // human-facing one-liners, worst first
}

// DefaultDKIMSelectors are the selectors probed when the caller names none.
// "default" is cPanel's; the others are common on the DA/Postfix hosts.
var DefaultDKIMSelectors = []string{"default"}

// Check resolves and evaluates the mail-auth records for domain. serverIPs are
// the host's public sending IPs (used for the SPF-authorization and PTR checks);
// selectors overrides the DKIM selectors probed. Every lookup is bounded by ctx.
func Check(ctx context.Context, r Resolver, domain string, serverIPs, selectors []string) Report {
	domain = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
	rep := Report{Domain: domain, ServerIPs: serverIPs}
	if domain == "" {
		rep.Findings = []string{"no domain given"}
		return rep
	}
	if len(selectors) == 0 {
		selectors = DefaultDKIMSelectors
	}

	rep.SPF = checkSPF(ctx, r, domain, serverIPs)
	rep.DMARC = checkDMARC(ctx, r, domain)
	for _, sel := range selectors {
		rep.DKIM = append(rep.DKIM, checkDKIM(ctx, r, domain, sel))
	}
	rep.MX = lookupMX(ctx, r, domain)
	rep.PTR = checkPTR(ctx, r, serverIPs)
	rep.Findings = findings(rep)
	return rep
}

func checkSPF(ctx context.Context, r Resolver, domain string, serverIPs []string) SPF {
	var out SPF
	txts, err := r.LookupTXT(ctx, domain)
	if err != nil {
		out.Note = "TXT lookup failed: " + err.Error()
		return out
	}
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			out.Records = append(out.Records, strings.TrimSpace(t))
		}
	}
	out.Present = len(out.Records) > 0
	out.Multiple = len(out.Records) > 1
	if !out.Present {
		out.AuthorizesServerIP = "unknown"
		out.Note = "no v=spf1 record"
		return out
	}
	// RFC 7208: more than one SPF record is a permerror; still report the first.
	out.Record = out.Records[0]
	out.AllQualifier = spfAllQualifier(out.Record)
	authorized, hadUneval := spfAuthorizesDirect(out.Record, serverIPs)
	switch {
	case authorized:
		out.AuthorizesServerIP = "yes"
	case hadUneval:
		out.AuthorizesServerIP = "unknown"
		out.Note = "relies on include:/a/mx/redirect — not expanded here; the mail log's SPF verdict is authoritative"
	default:
		out.AuthorizesServerIP = "no"
		out.Note = "no ip4:/ip6: mechanism lists a server IP"
	}
	return out
}

// spfAllQualifier returns the qualifier on the trailing "all" mechanism
// ("-all", "~all", "?all", "+all"), or "" when absent.
func spfAllQualifier(record string) string {
	for _, tok := range strings.Fields(record) {
		l := strings.ToLower(tok)
		switch l {
		case "-all", "~all", "?all", "+all":
			return l
		case "all":
			return "+all" // a bare "all" defaults to the "+" pass qualifier
		}
	}
	return ""
}

// spfAuthorizesDirect reports whether a direct ip4:/ip6: mechanism in record
// lists any server IP, and whether the record also carries mechanisms this
// checker does not expand (include/a/mx/redirect/exists/ptr).
func spfAuthorizesDirect(record string, serverIPs []string) (authorized, hadUnevaluated bool) {
	ips := make([]net.IP, 0, len(serverIPs))
	for _, s := range serverIPs {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	for _, tok := range strings.Fields(record) {
		mech := tok
		if n := len(mech); n > 0 && (mech[0] == '+' || mech[0] == '-' || mech[0] == '~' || mech[0] == '?') {
			mech = mech[1:]
		}
		l := strings.ToLower(mech)
		switch {
		case strings.HasPrefix(l, "ip4:") || strings.HasPrefix(l, "ip6:"):
			if ipMechMatches(mech[4:], ips) {
				return true, hadUnevaluated
			}
		case l == "a" || strings.HasPrefix(l, "a:") || strings.HasPrefix(l, "a/"),
			l == "mx" || strings.HasPrefix(l, "mx:") || strings.HasPrefix(l, "mx/"),
			strings.HasPrefix(l, "include:"), strings.HasPrefix(l, "redirect="),
			strings.HasPrefix(l, "exists:"), l == "ptr" || strings.HasPrefix(l, "ptr:"):
			hadUnevaluated = true
		}
	}
	return false, hadUnevaluated
}

// ipMechMatches reports whether spec (an SPF ip4:/ip6: value, a bare address or
// a CIDR) contains any of ips.
func ipMechMatches(spec string, ips []net.IP) bool {
	spec = strings.TrimSpace(spec)
	if !strings.Contains(spec, "/") {
		want := net.ParseIP(spec)
		if want == nil {
			return false
		}
		for _, ip := range ips {
			if ip.Equal(want) {
				return true
			}
		}
		return false
	}
	_, cidr, err := net.ParseCIDR(spec)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func checkDMARC(ctx context.Context, r Resolver, domain string) DMARC {
	var out DMARC
	txts, err := r.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		out.Note = "TXT lookup failed: " + err.Error()
		return out
	}
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
			out.Present = true
			out.Record = strings.TrimSpace(t)
			out.Policy = dmarcTag(out.Record, "p")
			out.Pct = dmarcTag(out.Record, "pct")
			return out
		}
	}
	out.Note = "no v=DMARC1 record at _dmarc." + domain
	return out
}

// dmarcTag extracts a "key=value" tag (semicolon-separated) from a DMARC record.
func dmarcTag(record, key string) string {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if eq := strings.IndexByte(part, '='); eq > 0 {
			if strings.EqualFold(strings.TrimSpace(part[:eq]), key) {
				return strings.ToLower(strings.TrimSpace(part[eq+1:]))
			}
		}
	}
	return ""
}

func checkDKIM(ctx context.Context, r Resolver, domain, selector string) DKIM {
	out := DKIM{Selector: selector}
	name := selector + "._domainkey." + domain
	txts, err := r.LookupTXT(ctx, name)
	if err != nil {
		out.Note = "not found at " + name
		return out
	}
	for _, t := range txts {
		l := strings.ToLower(strings.TrimSpace(t))
		if strings.HasPrefix(l, "v=dkim1") || strings.Contains(l, "p=") {
			out.Present = true
			return out
		}
	}
	out.Note = "no key at " + name
	return out
}

func lookupMX(ctx context.Context, r Resolver, domain string) []string {
	mxs, err := r.LookupMX(ctx, domain)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(mxs))
	for _, mx := range mxs {
		out = append(out, strings.TrimSuffix(mx.Host, "."))
	}
	return out
}

func checkPTR(ctx context.Context, r Resolver, serverIPs []string) []PTR {
	out := make([]PTR, 0, len(serverIPs))
	for _, ipStr := range serverIPs {
		p := PTR{IP: ipStr}
		names, err := r.LookupAddr(ctx, ipStr)
		if err != nil || len(names) == 0 {
			p.Note = "no PTR"
			out = append(out, p)
			continue
		}
		p.Name = strings.TrimSuffix(names[0], ".")
		// Forward-confirm: the PTR name must resolve back to this IP.
		if addrs, err := r.LookupIPAddr(ctx, p.Name); err == nil {
			want := net.ParseIP(ipStr)
			for _, a := range addrs {
				if a.IP.Equal(want) {
					p.FCrDNS = true
					break
				}
			}
		}
		if !p.FCrDNS {
			p.Note = "PTR does not forward-confirm to this IP"
		}
		out = append(out, p)
	}
	return out
}

// findings distils the report into human-facing one-liners, worst first, so an
// operator (or the MCP) sees the actionable problems without parsing the record.
func findings(rep Report) []string {
	var f []string
	switch {
	case !rep.SPF.Present:
		f = append(f, "SPF: MISSING — add a v=spf1 record that authorizes the sending IP")
	case rep.SPF.Multiple:
		f = append(f, "SPF: INVALID — more than one v=spf1 record (RFC permerror); keep exactly one")
	case rep.SPF.AuthorizesServerIP == "no":
		f = append(f, "SPF: does NOT list the server IP — mail from this host will fail SPF")
	case rep.SPF.AllQualifier == "+all":
		f = append(f, "SPF: uses +all (passes everything) — effectively no protection")
	}
	switch {
	case !rep.DMARC.Present:
		f = append(f, "DMARC: MISSING — add a _dmarc TXT (start with p=none to monitor)")
	case rep.DMARC.Policy == "none":
		f = append(f, "DMARC: policy p=none (monitor only, not enforced)")
	}
	dkimOK := false
	for _, d := range rep.DKIM {
		if d.Present {
			dkimOK = true
		}
	}
	if !dkimOK {
		f = append(f, "DKIM: no key found at the probed selector(s) — check the selector")
	}
	for _, p := range rep.PTR {
		if p.Name == "" {
			f = append(f, "PTR: "+p.IP+" has no reverse DNS")
		} else if !p.FCrDNS {
			f = append(f, "PTR: "+p.IP+" ("+p.Name+") does not forward-confirm")
		}
	}
	return f
}
