package maildns

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
)

type fakeResolver struct {
	txt    map[string][]string
	mx     map[string][]*net.MX
	ip     map[string][]net.IPAddr
	addr   map[string][]string
	txtErr map[string]error
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if e := f.txtErr[name]; e != nil {
		return nil, e
	}
	return f.txt[name], nil
}
func (f fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return f.mx[name], nil
}
func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	return f.ip[host], nil
}
func (f fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	return f.addr[addr], nil
}

func TestSPFAllQualifier(t *testing.T) {
	cases := map[string]string{
		"v=spf1 ip4:1.2.3.4 -all": "-all",
		"v=spf1 include:x ~all":   "~all",
		"v=spf1 ?all":             "?all",
		"v=spf1 +all":             "+all",
		"v=spf1 mx all":           "+all", // bare all == +all
		"v=spf1 a mx":             "",     // no all mechanism
	}
	for rec, want := range cases {
		if got := spfAllQualifier(rec); got != want {
			t.Errorf("spfAllQualifier(%q) = %q, want %q", rec, got, want)
		}
	}
}

func TestSPFDirectResult(t *testing.T) {
	srv := []string{"84.54.49.200", "2a01:dead::5"}
	cases := []struct {
		rec  string
		want string
	}{
		{"v=spf1 ip4:84.54.49.200 -all", "pass"},
		{"v=spf1 ip4:84.54.49.0/24 -all", "pass"},   // CIDR contains the IP
		{"v=spf1 ip6:2a01:dead::/32 -all", "pass"},  // IPv6 CIDR
		{"v=spf1 ip4:203.0.113.9 -all", "fail"},     // no match → falls to -all
		{"v=spf1 ip4:203.0.113.9 ~all", "softfail"}, // → ~all
		{"v=spf1 ip4:203.0.113.9 ?all", "neutral"},  // → ?all
		// F1: a matching ip with a Fail/SoftFail/Neutral qualifier is NOT a pass.
		{"v=spf1 -ip4:84.54.49.200 -all", "fail"},
		{"v=spf1 ~ip4:84.54.49.200 -all", "softfail"},
		{"v=spf1 ?ip4:84.54.49.200 -all", "neutral"},
		// F2: +all (and bare all) pass everything.
		{"v=spf1 +all", "pass"},
		{"v=spf1 mx all", "unknown"}, // mx unresolved appears before `all` → unknown
		// include/a/mx before a decision → unknown (first-match order matters).
		{"v=spf1 include:_spf.google.com -all", "unknown"},
		{"v=spf1 ip4:203.0.113.9 include:x -all", "unknown"},
		// but a direct match BEFORE the include is decidable.
		{"v=spf1 ip4:84.54.49.200 include:x -all", "pass"},
		{"v=spf1", "unknown"}, // no terminal
	}
	for _, c := range cases {
		if got := spfDirectResult(c.rec, srv); got != c.want {
			t.Errorf("spfDirectResult(%q) = %q, want %q", c.rec, got, c.want)
		}
	}
}

func TestDMARCTag(t *testing.T) {
	rec := "v=DMARC1; p=reject; pct=100; rua=mailto:x@y"
	if got := dmarcTag(rec, "p"); got != "reject" {
		t.Errorf("p = %q", got)
	}
	if got := dmarcTag(rec, "pct"); got != "100" {
		t.Errorf("pct = %q", got)
	}
	if got := dmarcTag(rec, "sp"); got != "" {
		t.Errorf("absent tag should be empty, got %q", got)
	}
}

func TestCheck_FullReport(t *testing.T) {
	srv := []string{"84.54.49.200"}
	f := fakeResolver{
		txt: map[string][]string{
			"axidwear.com":                    {"some-other-txt", "v=spf1 ip4:84.54.49.200 -all"},
			"_dmarc.axidwear.com":             {"v=DMARC1; p=reject; pct=100"},
			"default._domainkey.axidwear.com": {"v=DKIM1; k=rsa; p=MIGf..."},
		},
		mx:   map[string][]*net.MX{"axidwear.com": {{Host: "mail.axidwear.com.", Pref: 10}}},
		addr: map[string][]string{"84.54.49.200": {"titan.myip.gr."}},
		ip:   map[string][]net.IPAddr{"titan.myip.gr": {{IP: net.ParseIP("84.54.49.200")}}},
	}
	rep := Check(context.Background(), f, "AxidWear.com.", srv, nil)

	if rep.Domain != "axidwear.com" {
		t.Fatalf("domain not normalized: %q", rep.Domain)
	}
	if !rep.SPF.Present || rep.SPF.Multiple || rep.SPF.AuthorizesServerIP != "pass" || rep.SPF.AllQualifier != "-all" {
		t.Fatalf("SPF wrong: %+v", rep.SPF)
	}
	if !rep.DMARC.Present || rep.DMARC.Policy != "reject" || rep.DMARC.Pct != "100" {
		t.Fatalf("DMARC wrong: %+v", rep.DMARC)
	}
	if len(rep.DKIM) != 1 || !rep.DKIM[0].Present || rep.DKIM[0].Selector != "default" {
		t.Fatalf("DKIM wrong: %+v", rep.DKIM)
	}
	if !reflect.DeepEqual(rep.MX, []string{"mail.axidwear.com"}) {
		t.Fatalf("MX wrong: %+v", rep.MX)
	}
	if len(rep.PTR) != 1 || rep.PTR[0].Name != "titan.myip.gr" || !rep.PTR[0].FCrDNS {
		t.Fatalf("PTR wrong: %+v", rep.PTR)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("a fully-configured domain should have no findings, got %v", rep.Findings)
	}
}

func TestCheck_MisconfiguredFindings(t *testing.T) {
	srv := []string{"84.54.49.200"}
	f := fakeResolver{
		txt: map[string][]string{
			// SPF lists a different IP → server not authorized; no DMARC; no DKIM.
			"bad.example": {"v=spf1 ip4:203.0.113.1 -all"},
		},
		addr: map[string][]string{"84.54.49.200": {}}, // no PTR
	}
	rep := Check(context.Background(), f, "bad.example", srv, nil)
	if rep.SPF.AuthorizesServerIP != "fail" { // server IP not listed → falls through to -all
		t.Fatalf("expected SPF fail, got %q", rep.SPF.AuthorizesServerIP)
	}
	joined := ""
	for _, s := range rep.Findings {
		joined += s + "\n"
	}
	for _, want := range []string{"SPF: the server IP FAILS SPF", "DMARC: MISSING", "DKIM: no key", "PTR: 84.54.49.200 has no reverse DNS"} {
		if !contains(joined, want) {
			t.Fatalf("missing finding %q in:\n%s", want, joined)
		}
	}
}

func TestCheck_DKIMRevokedKeyNotPresent(t *testing.T) {
	f := fakeResolver{txt: map[string][]string{
		"default._domainkey.rev.example": {"v=DKIM1; k=rsa; p="}, // empty p= = revoked
	}}
	rep := Check(context.Background(), f, "rev.example", nil, nil)
	if len(rep.DKIM) != 1 || rep.DKIM[0].Present {
		t.Fatalf("revoked (empty p=) key must not be Present: %+v", rep.DKIM)
	}
	if !contains(rep.DKIM[0].Note, "revoked") {
		t.Fatalf("expected revoked note, got %q", rep.DKIM[0].Note)
	}
}

func TestCheck_MultipleSPFInvalid(t *testing.T) {
	f := fakeResolver{txt: map[string][]string{
		"dup.example": {"v=spf1 ip4:1.1.1.1 -all", "v=spf1 include:x ~all"},
	}}
	rep := Check(context.Background(), f, "dup.example", nil, nil)
	if !rep.SPF.Multiple {
		t.Fatalf("expected Multiple=true, got %+v", rep.SPF)
	}
	if !contains(join(rep.Findings), "SPF: INVALID") {
		t.Fatalf("expected invalid-SPF finding, got %v", rep.Findings)
	}
}

func TestCheck_TXTError(t *testing.T) {
	f := fakeResolver{txtErr: map[string]error{"err.example": errors.New("servfail")}}
	rep := Check(context.Background(), f, "err.example", nil, nil)
	if rep.SPF.Present || rep.SPF.Note == "" {
		t.Fatalf("expected SPF absent with a note on lookup error, got %+v", rep.SPF)
	}
}

func contains(hay, needle string) bool { return len(hay) >= len(needle) && indexOf(hay, needle) >= 0 }
func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
func join(ss []string) string {
	out := ""
	for _, s := range ss {
		out += s + "\n"
	}
	return out
}
