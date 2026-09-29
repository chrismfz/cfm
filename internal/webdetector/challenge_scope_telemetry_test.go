package webdetector

import (
	"net/http"
	"strings"
	"testing"

	"cfm/internal/abuseshadow"
)

// scope= names the surface a solve was verified on (web / panel:<port>). The
// rung marks and the IP release are web-scope only, so without it a panel
// solve reads exactly like a web one on every line and row.

func TestScopeSuffix_RendersTheVerifyScope(t *testing.T) {
	for _, c := range []struct{ scope, want string }{
		{"", ""}, // a literal that never went through verify
		{"web", " scope=web"},
		{"panel:2083", " scope=panel:2083"},
		{"panel 2083", ` scope="panel 2083"`}, // not a token: quoted, never splits the line
	} {
		if got := (ChallengeSolve{Scope: c.scope}).ScopeSuffix(); got != c.want {
			t.Errorf("Scope %q: got %q, want %q", c.scope, got, c.want)
		}
	}
}

// The challenge server's own result=solved line (no hook installed): scope=
// follows the geo fields and src=.
func TestSolvedLine_ScopeFollowsGeoAndSrc(t *testing.T) {
	s := ChallengeSolve{IP: "203.0.113.40", Host: "h", URI: "/", Diff: 16, UA: "Mozilla/5.0",
		CountryISO: "GR", ASN: 6799, ASNName: "OTEnet S.A.", SrcResolved: true, Scope: "web"}
	line := s.SolvedLine()
	if !strings.HasPrefix(line, "[challenge] ip=203.0.113.40 host=h uri=/ result=solved ms=0 solve_ms=- diff=16 tls_fp=- ua_family=- ") {
		t.Fatalf("head: %q", line)
	}
	if !strings.HasSuffix(line, ` cc=GR asn=6799 asn_name="OTEnet S.A." src=- scope=web`) {
		t.Fatalf("tail: %q", line)
	}
}

func TestScope_RidesLastOnTheRejectLineAndInTheHistoryRow(t *testing.T) {
	s := ChallengeSolve{IP: "1.2.3.4", Host: "h", HumanityScored: true, HumanityScore: 100,
		V2Grain: "vhost", V2Via: "manual", SrcResolved: true, Src: []string{"vhost:manual"}, Scope: "panel:2083"}
	if line := s.RejectLine(); !strings.HasSuffix(line, " src=vhost:manual v2_via=manual scope=panel:2083") {
		t.Fatalf("reject line: %q", line)
	}
	if got := s.historyPayload()["scope"]; got != "panel:2083" {
		t.Fatalf("history payload scope: %v", got)
	}
	if _, ok := (ChallengeSolve{}).historyPayload()["scope"]; ok {
		t.Fatal("an unset scope must not persist")
	}
	// Not a humanity key: a row written with the rung off carries it too.
	if got := (ChallengeSolve{Scope: "web"}).historyPayload()["scope"]; got != "web" {
		t.Fatalf("unscored solve lost scope: %v", got)
	}
}

func TestScope_OnTheShadowLineRoundTripsThroughTheParser(t *testing.T) {
	s := ChallengeSolve{UAFamily: "Chrome", SrcResolved: true, Src: []string{"waf:302"}, Scope: "panel:2083"}
	line := "2026-09-29 10:00:00 [abuse-shadow] signal=humanity host=h ip=1.2.3.4 hs=130 tells=webdriver fp=- verdict=would_v2" + s.ShadowContextSuffix()
	e, ok := abuseshadow.Parse(line)
	if !ok || e.Src != "waf:302" || e.Scope != "panel:2083" || !strings.HasSuffix(line, " src=waf:302 scope=panel:2083") {
		t.Fatalf("parsed %+v from %q", e, line)
	}
	// The common case renders too: a web-scope would_v2 line is not "(unknown)".
	s.Scope = "web"
	if got := s.ShadowContextSuffix(); !strings.HasSuffix(got, " src=waf:302 scope=web") {
		t.Fatalf("web scope: %q", got)
	}
	// A value that is not a plain token renders invalid, like ptr=.
	if got := (ChallengeSolve{Scope: "a b"}).ShadowContextSuffix(); !strings.HasSuffix(got, " scope=invalid") {
		t.Fatalf("non-token scope: %q", got)
	}
}

// End to end: the scope the verify resolved is the one the solve and the
// reject carry — a web verify says web, a panel verify names its port.
func TestVerify_SolveAndRejectCarryTheVerifyScope(t *testing.T) {
	base, capt := startVerifyServer(t)
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
	panel := map[string]string{"X-CFM-Panel-Port": "2083", "X-Forwarded-Port": "2083"}

	solve := func(hdr map[string]string, want string) {
		t.Helper()
		n, _ := capt.counts()
		resp := postVerifyHdr(t, base, "203.0.113.40", "shop.example.com", ua, `{"v":1}`, hdr)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("scope %s: status %d, want the solved redirect", want, resp.StatusCode)
		}
		capt.mu.Lock()
		defer capt.mu.Unlock()
		if len(capt.solved) != n+1 || capt.solved[n].Scope != want {
			t.Fatalf("solved: want one solve with scope %q, got %+v", want, capt.solved[n:])
		}
	}
	solve(nil, "web")
	solve(panel, "panel:2083")

	// A reject on the panel scope (a vhost arm covers every scope) names it too.
	setV2HostArmed(t, func(host string) bool { return host == "shop.example.com" })
	_, r0 := capt.counts()
	resp := postVerifyHdr(t, base, "203.0.113.41", "shop.example.com", ua, `{"v":1,"wd":true,"ptr":0,"tch":0,"key":0}`, panel)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-CFM-V2") != "reject" {
		t.Fatalf("panel reject: status %d", resp.StatusCode)
	}
	capt.mu.Lock()
	defer capt.mu.Unlock()
	if len(capt.rejects) != r0+1 || capt.rejects[r0].Scope != "panel:2083" ||
		!strings.HasSuffix(capt.rejects[r0].RejectLine(), " scope=panel:2083") {
		t.Fatalf("reject: %+v", capt.rejects[r0:])
	}
}
