package webdetector

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"cfm/internal/enrich"
)

// The farm's Linux profile with no certain tell (sw_renderer + linux_sw +
// no_input = 110): it fails Rung 1 at every retry, like a VDI desk would.
const fallbackFailing = `{"v":1,"wd":false,"glr":"ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)","ow":1920,"oh":1080,"ptr":0,"tch":0,"key":0,"mv":0,"hc":8}`

func withFallback(t *testing.T, mode string) {
	t.Helper()
	ConfigureChallengeV2Fallback(mode)
	t.Cleanup(func() { ConfigureChallengeV2Fallback(fallbackAudience) })
}

func fallbackGeo(t *testing.T, cc string, asn uint, asnName string) {
	t.Helper()
	setSolveEnricher(t, func(ip string) enrich.Result {
		return enrich.Result{CountryISO: cc, ASN: asn, ASNName: asnName}
	})
}

// A failing solve with no certain tell, from the audience, is asked for one
// click instead of refused; the click passes it, marked; a token re-post with
// no input is asked again with the same token.
func TestVerify_FallbackAsksThenClickPasses(t *testing.T) {
	base, capt := startVerifyServer(t)
	fallbackGeo(t, "GR", 6799, "OTE SA (Hellenic Telecommunications Organisation)")
	post := verifyPoster(t, base, "198.51.100.30", "shop.example.gr", linuxChromeUA, time.Now().UTC())

	resp := post(fallbackFailing, nil)
	tok := resp.Header.Get(confirmHeader)
	if resp.StatusCode != http.StatusForbidden || tok == "" || resp.Header.Get("X-CFM-V2") != "" {
		t.Fatalf("first POST: status=%d token=%q v2=%q, want a 403 confirm, not a v2 reject", resp.StatusCode, tok, resp.Header.Get("X-CFM-V2"))
	}
	if solved, rejects := capt.counts(); solved != 0 || rejects != 0 {
		t.Fatalf("a fallback ask cleared or rejected: solved=%d rejects=%d", solved, rejects)
	}
	resp = post(fallbackFailing, map[string]string{confirmHeader: tok})
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(confirmHeader) != tok {
		t.Fatalf("token, no input: status=%d token=%q, want 403 and the same token", resp.StatusCode, resp.Header.Get(confirmHeader))
	}
	resp = post(fallbackFailing, map[string]string{confirmHeader: tok, clickHeader: "1"})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("clicked re-post: status=%d, want 303", resp.StatusCode)
	}
	solved, rejects := capt.counts()
	if solved != 1 || rejects != 0 {
		t.Fatalf("solved=%d rejects=%d, want 1/0", solved, rejects)
	}
	s := capt.solved[0]
	if s.V2Rescued != v2RescuedConfirm || s.V2Confirm != confirmClicked || s.V2Grain != v2GrainAll {
		t.Fatalf("solve marks: rescued=%q confirm=%q grain=%q", s.V2Rescued, s.V2Confirm, s.V2Grain)
	}
	if !strings.Contains(s.HumanitySuffix(), "v2_rescued=confirm") {
		t.Errorf("solve line lacks v2_rescued=confirm: %q", s.HumanitySuffix())
	}
}

// Refused as before: outside the audience, a datacenter ASN inside it, a
// certain tell, the knob off. Offered to everyone with the knob at all.
func TestVerify_FallbackScope(t *testing.T) {
	cases := []struct {
		name, mode, cc, asnName, body string
		asn                           uint
		wantConfirm                   bool
	}{
		{"outside the audience", fallbackAudience, "US", "Comcast Cable Communications, LLC", fallbackFailing, 7922, false},
		{"datacenter in the audience", fallbackAudience, "GR", "Hetzner Online GmbH", fallbackFailing, 24940, false},
		{"certain tell", fallbackAudience, "GR", "OTE SA", `{"v":1,"wd":true,"ptr":0,"tch":0,"key":0}`, 6799, false},
		{"knob off", fallbackOff, "GR", "OTE SA", fallbackFailing, 6799, false},
		{"knob all, outside the audience", fallbackAll, "US", "Comcast Cable Communications, LLC", fallbackFailing, 7922, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withFallback(t, c.mode)
			base, capt := startVerifyServer(t)
			fallbackGeo(t, c.cc, c.asn, c.asnName)
			resp := verifyPoster(t, base, "198.51.100.31", "shop.example.gr", linuxChromeUA, time.Now().UTC())(c.body, nil)
			gotConfirm := resp.StatusCode == http.StatusForbidden && resp.Header.Get(confirmHeader) != ""
			if gotConfirm != c.wantConfirm {
				t.Fatalf("status=%d token=%q v2=%q, want confirm=%v", resp.StatusCode, resp.Header.Get(confirmHeader), resp.Header.Get("X-CFM-V2"), c.wantConfirm)
			}
			if _, rejects := capt.counts(); !c.wantConfirm && rejects != 1 {
				t.Fatalf("rejects=%d, want the plain v2 reject", rejects)
			}
		})
	}
}

// The fallback ask names itself on the result=v2_confirm line.
func TestConfirmLine_Fallback(t *testing.T) {
	s := ChallengeSolve{IP: "198.51.100.32", Host: "shop.example.gr", HumanityScored: true, HumanityScore: 110, HumanityTells: "sw_renderer,linux_sw,no_input", V2Grain: v2GrainAll, ConfirmFallback: true}
	if l := s.ConfirmLine(); !strings.Contains(l, "result=v2_confirm") || !strings.HasSuffix(l, " confirm=fallback") {
		t.Fatalf("line=%q", l)
	}
	s.ConfirmFallback = false
	if strings.Contains(s.ConfirmLine(), "confirm=fallback") {
		t.Fatal("an under-attack confirm reads as a fallback")
	}
}

func TestConfigureChallengeV2Fallback(t *testing.T) {
	t.Cleanup(func() { ConfigureChallengeV2Fallback(fallbackAudience) })
	for in, want := range map[string]string{"off": fallbackOff, " ALL ": fallbackAll, "audience": fallbackAudience, "bogus": fallbackAudience, "": fallbackAudience} {
		ConfigureChallengeV2Fallback(in)
		challengeV2Fallback.mu.RLock()
		got := challengeV2Fallback.mode
		challengeV2Fallback.mu.RUnlock()
		if got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}
