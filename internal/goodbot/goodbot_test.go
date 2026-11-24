package goodbot

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestSuffixName(t *testing.T) {
	for _, c := range []struct {
		ptr, name string
		ok        bool
	}{
		{"fwdproxy-frc-011.fbsv.net.", "meta", true},
		{"FWDPROXY-NCG-014.FBSV.NET", "meta", true},
		{"crawl-66-249-66-1.googlebot.com", "googlebot", true},
		// Google's special-case crawlers (AdsBot) stay verified; its
		// user-triggered fetchers, which fetch any URL a user hands Google,
		// never match (case and trailing dot normalised first).
		{"rate-limited-proxy-66-249-90-77.google.com", "google", true},
		{"google-proxy-192-178-8-41.google.com", "", false},
		{"GOOGLE-PROXY-66-249-82-238.GOOGLE.COM.", "", false},
		// An allow-list: any other google.com host never matches either, so
		// a new Google naming scheme does not verify silently.
		{"something-new-66-249-1-1.google.com", "", false},
		{"google.com", "", false},
		// The prefixes only apply under their own suffix.
		{"google-proxy-1.googlebot.com", "googlebot", true},
		{"fbsv.net.evil.example", "", false},
		{"evilfbsv.net", "", false},
		{"", "", false},
	} {
		name, _, ok := SuffixName(c.ptr)
		if name != c.name || ok != c.ok {
			t.Errorf("SuffixName(%q) = %q,%t want %q,%t", c.ptr, name, ok, c.name, c.ok)
		}
	}
}

func TestForwardConfirmsWith(t *testing.T) {
	ctx := context.Background()
	answer := func(addrs []string, err error) func(context.Context, string) ([]string, error) {
		return func(context.Context, string) ([]string, error) { return addrs, err }
	}
	if ok, err := ForwardConfirmsWith(ctx, answer([]string{"69.63.184.14"}, nil), "h", "69.63.184.14"); !ok || err != nil {
		t.Errorf("match = %t,%v want true,nil", ok, err)
	}
	if ok, err := ForwardConfirmsWith(ctx, answer([]string{"2a03:2880:0:0::1"}, nil), "h", "2a03:2880::1"); !ok || err != nil {
		t.Errorf("non-canonical v6 = %t,%v want true,nil", ok, err)
	}
	if ok, err := ForwardConfirmsWith(ctx, answer([]string{"203.0.113.1"}, nil), "h", "69.63.184.14"); ok || err != nil {
		t.Errorf("other address = %t,%v want false,nil", ok, err)
	}
	if ok, err := ForwardConfirmsWith(ctx, answer(nil, &net.DNSError{IsNotFound: true}), "h", "69.63.184.14"); ok || err != nil {
		t.Errorf("NXDOMAIN = %t,%v want a definitive false,nil", ok, err)
	}
	if ok, err := ForwardConfirmsWith(ctx, answer(nil, errors.New("timeout")), "h", "69.63.184.14"); ok || err == nil {
		t.Errorf("timeout = %t,%v want false with an error (inconclusive)", ok, err)
	}
}

// A PTR without a good-bot suffix is a verdict with no DNS at all.
func TestVerifyNoSuffixNoDNS(t *testing.T) {
	if name, cacheable := Verify("host.example.net", "192.0.2.1"); name != "" || !cacheable {
		t.Errorf("Verify(non-bot) = %q,%t want \"\",true", name, cacheable)
	}
}

// Suffixes is a copy: writing to it changes nothing the matcher trusts.
func TestSuffixesIsACopy(t *testing.T) {
	m := Suffixes()
	if m[".fbsv.net"] != "meta" {
		t.Fatalf("Suffixes() = %v, want .fbsv.net -> meta", m)
	}
	m[".example.net"] = "evil"
	if _, _, ok := SuffixName("x.example.net"); ok {
		t.Error("a write to the Suffixes() copy widened the registry")
	}
}

// Verify never forward-confirms a google-proxy-* PTR: no DNS, no verdict.
func TestVerifyGoogleProxyNotGoodBot(t *testing.T) {
	name, cacheable := Verify("google-proxy-192-178-8-41.google.com", "192.178.8.41")
	if name != "" || !cacheable {
		t.Errorf("Verify(google-proxy) = %q,%t want \"\",true", name, cacheable)
	}
}

func TestNotGoodBotPTR(t *testing.T) {
	for ptr, want := range map[string]bool{
		"google-proxy-192-178-8-41.google.com":       true,
		"GOOGLE-PROXY-66-249-82-238.GOOGLE.COM.":     true,
		"rate-limited-proxy-66-249-90-77.google.com": false,
		"crawl-66-249-66-1.googlebot.com":            false,
		"ppp089044094244.access.hol.gr":              false,
		"fwdproxy-frc-011.fbsv.net":                  false,
		"":                                           false,
	} {
		if got := NotGoodBotPTR(ptr); got != want {
			t.Errorf("NotGoodBotPTR(%q) = %v, want %v", ptr, got, want)
		}
	}
	// Every onlyPrefixes key must be a registry suffix, or it restricts nothing.
	for suf := range onlyPrefixes {
		if _, ok := ptrSuffixes[suf]; !ok {
			t.Errorf("onlyPrefixes key %q is not a ptrSuffixes suffix", suf)
		}
	}
}
