package webdetector

import (
	"strings"
	"testing"
)

// Device-claim tells (mobile_hw_lie, mac_hw_lie) and the device-claim group,
// written from the 2026-09-23 fleet corpus. Every NEGATIVE case below is a
// real human setup found in that corpus (or a platform fact the tells must
// respect); every POSITIVE case is a farm shape from it. See
// docs/traffic-classifier.md, "Rung-1 hardware tells".

const (
	iphoneUA     = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1"
	macUA        = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
	lenovoTabUA  = "Mozilla/5.0 (Linux; Android 11; Lenovo TB-X306F Build/RP1A.200720.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/153.0.0.0 Safari/537.36"
	oldGalaxyUA  = "Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36"
	firefoxAndUA = "Mozilla/5.0 (Android 14; Mobile; rv:143.0) Gecko/143.0 Firefox/143.0"
	swiftShader  = "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)"
)

func tellsOf(t *testing.T, sig *humanitySignals, ua string) (int, string) {
	t.Helper()
	hs, tells := scoreHumanity(sig, ua)
	return hs, strings.Join(tells, ",")
}

func noInput(sig *humanitySignals) *humanitySignals {
	sig.PTR, sig.TCH, sig.KEY = intp(0), intp(0), intp(0)
	return sig
}

// The human setups the corpus showed near these tells must stay clean.
func TestHWTells_RealHumanSetupsStayClean(t *testing.T) {
	cases := []struct {
		name string
		sig  *humanitySignals
		ua   string
	}{
		{"iphone safari", &humanitySignals{V: 1, HC: intp(4), DPR: fptr(3)}, iphoneUA},
		// Cheap Android tablet: dpr 1 is REAL here (why dpr is not a tell).
		{"lenovo tablet dpr 1", &humanitySignals{V: 1, HC: intp(8), DM: fptr(4), DPR: fptr(1)}, lenovoTabUA},
		// Top human Android core count seen: 10.
		{"android 10 cores", &humanitySignals{V: 1, HC: intp(10), DM: fptr(8)}, androidUA},
		// Real workstations in GR ISPs: 32 and 48 threads (why the bar is 64).
		{"ryzen 32 threads", &humanitySignals{V: 1, HC: intp(32), DM: fptr(32), DPR: fptr(1)}, chromeUA},
		{"48 threads", &humanitySignals{V: 1, HC: intp(48), DM: fptr(32), DPR: fptr(1)}, chromeUA},
		// RDS/VDI session host: a Windows or Linux UA with 64+ logical
		// processors is NOT a contradiction (review finding) — only a Mac or
		// a phone claiming that many is.
		{"windows rds host 64 threads", &humanitySignals{V: 1, HC: intp(64), DM: fptr(8)}, chromeUA},
		{"linux box 128 threads", &humanitySignals{V: 1, HC: intp(128)}, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"},
		// Old Intel Mac, dpr 1, 2 threads.
		{"old mac dpr 1", &humanitySignals{V: 1, HC: intp(2), DM: fptr(8), DPR: fptr(1)}, macUA},
		// Firefox on Android: no deviceMemory at all.
		{"firefox android", &humanitySignals{V: 1, HC: intp(8)}, firefoxAndUA},
		// deviceMemory under an iOS UA is NOT a tell (measured, not adopted:
		// redundant in the corpus, and legitimate for an EU non-WebKit browser).
		{"ios with deviceMemory", &humanitySignals{V: 1, HC: intp(4), DM: fptr(4)}, iphoneUA},
	}
	for _, c := range cases {
		if hs, tells := tellsOf(t, c.sig, c.ua); hs != 0 {
			t.Errorf("%s: a real human setup scored hs=%d tells=%s", c.name, hs, tells)
		}
	}
}

// Absence never convicts (D5b): a mobile UA reporting no hc.
func TestHWTells_AbsenceNeverConvicts(t *testing.T) {
	if hs, tells := tellsOf(t, &humanitySignals{V: 1, DM: fptr(8)}, androidUA); hs != 0 {
		t.Fatalf("android with no hc: hs=%d %s", hs, tells)
	}
}

// Boundaries: the bars are >= 16 (phone/tablet UA) and >= 64 (Mac UA); a
// Windows/Linux UA has no bar at all.
func TestHWTells_Boundaries(t *testing.T) {
	for _, c := range []struct {
		hc   int
		ua   string
		want string
	}{
		{15, androidUA, ""},
		{16, androidUA, "mobile_hw_lie"},
		{63, macUA, ""},
		{64, macUA, "mac_hw_lie"},
		{64, androidUA, "mobile_hw_lie"},
		{256, chromeUA, ""},
	} {
		if _, tells := tellsOf(t, &humanitySignals{V: 1, HC: intp(c.hc)}, c.ua); tells != c.want {
			t.Errorf("hc %d on %.30s: tells %q, want %q", c.hc, c.ua, tells, c.want)
		}
	}
}

// THE DEVICE-CLAIM GROUP: members are all LISTED, but hs takes the group's
// strongest weight once — one spoofed device never rejects on its own, however
// many members it trips (review finding: the sum did).
func TestHWTells_DeviceClaimGroupNeverRejectsAlone(t *testing.T) {
	fail := defaultV2FailScore
	cases := []struct {
		name, want string
		sig        *humanitySignals
		ua         string
		hs         int
	}{
		// DevTools phone emulation / a UA switcher on a 16-thread desktop:
		// zero touch points AND desktop cores under an iPhone UA.
		{"ua switcher on a 16-thread desktop", "touch_lie,mobile_hw_lie,no_input",
			noInput(&humanitySignals{V: 1, MTP: intp(0), HC: intp(16), DM: fptr(8)}), iphoneUA, tellMobileHWLie + ampNoInput},
		// Android emulator (BlueStacks, Studio) on a big host, opened in-app
		// with no visible window: group + outer_zero, but no third signal.
		{"android emulator, in-app", "outer_zero,mobile_hw_lie",
			&humanitySignals{V: 1, HC: intp(16), OW: intp(0), OH: intp(0)}, androidUA, tellMobileHWLie + tellOuterZero},
		// "Android 5.0" reporting 128 threads.
		{"android 5 with 128 threads", "mobile_hw_lie",
			&humanitySignals{V: 1, HC: intp(128), DM: fptr(8)}, oldGalaxyUA, tellMobileHWLie},
		// A farm "iPhone" on a 96-thread box without a software renderer.
		{"iphone on a server, real GPU", "mobile_hw_lie,no_input",
			noInput(&humanitySignals{V: 1, HC: intp(96), DM: fptr(32), DPR: fptr(1)}), iphoneUA, tellMobileHWLie + ampNoInput},
		// A "Mac" with 96 threads, real GPU.
		{"mac 96 threads, real GPU", "mac_hw_lie", &humanitySignals{V: 1, HC: intp(96)}, macUA, tellMacHWLie},
		// touch_lie alone scores exactly as before the group existed.
		{"touch_lie alone", "touch_lie", &humanitySignals{V: 1, MTP: intp(0)}, androidUA, tellTouchLie},
	}
	for _, c := range cases {
		hs, tells := tellsOf(t, c.sig, c.ua)
		if tells != c.want || hs != c.hs || hs >= fail {
			t.Errorf("%s: want PASS hs=%d tells=%q, got hs=%d tells=%s", c.name, c.hs, c.want, hs, tells)
		}
	}
}

// A device-claim contradiction PLUS independent evidence from outside the
// group rejects — the shape every caught farm solve in the corpus had
// (software renderer).
func TestHWTells_CorroboratedFarmShapesFail(t *testing.T) {
	fail := defaultV2FailScore
	cases := []struct {
		name, want string
		sig        *humanitySignals
		ua         string
	}{
		// gastronom.hk / kialasiatrika.gr: an "iPhone" on a 96-thread box with SwiftShader.
		{"iphone on a server + swiftshader", "sw_renderer,mobile_hw_lie,no_input",
			noInput(&humanitySignals{V: 1, HC: intp(96), DM: fptr(32), DPR: fptr(1), GLR: swiftShader}), iphoneUA},
		// vitolighting.com: a "Mac" with 96 threads and a software renderer.
		{"mac 96 threads + swiftshader", "sw_renderer,mac_hw_lie",
			&humanitySignals{V: 1, HC: intp(96), DM: fptr(32), GLR: swiftShader}, macUA},
	}
	for _, c := range cases {
		hs, tells := tellsOf(t, c.sig, c.ua)
		if tells != c.want || hs < fail {
			t.Errorf("%s: want FAIL with %q, got hs=%d tells=%s", c.name, c.want, hs, tells)
		}
	}
	// And the same software renderer WITHOUT a device lie still passes —
	// including on a 64-thread RDS/VDI host (the human D5b protects; review
	// finding: a Windows/Linux core count is never a device lie).
	if hs, _ := tellsOf(t, noInput(&humanitySignals{V: 1, HC: intp(8), GLR: swiftShader}), chromeUA); hs >= fail {
		t.Fatalf("sw_renderer + no_input alone must still pass, got %d", hs)
	}
	if hs, tells := tellsOf(t, noInput(&humanitySignals{V: 1, HC: intp(64), GLR: swiftShader}), chromeUA); hs >= fail {
		t.Fatalf("an RDS user (64 threads + SwiftShader, Windows UA) must pass, got hs=%d tells=%s", hs, tells)
	}
}

// The readings reach the tells through the real body parser. The sanitize
// bound DROPS an over-bound hc (never clamps: sig= stays as reported) — a
// knowing D5b residual, pinned here so a change to it is deliberate.
func TestHWTells_ThroughParseHumanityBody(t *testing.T) {
	sig := parseHumanityBody([]byte(`{"v":1,"wd":false,"mtp":5,"ow":390,"oh":844,"ptr":0,"tch":0,"key":0,"mv":0,"hc":96,"dm":32,"dpr":1,"raf":16.7}`))
	if sig == nil {
		t.Fatal("payload did not parse")
	}
	if hs, tells := tellsOf(t, sig, iphoneUA); tells != "mobile_hw_lie,no_input" || hs != tellMobileHWLie+ampNoInput {
		t.Fatalf("parsed farm payload: hs=%d tells=%s", hs, tells)
	}
	if sig = parseHumanityBody([]byte(`{"v":1,"hc":2000000}`)); sig == nil || sig.HC != nil {
		t.Fatalf("an over-bound hc must be dropped (as reported, never fabricated), got %+v", sig)
	}
	if sig = parseHumanityBody([]byte(`{"v":1,"hc":-4}`)); sig.HC != nil {
		t.Fatalf("a negative hc must be dropped, got %d", *sig.HC)
	}
}

// CHALLENGE_V2_HW_TELLS = 0 is a kill switch: the hardware members are not
// evaluated at all; touch_lie is unaffected. The knob rides the same settings
// snapshot as the other v2 knobs.
func TestHWTells_KillSwitch(t *testing.T) {
	if hs, tells := tellsOf(t, &humanitySignals{V: 1, HC: intp(96), GLR: swiftShader}, macUA); tells != "sw_renderer,mac_hw_lie" || hs != tellSWRenderer+tellMacHWLie {
		t.Fatalf("on: hs=%d tells=%s", hs, tells)
	}
	hs, tells := scoreHumanityOpts(&humanitySignals{V: 1, HC: intp(96), GLR: swiftShader}, macUA, false)
	if strings.Join(tells, ",") != "sw_renderer" || hs != tellSWRenderer {
		t.Fatalf("off: hs=%d tells=%v", hs, tells)
	}
	if _, tells := scoreHumanityOpts(&humanitySignals{V: 1, MTP: intp(0), HC: intp(96)}, androidUA, false); strings.Join(tells, ",") != "touch_lie" {
		t.Fatalf("off must leave touch_lie alone, got %v", tells)
	}

	ConfigureChallengeV2HWTells(false)
	t.Cleanup(func() { ConfigureChallengeV2HWTells(true) })
	if _, _, _, _, hw := challengeV2SettingsAll(); hw {
		t.Fatalf("the knob must reach the settings snapshot")
	}
}
