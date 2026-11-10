package webdetector

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
)

// linux_sw (operator decision 2026-11-10, E4 read 6): a desktop Linux UA on a
// software renderer, +20 in the device-claim group. The farm fingerprint
// c28caa00 passed at exactly sw_renderer,no_input = 90 with an X11 Linux
// Chrome UA; with this tell that profile scores 110 and is rejected, while
// Linux + a software renderer ALONE (a real person on a Linux VM / RDP) is 80
// and still passes (D5b). See docs/traffic-classifier.md, "linux_sw".

const (
	linuxChromeUA  = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
	linuxFirefoxUA = "Mozilla/5.0 (X11; Linux x86_64; rv:158.0) Gecko/20100101 Firefox/158.0"
	linuxArmUA     = "Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
	crosUA         = "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
	// Android's reduced UA, without a "Mobile" token: a tablet. (Android
	// Chrome's "desktop site" mode sends exactly "X11; Linux x86_64" instead,
	// which IS classified desktop Linux: only such a tablet's hardware GPU
	// keeps it clear of the tell.)
	androidTabUA = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
	kindleUA     = "Mozilla/5.0 (X11; U; Linux armv7l like Android; en-us) AppleWebKit/531.2+ (KHTML, like Gecko) Version/5.0 Safari/531.2+ Kindle/3.0+"
	// A Linux phone OS that still says Mobile.
	linuxMobileUA = "Mozilla/5.0 (X11; Linux aarch64; Mobile; rv:128.0) Gecko/20100101 Firefox/128.0"
	winChromeUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
	llvmpipeGLR   = "ANGLE (Mesa, llvmpipe (LLVM 15.0.7 256 bits), OpenGL 4.5)"
	hwGLR         = "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002504) Direct3D11 vs_5_0 ps_5_0, D3D11)"
)

// The UA rule, one case per clause and per exclusion: removing any one of
// them flips at least one row (the mutation check in the change's review).
// "isolated" rows are combinations built so that ONE exclusion is all that
// keeps the UA out; the others are real UAs.
func TestUAClaimsDesktopLinux(t *testing.T) {
	for _, c := range []struct {
		ua   string
		want bool
		why  string
	}{
		{linuxChromeUA, true, "X11; Linux x86_64"},
		{linuxFirefoxUA, true, "Firefox on Linux"},
		{linuxArmUA, true, "X11; Linux aarch64"},
		{"Mozilla/5.0 (X11; Linux i686; rv:109.0) Gecko/20100101 Firefox/115.0", true, "X11; Linux i686"},
		{"Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:109.0) Gecko/20100101 Firefox/115.0", true, "distro form"},
		{"Mozilla/5.0 (X11; Fedora; Linux armv7l; rv:109.0) Gecko/20100101 Firefox/115.0", true, "distro + arch form"},
		{"mozilla/5.0 (x11; linux x86_64) applewebkit/537.36 (khtml, like gecko) chrome/154.0.0.0 safari/537.36", true, "tokens match case-insensitively"},
		// The X11 clause.
		{"Mozilla/5.0 (Windows NT 10.0; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36", false, "Linux without X11"},
		{"Mozilla/5.0 (Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36", false, "bare Linux form, unsourced"},
		// The Linux clause.
		{"Mozilla/5.0 (X11; FreeBSD amd64; rv:120.0) Gecko/20100101 Firefox/120.0", false, "X11 without Linux"},
		// Android (uaClaimsMobile), CrOS, Mobile.
		{androidTabUA, false, "Android tablet"},
		{androidUA, false, "Android phone"},
		{kindleUA, false, "X11 Linux like Android: the Android exclusion"},
		{crosUA, false, "ChromeOS"},
		{"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36", false, "isolated: the CrOS exclusion"},
		{linuxMobileUA, false, "the Mobile exclusion"},
		// TVs, cast devices, cars, cloud browsers.
		{"Mozilla/5.0 (SMART-TV; X11; Linux armv7l) AppleWebKit/537.42 (KHTML, like Gecko) Chromium/25.0.1349.2 Chrome/25.0.1349.2 Safari/537.42", false, "Samsung SMART-TV"},
		{"Mozilla/5.0 (X11; Linux; ko-KR) AppleWebKit/534.26+ (KHTML, like Gecko) Version/5.0 Safari/534.26+ LG Browser/5.00.00(+mouse+3D; SmartTV; 2012) LG NetCast.TV-2012", false, "LG NetCast (also SmartTV)"},
		{"Mozilla/5.0 (X11; Linux; ko-KR) AppleWebKit/534.26+ (KHTML, like Gecko) Version/5.0 Safari/534.26+ LG NetCast.TV-2012", false, "isolated: NetCast"},
		{"Mozilla/5.0 (X11; Linux armv7l; SmartTV) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36", false, "isolated: SmartTV"},
		{"Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.196 Safari/537.36 CrKey/1.56.500000", false, "Chromecast CrKey"},
		{"Mozilla/5.0 (X11; Linux armv7l; Tizen 2.3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36", false, "isolated: Tizen"},
		{"Mozilla/5.0 (X11; Linux armv7l; Web0S) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36", false, "isolated: Web0S"},
		{"Mozilla/5.0 (X11; Linux armv7l; webOS) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36", false, "isolated: webOS"},
		{"Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36 HbbTV/1.5.1", false, "isolated: HbbTV"},
		{"Mozilla/5.0 (X11; GNU/Linux) AppleWebKit/537.36 (KHTML, like Gecko) Chromium/79.0.3945.130 Chrome/79.0.3945.130 Safari/537.36 Tesla/2020.16.2.1-e99c70fff409", false, "Tesla, GNU/Linux"},
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36 Tesla/2023.44.30", false, "Tesla, Linux x86_64"},
		{"Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/534.35 (KHTML, like Gecko) Chrome/11.0.696.65 Safari/534.35 Puffin/2.9174AP", false, "Puffin, X11 form"},
		{"Mozilla/5.0 (Linux; U; Linux x86_64; en-US) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36 Puffin/9.7.2.51367AP", false, "Puffin, no X11"},
		{oldGalaxyUA, false, "Android phone with Mobile"},
		{winChromeUA, false, "Windows"},
		{macUA, false, "Mac"},
		{iphoneUA, false, "iPhone"},
		{"", false, "empty"},
	} {
		if got := uaClaimsDesktopLinux(c.ua); got != c.want {
			t.Errorf("%s: uaClaimsDesktopLinux(%.60q) = %v, want %v", c.why, c.ua, got, c.want)
		}
	}
}

// The score table the operator approved, and everything around it that must
// NOT move.
func TestLinuxSW_ScoreTable(t *testing.T) {
	cases := []struct {
		name, tells string
		sig         *humanitySignals
		ua          string
		hs          int
	}{
		// Read 6's farm profile: 60 + 20 + 30 = 110, rejected.
		{"c28caa00 profile: linux + swiftshader + no input", "sw_renderer,linux_sw,no_input",
			noInput(&humanitySignals{V: 1, HC: intp(8), GLR: swiftShader}), linuxChromeUA,
			tellSWRenderer + tellLinuxSW + ampNoInput},
		// The human on a Linux VM / RDP with input: 80, passes.
		{"linux + swiftshader alone", "sw_renderer,linux_sw",
			&humanitySignals{V: 1, HC: intp(8), GLR: swiftShader}, linuxChromeUA,
			tellSWRenderer + tellLinuxSW},
		{"linux firefox + llvmpipe alone", "sw_renderer,linux_sw",
			&humanitySignals{V: 1, GLR: llvmpipeGLR}, linuxFirefoxUA, tellSWRenderer + tellLinuxSW},
		{"linux aarch64 + no input", "sw_renderer,linux_sw,no_input",
			noInput(&humanitySignals{V: 1, GLR: swiftShader}), linuxArmUA, tellSWRenderer + tellLinuxSW + ampNoInput},
		// Unchanged: Windows / Mac with the same report stay at 90 — the RDP
		// human's profile (D5b).
		{"windows + swiftshader + no input", "sw_renderer,no_input",
			noInput(&humanitySignals{V: 1, HC: intp(8), GLR: swiftShader}), winChromeUA, tellSWRenderer + ampNoInput},
		{"mac + swiftshader + no input", "sw_renderer,no_input",
			noInput(&humanitySignals{V: 1, HC: intp(8), GLR: swiftShader}), macUA, tellSWRenderer + ampNoInput},
		// Never Android, ChromeOS or a mobile UA.
		{"android + swiftshader + no input", "sw_renderer,no_input",
			noInput(&humanitySignals{V: 1, GLR: swiftShader}), androidTabUA, tellSWRenderer + ampNoInput},
		{"chromeos + swiftshader + no input", "sw_renderer,no_input",
			noInput(&humanitySignals{V: 1, GLR: swiftShader}), crosUA, tellSWRenderer + ampNoInput},
		{"linux mobile + swiftshader", "sw_renderer",
			&humanitySignals{V: 1, GLR: swiftShader}, linuxMobileUA, tellSWRenderer},
		// No software renderer, no tell: a Linux UA alone is nothing, and
		// no_input never opens a score.
		{"linux + hardware GPU + no input", "",
			noInput(&humanitySignals{V: 1, GLR: hwGLR}), linuxChromeUA, 0},
		{"linux + no renderer reported", "",
			noInput(&humanitySignals{V: 1}), linuxChromeUA, 0},
		{"linux, no payload", "", nil, linuxChromeUA, 0},
		// Group: ua_lie (50) beside linux_sw (20) counts once, at 50 — no
		// stacking. (mobile_hw_lie / mac_hw_lie / touch_lie cannot co-fire:
		// their UA claims exclude a desktop Linux one.)
		{"linux legacy-edge lie + swiftshader", "ua_lie,sw_renderer,linux_sw",
			&humanitySignals{V: 1, GLR: swiftShader},
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36 Edge/12.246",
			tellSWRenderer + tellUALie},
		// A phone UA on a 16-thread box with a software renderer: the group
		// is mobile_hw_lie alone, exactly as before.
		{"android + 16 threads + swiftshader", "sw_renderer,mobile_hw_lie",
			&humanitySignals{V: 1, HC: intp(16), GLR: swiftShader}, androidUA, tellSWRenderer + tellMobileHWLie},
		// The RDS/VDI rule still holds: a Linux UA's core count is never a
		// lie, so 128 threads adds nothing beyond linux_sw.
		{"linux + 128 threads + swiftshader", "sw_renderer,linux_sw",
			&humanitySignals{V: 1, HC: intp(128), GLR: swiftShader}, linuxChromeUA, tellSWRenderer + tellLinuxSW},
		// With outer_zero: 60 + 40 + 20 = 120.
		{"linux + swiftshader + outer_zero", "sw_renderer,linux_sw,outer_zero",
			&humanitySignals{V: 1, GLR: swiftShader, OW: intp(0), OH: intp(0)}, linuxChromeUA,
			tellSWRenderer + tellOuterZero + tellLinuxSW},
	}
	for _, c := range cases {
		hs, tells := tellsOf(t, c.sig, c.ua)
		if tells != c.tells || hs != c.hs {
			t.Errorf("%s: want hs=%d tells=%q, got hs=%d tells=%q", c.name, c.hs, c.tells, hs, tells)
		}
	}
}

// CHALLENGE_V2_HW_TELLS = 0 turns linux_sw off with the other hardware tells;
// sw_renderer itself is unaffected.
func TestLinuxSW_KillSwitch(t *testing.T) {
	hs, tells := scoreHumanityOpts(noInput(&humanitySignals{V: 1, GLR: swiftShader}), linuxChromeUA, false)
	if got := strings.Join(tells, ","); got != "sw_renderer,no_input" || hs != tellSWRenderer+ampNoInput {
		t.Fatalf("switch off: want hs=%d tells=sw_renderer,no_input, got hs=%d tells=%s", tellSWRenderer+ampNoInput, hs, got)
	}
}

// The real-input rescue does not count linux_sw: Linux + sw + outer_zero with
// real input scores 120 and is rescued exactly as the Windows 100 class is. A
// stronger group member (ua_lie) leaves linux_sw no share, so that solve is
// judged at its full score.
func TestLinuxSW_Rescue(t *testing.T) {
	moved := func() *humanitySignals {
		return &humanitySignals{V: 1, GLR: swiftShader, PTR: intp(41), MV: fptr(714), TCH: intp(0), KEY: intp(0), OW: intp(0), OH: intp(0)}
	}
	for _, c := range []struct {
		name, ua, tells string
		hs              int
		rescued         bool
	}{
		{"linux 120", linuxChromeUA, "sw_renderer,linux_sw,outer_zero", 120, true},
		{"windows 100", winChromeUA, "sw_renderer,outer_zero", 100, true},
		{"linux ua_lie 150", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36 Edge/12.246",
			"ua_lie,sw_renderer,linux_sw,outer_zero", 150, false},
	} {
		sig := moved()
		hs, tells := tellsOf(t, sig, c.ua)
		if hs != c.hs || tells != c.tells || challengeV2InputRescue(sig, tells, hs) != c.rescued {
			t.Errorf("%s: hs=%d tells=%q rescued=%v, want %d %q %v", c.name, hs, tells,
				challengeV2InputRescue(sig, tells, hs), c.hs, c.tells, c.rescued)
		}
	}
	for tells, want := range map[string]int{
		"sw_renderer,linux_sw":                tellLinuxSW,
		"sw_renderer,linux_sw,no_input":       tellLinuxSW,
		"ua_lie,sw_renderer,linux_sw":         0,
		"sw_renderer,outer_zero":              0,
		"sw_renderer,touch_lie,mobile_hw_lie": 0,
		"":                                    0,
	} {
		if got := linuxSWShare(tells); got != want {
			t.Errorf("linuxSWShare(%q) = %d, want %d", tells, got, want)
		}
	}
}

// End to end at the gate, under a vhost arm: the read-6 farm profile is
// rejected, the same machine with real input passes, the Windows twin still
// passes at 90, and the 100 class with real input is rescued on Windows (100)
// and on Linux (120) alike. Unarmed, the farm profile passes and is scored at
// the same 110 (what the would_v2 shadow line reports).
func TestVerify_LinuxSWAtTheGate(t *testing.T) {
	base, capt := startVerifyServer(t)
	const armedHost = "shop.example.gr"
	setV2HostArmed(t, func(host string) bool { return host == armedHost })
	setV2GoodBot(t, func(context.Context, string, string) (string, string) { return "", "" })
	const (
		farm   = `{"v":1,"wd":false,"glr":"ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)","ow":1920,"oh":1080,"ptr":0,"tch":0,"key":0,"mv":0,"hc":8}`
		human  = `{"v":1,"wd":false,"glr":"ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)","ow":1920,"oh":1080,"ptr":41,"tch":0,"key":0,"mv":714,"hc":8}`
		oldPC  = `{"v":1,"wd":false,"glr":"Google SwiftShader","ow":0,"oh":0,"tch":0,"key":0,"ptr":41,"mv":714}`
		status = "X-CFM-V2"
	)
	resp := postVerify(t, base, "203.0.113.60", armedHost, linuxChromeUA, farm)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(status) != "reject" {
		t.Fatalf("farm profile: status=%d %s=%q, want 403 + reject", resp.StatusCode, status, resp.Header.Get(status))
	}
	if r := capt.rejects[len(capt.rejects)-1]; r.HumanityScore != 110 || r.HumanityTells != "sw_renderer,linux_sw,no_input" ||
		!strings.Contains(r.RejectLine(), ",rf:angle-swiftshader ") {
		t.Fatalf("farm reject: hs=%d tells=%q line=%q", r.HumanityScore, r.HumanityTells, r.RejectLine())
	}
	if resp = postVerify(t, base, "203.0.113.61", armedHost, linuxChromeUA, human); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("linux human with input: status=%d, want 303", resp.StatusCode)
	}
	if s := capt.solved[len(capt.solved)-1]; s.HumanityScore != 80 || s.V2Rescued != "" {
		t.Fatalf("linux human: hs=%d rescued=%q, want a plain 80 pass", s.HumanityScore, s.V2Rescued)
	}
	if resp = postVerify(t, base, "203.0.113.62", armedHost, winChromeUA, farm); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("windows twin: status=%d, want 303 (90 passes, D5b)", resp.StatusCode)
	}
	if s := capt.solved[len(capt.solved)-1]; s.HumanityScore != 90 || s.HumanityTells != "sw_renderer,no_input" {
		t.Fatalf("windows twin: hs=%d tells=%q", s.HumanityScore, s.HumanityTells)
	}
	if resp = postVerify(t, base, "203.0.113.63", armedHost, winChromeUA, oldPC); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("windows 100 class with input: status=%d, want the rescued 303", resp.StatusCode)
	}
	if s := capt.solved[len(capt.solved)-1]; s.V2Rescued != v2RescuedInput {
		t.Fatalf("windows 100 class: rescued=%q, want input", s.V2Rescued)
	}
	if resp = postVerify(t, base, "203.0.113.64", armedHost, linuxChromeUA, oldPC); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("linux 120 with input: status=%d, want the rescued 303 (linux_sw is not counted against the cap)", resp.StatusCode)
	}
	if s := capt.solved[len(capt.solved)-1]; s.HumanityScore != 120 || s.V2Rescued != v2RescuedInput ||
		!strings.Contains(s.HumanitySuffix(), " v2_rescued=input") {
		t.Fatalf("linux 120: hs=%d rescued=%q line=%q", s.HumanityScore, s.V2Rescued, s.HumanitySuffix())
	}
	// Unarmed: passes, shadow-scored at the same 110.
	if resp = postVerify(t, base, "203.0.113.65", "blog.example.gr", linuxChromeUA, farm); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("unarmed farm profile: status=%d, want 303", resp.StatusCode)
	}
	if s := capt.solved[len(capt.solved)-1]; s.HumanityScore != 110 || s.V2Grain != "" {
		t.Fatalf("unarmed: hs=%d grain=%q", s.HumanityScore, s.V2Grain)
	}

	// Kill switch through the verify path's settings snapshot.
	ConfigureChallengeV2HWTells(false)
	t.Cleanup(func() { ConfigureChallengeV2HWTells(true) })
	if resp = postVerify(t, base, "203.0.113.66", armedHost, linuxChromeUA, farm); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("switch off: status=%d, want 303 (90)", resp.StatusCode)
	}
	if s := capt.solved[len(capt.solved)-1]; s.HumanityScore != 90 || strings.Contains(s.HumanityTells, "linux_sw") {
		t.Fatalf("switch off: hs=%d tells=%q", s.HumanityScore, s.HumanityTells)
	}
}

// rf: the software-renderer family, log-only. One case per family, and
// absent whenever the renderer is not software.
func TestRendererFamily(t *testing.T) {
	for glr, want := range map[string]string{
		"Google SwiftShader": rfSwiftShader,
		"ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)": rfANGLESwiftShader,
		"ANGLE (Google, Vulkan 1.1.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)": rfANGLESwiftShader,
		"llvmpipe (LLVM 15.0.7, 256 bits)": rfLLVMPipe,
		llvmpipeGLR:                        rfLLVMPipe,
		"Gallium 0.4 on softpipe":          rfSoftpipe,
		"Software Rasterizer":              rfSWRast,
		"Mesa OffScreen":                   rfMesaOffscreen,
		hwGLR:                              "",
		"Apple M2":                         "",
		"":                                 "",
		"ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0)": "",
	} {
		if got := softwareRendererFamily(glr); got != want {
			t.Errorf("softwareRendererFamily(%q) = %q, want %q", glr, got, want)
		}
	}
}

// The table must call EXACTLY the same strings software as the marks list it
// replaced (2026-11-10): sw_renderer is a scored tell, and the rf refactor
// must not move it. oldMarks is that list verbatim; the corpus embeds each
// mark in real renderer shapes, in both cases, plus hardware strings.
func TestSoftwareRenderers_SameSetAsBefore(t *testing.T) {
	oldMarks := []string{
		"swiftshader", "llvmpipe", "softpipe", "software rasterizer", "mesa offscreen", "angle (google, vulkan 1.1.0 (swiftshader",
	}
	oldIsSoftware := func(glr string) bool {
		glr = strings.ToLower(glr)
		if glr == "" {
			return false
		}
		for _, m := range oldMarks {
			if strings.Contains(glr, m) {
				return true
			}
		}
		return false
	}
	corpus := []string{"", "Apple M2", hwGLR, llvmpipeGLR, swiftShader, "angle (", "ANGLE (Google, Vulkan 1.1.0 (SwiftShader",
		"Mesa Intel(R) UHD Graphics 620 (KBL GT2)", "Mesa DRI Intel(R) HD Graphics", "Microsoft Basic Render Driver",
		"Software", "rasterizer", "Mesa", "offscreen", "swift shader", "ANGLE (SwiftShader)"}
	for _, m := range oldMarks {
		for _, f := range []string{"%s", "ANGLE (Google, %s)", "Google %s Device", "%s driver"} {
			corpus = append(corpus, fmt.Sprintf(f, m), fmt.Sprintf(f, strings.ToUpper(m)))
		}
	}
	for _, r := range softwareRenderers {
		corpus = append(corpus, r.mark, r.mark+" "+r.also, r.also)
	}
	for _, glr := range corpus {
		if got, want := softwareRendererFamily(glr) != "", oldIsSoftware(glr); got != want {
			t.Errorf("%q: software=%v, the old list said %v", glr, got, want)
		}
	}
}

// rf rides sig= (log line) and payload.sig (history row) as a short enum,
// after every numeric reading, and is absent for a hardware renderer — and on
// the history row it is a JSON string.
func TestRendererFamily_Surfaces(t *testing.T) {
	sw := ChallengeSolve{sig: noInput(&humanitySignals{V: 1, GLR: swiftShader, HC: intp(8)}).sigFields()}
	if got := sw.SignalSuffix(); got != " sig=ptr:0,tch:0,key:0,hc:8,rf:angle-swiftshader" {
		t.Fatalf("sig= with a software renderer: %q", got)
	}
	if got := sw.signalMap()["rf"]; got != "angle-swiftshader" {
		t.Fatalf("payload.sig.rf = %#v, want the string angle-swiftshader", got)
	}
	hw := ChallengeSolve{sig: noInput(&humanitySignals{V: 1, GLR: hwGLR, HC: intp(8)}).sigFields()}
	if got := hw.SignalSuffix(); strings.Contains(got, "rf:") {
		t.Fatalf("a hardware renderer must carry no rf: %q", got)
	}
	if _, ok := hw.signalMap()["rf"]; ok {
		t.Fatal("a hardware renderer's history row carries rf")
	}
	// A software renderer and nothing else still yields a sig= field.
	only := ChallengeSolve{sig: (&humanitySignals{V: 1, GLR: "Google SwiftShader"}).sigFields()}
	if got := only.SignalSuffix(); got != " sig=rf:swiftshader" {
		t.Fatalf("rf alone: %q", got)
	}

	// Durable history: payload.sig.rf is persisted as the string.
	e := newSolveTestEngine(t)
	e.RecordChallengeSolved(ChallengeSolve{IP: "203.0.113.70", Host: "shop.example.com", URI: "/", HumanityScored: true, sig: sw.sig})
	sig, ok := latestSolveEvent(t, e).Payload["sig"].(map[string]any)
	if !ok || sig["rf"] != "angle-swiftshader" {
		t.Fatalf("persisted payload.sig = %#v", latestSolveEvent(t, e).Payload["sig"])
	}
}

// deviceClaimWeights is the one weight table claim() and linuxSWShare read: a
// member the scorer claims but the table lacks would score 0 silently. Every
// entry must weigh something, and the claim(...) calls in the scorer and the
// table's keys must be the same set (read from the source, so a new member
// cannot be added on one side only).
func TestDeviceClaimWeights_MatchTheScorer(t *testing.T) {
	src, err := os.ReadFile("challenge_v2.go")
	if err != nil {
		t.Fatal(err)
	}
	claimed := map[string]bool{}
	for _, m := range regexp.MustCompile(`\bclaim\("([a-z_]+)"\)`).FindAllStringSubmatch(string(src), -1) {
		claimed[m[1]] = true
	}
	if len(claimed) == 0 {
		t.Fatal("no claim(...) calls found in challenge_v2.go")
	}
	for name := range claimed {
		if w, ok := deviceClaimWeights[name]; !ok || w <= 0 {
			t.Errorf("claim(%q): weight %d, in table %v", name, w, ok)
		}
	}
	for name, w := range deviceClaimWeights {
		if w <= 0 || !claimed[name] {
			t.Errorf("deviceClaimWeights[%q] = %d, claimed by the scorer: %v", name, w, claimed[name])
		}
	}
}
