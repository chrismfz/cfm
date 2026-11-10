package webdetector

import (
	"context"
	"net/http"
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
	// The bare desktop form, without X11 (Wayland-only builds, some Electron apps).
	linuxBareUA = "Mozilla/5.0 (Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
	crosUA      = "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
	// Android's reduced UA ("Linux; Android 10; K") and the desktop-mode
	// request some Android browsers send ("X11; Linux x86_64" is NOT in it,
	// but "Linux; Android" with no "Mobile" token is: a tablet).
	androidTabUA = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
	kindleUA     = "Mozilla/5.0 (X11; U; Linux armv7l like Android; en-us) AppleWebKit/531.2+ (KHTML, like Gecko) Version/5.0 Safari/531.2+ Kindle/3.0+"
	// A Linux phone OS that still says Mobile.
	linuxMobileUA = "Mozilla/5.0 (X11; Linux aarch64; Mobile; rv:128.0) Gecko/20100101 Firefox/128.0"
	winChromeUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
	llvmpipeGLR   = "ANGLE (Mesa, llvmpipe (LLVM 15.0.7 256 bits), OpenGL 4.5)"
	hwGLR         = "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002504) Direct3D11 vs_5_0 ps_5_0, D3D11)"
)

func TestUAClaimsDesktopLinux(t *testing.T) {
	for ua, want := range map[string]bool{
		linuxChromeUA:  true,
		linuxFirefoxUA: true,
		linuxArmUA:     true,
		linuxBareUA:    true,
		crosUA:         false,
		androidUA:      false,
		androidTabUA:   false,
		oldGalaxyUA:    false,
		kindleUA:       false,
		linuxMobileUA:  false,
		winChromeUA:    false,
		// Smart TVs: Linux, but not the desktop form.
		"Mozilla/5.0 (SMART-TV; Linux; Tizen 6.0) AppleWebKit/537.36 (KHTML, like Gecko) 85.0.4183.93/6.0 TV Safari/537.36":         false,
		"Mozilla/5.0 (Web0S; Linux/SmartTV) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36 WebAppManager": false,
		// Defensive exclusions: an Android-x86 build naming its arch, and a
		// CrOS token beside a Linux one — Android / ChromeOS win.
		"Mozilla/5.0 (Linux; Android 9; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36":           false,
		"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36": false,
		macUA:    false,
		iphoneUA: false,
		"":       false,
	} {
		if got := uaClaimsDesktopLinux(ua); got != want {
			t.Errorf("uaClaimsDesktopLinux(%.50q) = %v, want %v", ua, got, want)
		}
	}
}

// The score table the operator approved, and everything around it that must
// NOT move.
func TestLinuxSW_ScoreTable(t *testing.T) {
	fail := defaultV2FailScore
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
		{"bare linux x86_64 form", "sw_renderer,linux_sw",
			&humanitySignals{V: 1, GLR: swiftShader}, linuxBareUA, tellSWRenderer + tellLinuxSW},
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
	// The two numbers the operator approved, spelled out.
	if hs, _ := tellsOf(t, &humanitySignals{V: 1, GLR: swiftShader}, linuxChromeUA); hs != 80 || hs >= fail {
		t.Fatalf("linux + sw_renderer alone must be 80 and pass, got %d", hs)
	}
	if hs, _ := tellsOf(t, noInput(&humanitySignals{V: 1, GLR: swiftShader}), linuxChromeUA); hs != 110 || hs < fail {
		t.Fatalf("linux + sw_renderer + no_input must be 110 and reject, got %d", hs)
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

// The real-input rescue: linux_sw with real input can only score 80 (no_input
// needs zero events), which passes without a rescue; with outer_zero it is 120,
// over the fixed cap, and is not rescued.
func TestLinuxSW_Rescue(t *testing.T) {
	moved := &humanitySignals{V: 1, GLR: swiftShader, PTR: intp(41), MV: fptr(714), TCH: intp(0), KEY: intp(0)}
	hs, tells := tellsOf(t, moved, linuxChromeUA)
	if hs != tellSWRenderer+tellLinuxSW || hs >= defaultV2FailScore {
		t.Fatalf("linux + sw with input: hs=%d tells=%s, want a passing 80", hs, tells)
	}
	if !challengeV2InputRescue(moved, tells, hs) {
		t.Fatalf("the predicate itself must accept a <= cap score with input")
	}
	moved.OW, moved.OH = intp(0), intp(0)
	hs, tells = tellsOf(t, moved, linuxChromeUA)
	if hs != rescueMaxScore+tellLinuxSW || challengeV2InputRescue(moved, tells, hs) {
		t.Fatalf("linux + sw + outer_zero with input: hs=%d rescued=%v, want an unrescued %d",
			hs, challengeV2InputRescue(moved, tells, hs), rescueMaxScore+tellLinuxSW)
	}
}

// End to end at the gate, under a vhost arm: the read-6 farm profile is
// rejected, the same machine with real input passes, the Windows twin still
// passes at 90, a Windows 100-class solve with input is still rescued and a
// Linux one at 120 is not. Unarmed, the farm profile passes and is scored at
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
	resp = postVerify(t, base, "203.0.113.64", armedHost, linuxChromeUA, oldPC)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("linux 120 with input: status=%d, want 403 (over the rescue cap)", resp.StatusCode)
	}
	if r := capt.rejects[len(capt.rejects)-1]; r.HumanityScore != 120 || r.V2Rescued != "" {
		t.Fatalf("linux 120: hs=%d rescued=%q", r.HumanityScore, r.V2Rescued)
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

// rf: the software-renderer family, log-only. One case per family, the
// fallback, and absent whenever the renderer is not software.
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
		// The scorer's sw_renderer and the reading agree on every input.
		_, tells := tellsOf(t, &humanitySignals{V: 1, GLR: glr}, winChromeUA)
		if (tells == "sw_renderer") != (want != "") {
			t.Errorf("%q: tells=%q but family=%q", glr, tells, want)
		}
	}
	if got := rendererFamilyForMark("some future software gl", "some future software gl"); got != rfOther {
		t.Errorf("an unnamed mark must map to %q, got %q", rfOther, got)
	}
}

// Every mark the detector matches has a named family, so rf:other only ever
// means "a mark was added without one" — and this test fails that addition.
func TestRendererFamily_EveryMarkIsNamed(t *testing.T) {
	for _, m := range softwareRendererMarks {
		if f := softwareRendererFamily(m); f == "" || f == rfOther {
			t.Errorf("mark %q: family %q", m, f)
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
