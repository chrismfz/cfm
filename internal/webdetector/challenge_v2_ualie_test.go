package webdetector

import (
	"strings"
	"testing"
)

// ua_lie: a legacy (EdgeHTML) Edge/12-18 token beside Chrome/80+, a pairing no
// browser shipped (uaplausible.LegacyEdgeOnModernChrome). The signals below are
// the three variants of the one scanner that sends it, as its solves were
// logged on the fleet (2026-09-22..29, cfm.challenges.log sig=): each passed
// before this tell existed. See docs/traffic-classifier.md, "ua_lie".

const (
	edgeLieUA    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36 Edge/12.246"
	realEdge18UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19577"
	edgeLieMacUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36 Edge/12.246"
)

func TestUALie_ScannerVariants(t *testing.T) {
	fail := defaultV2FailScore
	cases := []struct {
		name, tells string
		sig         *humanitySignals
		hs          int
		rejects     bool
	}{
		// sig=ptr:0,tch:0,key:0,mv:0,hc:16,dm:8,dpr:1,raf:16.7 + SwiftShader: hs was 90.
		{"software renderer variant", "ua_lie,sw_renderer,no_input",
			noInput(&humanitySignals{V: 1, HC: intp(16), DM: fptr(8), DPR: fptr(1), GLR: swiftShader}),
			tellSWRenderer + tellUALie + ampNoInput, true},
		// outer 0x0, sig=ptr:0,tch:0,key:0,mv:0,hc:16,dm:32,dpr:1: hs was 70.
		{"no-window variant", "ua_lie,outer_zero,no_input",
			noInput(&humanitySignals{V: 1, HC: intp(16), DM: fptr(32), DPR: fptr(1), OW: intp(0), OH: intp(0)}),
			tellOuterZero + tellUALie + ampNoInput, true},
		// sig=ptr:0,tch:0,key:0,mv:0,hc:16,dm:32,dpr:1 and nothing else: hs was
		// 0. The UA lie alone (+ the amplifier) stays below the bar — D5b: a UA
		// switcher set to this string is one fact. Documented residual.
		{"clean-report variant", "ua_lie,no_input",
			noInput(&humanitySignals{V: 1, HC: intp(16), DM: fptr(32), DPR: fptr(1)}),
			tellUALie + ampNoInput, false},
	}
	for _, c := range cases {
		hs, tells := tellsOf(t, c.sig, edgeLieUA)
		if tells != c.tells || hs != c.hs || (hs >= fail) != c.rejects {
			t.Errorf("%s: want hs=%d tells=%q rejects=%v, got hs=%d tells=%s", c.name, c.hs, c.tells, c.rejects, hs, tells)
		}
	}
}

func TestUALie_NoPayloadNeverRejects(t *testing.T) {
	// UA-borne, so it is scored (and listed) without a payload, but alone it
	// is a device claim: 50, a pass. No payload means no amplifier either.
	if hs, tells := tellsOf(t, nil, edgeLieUA); hs != tellUALie || tells != "ua_lie" {
		t.Fatalf("no payload: want hs=%d tells=ua_lie, got hs=%d tells=%s", tellUALie, hs, tells)
	}
}

func TestUALie_CountsOnceInTheDeviceClaimGroup(t *testing.T) {
	// A "Mac" legacy-Edge UA reporting 96 threads trips ua_lie AND mac_hw_lie:
	// one spoof, so the group adds its max once and it still passes alone.
	hs, tells := tellsOf(t, &humanitySignals{V: 1, HC: intp(96)}, edgeLieMacUA)
	if tells != "ua_lie,mac_hw_lie" || hs != tellUALie || hs >= defaultV2FailScore {
		t.Fatalf("group: want hs=%d tells=ua_lie,mac_hw_lie (pass), got hs=%d tells=%s", tellUALie, hs, tells)
	}
}

func TestUALie_RealLegacyEdgeIsNotALie(t *testing.T) {
	// Genuine Edge 18 (Chrome/70) on an RDP box: sw_renderer + no_input = 90,
	// exactly as before — a stale browser is not an impossible one.
	hs, tells := tellsOf(t, noInput(&humanitySignals{V: 1, HC: intp(8), GLR: swiftShader}), realEdge18UA)
	if tells != "sw_renderer,no_input" || hs != tellSWRenderer+ampNoInput {
		t.Fatalf("real Edge 18: want hs=%d tells=sw_renderer,no_input, got hs=%d tells=%s", tellSWRenderer+ampNoInput, hs, tells)
	}
}

func TestUALie_NotUnderTheHWTellsKillSwitch(t *testing.T) {
	// CHALLENGE_V2_HW_TELLS gates mobile_hw_lie / mac_hw_lie only; ua_lie (like
	// touch_lie) is scored with the switch off.
	hs, tells := scoreHumanityOpts(noInput(&humanitySignals{V: 1, HC: intp(16), GLR: swiftShader}), edgeLieUA, false)
	if got := strings.Join(tells, ","); got != "ua_lie,sw_renderer,no_input" || hs != tellSWRenderer+tellUALie+ampNoInput {
		t.Fatalf("switch off: want hs=%d tells=ua_lie,sw_renderer,no_input, got hs=%d tells=%s", tellSWRenderer+tellUALie+ampNoInput, hs, got)
	}
}

func TestUALie_WeightKeepsOuterZeroAlonePassing(t *testing.T) {
	// The weight is chosen so ua_lie + outer_zero (two medium facts, no
	// amplifier) still passes, while ua_lie + sw_renderer rejects like
	// mac_hw_lie + sw_renderer. A heavier ua_lie would flip the first.
	if hs, _ := tellsOf(t, &humanitySignals{V: 1, OW: intp(0), OH: intp(0)}, edgeLieUA); hs >= defaultV2FailScore {
		t.Fatalf("ua_lie + outer_zero alone must pass, got hs=%d", hs)
	}
	if hs, _ := tellsOf(t, &humanitySignals{V: 1, GLR: swiftShader}, edgeLieUA); hs < defaultV2FailScore {
		t.Fatalf("ua_lie + sw_renderer must reject, got hs=%d", hs)
	}
}
