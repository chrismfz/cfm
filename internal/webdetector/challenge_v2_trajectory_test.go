package webdetector

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The trajectory readings render after the original eight, in a fixed order,
// rounded like their kin (ratios to 2 decimals, movement to 1, ms whole), and
// a reported zero stays a zero.
func TestSignalSuffix_TrajectoryReadings(t *testing.T) {
	sig := parseHumanityBody([]byte(`{"v":1,"ptr":41,"mv":714,"hc":4,"raf":16.7,` +
		`"ut":0,"co":83,"st":0.4312,"dj":0.876,"mj":88.25,"pd":4200.4}`))
	if sig == nil {
		t.Fatal("a well-formed body must parse")
	}
	const want = " sig=ptr:41,mv:714,hc:4,raf:16.7,ut:0,co:83,st:0.43,dj:0.88,mj:88.3,pd:4200"
	if got := (ChallengeSolve{sig: sig.sigFields()}).SignalSuffix(); got != want {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
	// The history row carries the same rounded numbers under the same keys.
	m := (ChallengeSolve{sig: sig.sigFields()}).signalMap()
	if m["st"] != 0.43 || m["co"] != float64(83) || m["pd"] != float64(4200) || m["ut"] != float64(0) {
		t.Fatalf("history sig map: %v", m)
	}
	// A page predating them reports none, and none appear.
	old := parseHumanityBody([]byte(`{"v":1,"ptr":41,"mv":714}`))
	if got := (ChallengeSolve{sig: old.sigFields()}).SignalSuffix(); got != " sig=ptr:41,mv:714" {
		t.Fatalf("an old page's report grew keys: %q", got)
	}
}

// Digit sanity only, like the other retained readings: what is not a reading
// becomes absent, never a fabricated zero; anything a browser could report
// survives, including an st above 1 (impossible geometry is corpus, not a
// reason to erase the report).
func TestSanitize_TrajectoryReadings(t *testing.T) {
	sig := parseHumanityBody([]byte(`{"v":1,"ut":-1,"co":9000000,"st":1.5,"dj":-0.2,"mj":1e300,"pd":0}`))
	if sig == nil {
		t.Fatal("a well-formed body must parse")
	}
	if sig.UT != nil || sig.CO != nil || sig.DJ != nil || sig.MJ != nil {
		t.Fatalf("non-readings survived: ut=%v co=%v dj=%v mj=%v", sig.UT, sig.CO, sig.DJ, sig.MJ)
	}
	if got := (ChallengeSolve{sig: sig.sigFields()}).SignalSuffix(); got != " sig=st:1.5,pd:0" {
		t.Fatalf("readings must survive verbatim, got %q", got)
	}
}

// Scored by NOTHING: the same report with and without the trajectory readings
// — at their most bot-like (every event untrusted, a dead-straight path, a
// metronome) — scores identically and gets the same rescue answer. Tightening
// the rescue from this corpus is a later, measured change, not this one.
func TestTrajectoryReadingsDecideNothing(t *testing.T) {
	const win7 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
	base := `"v":1,"wd":false,"glr":"Google SwiftShader","ow":0,"oh":0,"ptr":41,"mv":714,"tch":0,"key":0`
	plain := parseHumanityBody([]byte(`{` + base + `}`))
	botty := parseHumanityBody([]byte(`{` + base + `,"ut":41,"co":41,"st":1,"dj":0,"mj":17.4,"pd":80}`))
	hs1, t1 := scoreHumanity(plain, win7)
	hs2, t2 := scoreHumanity(botty, win7)
	if hs1 != hs2 || strings.Join(t1, ",") != strings.Join(t2, ",") {
		t.Fatalf("trajectory readings moved the score: %d %v vs %d %v", hs1, t1, hs2, t2)
	}
	tells := strings.Join(t2, ",")
	if challengeV2InputRescue(plain, tells) != challengeV2InputRescue(botty, tells) {
		t.Fatal("trajectory readings moved the rescue")
	}
}

// The worst-case report the page can build must fit the verify body cap: an
// over-cap body reads as NO payload (hs=-), which would silently drop every
// reading, the rescue's included. Every key the page writes is here at its
// longest plausible JSON form (17-significant-digit numbers; the 128-char
// renderer string all 3-byte UTF-8).
func TestHumanityPayloadWorstCaseFitsTheCap(t *testing.T) {
	num := "-1234.567890123456"
	keys := []string{"v", "mv", "ptr", "tch", "key", "mtp", "hc", "dm", "ow", "oh", "dpr", "raf",
		"ut", "co", "st", "dj", "mj", "pd"}
	var b strings.Builder
	b.WriteString(`{"wd":false,"glr":"` + strings.Repeat("€", 128) + `"`)
	for _, k := range keys {
		b.WriteString(`,"` + k + `":` + num)
	}
	b.WriteString("}")
	if n := b.Len(); n >= maxVerifyBodyBytes {
		t.Fatalf("worst-case payload is %d bytes, cap %d", n, maxVerifyBodyBytes)
	}
	// The key list must be the page's: a key the page writes that is not
	// listed here would make this bound a guess.
	page := challengeHTML()
	listed := map[string]bool{"wd": true, "glr": true}
	for _, k := range keys {
		listed[k] = true
	}
	init := regexp.MustCompile(`var HS = \{([^}]*)\}`).FindStringSubmatch(page)
	if init == nil {
		t.Fatal("the page's HS initializer was not found")
	}
	written := regexp.MustCompile(`([a-z]+):`).FindAllStringSubmatch(init[1], -1)
	written = append(written, regexp.MustCompile(`HS\.([a-z]+)`).FindAllStringSubmatch(page, -1)...)
	if len(written) < len(keys) {
		t.Fatalf("found only %d page keys", len(written))
	}
	for _, w := range written {
		if !listed[w[1]] {
			t.Errorf("the page writes HS.%s, which this bound does not count — add it", w[1])
		}
	}
}

// The page's collector, run for real under node with a stub window: it
// dispatches pointer events and reads the body hsBody() would post. Skips
// without node locally; CI has node (make test-js), so there it must run.
func TestChallengePageTrajectoryCollector(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI for the challenge-page collector test")
		}
		t.Skip("node not installed")
	}
	page := strings.ReplaceAll(challengeHTML(), "%%", "%")
	start := strings.Index(page, "  var HS = {")
	end := strings.Index(page, "  function b64urlToBytes")
	if start < 0 || end < start {
		t.Fatal("collector markers not found in the page")
	}
	collector := page[start:end]

	run := func(t *testing.T, events string) map[string]any {
		t.Helper()
		js := `
var listeners = {};
var window = { addEventListener: function (t, fn) { listeners[t] = fn; }, outerWidth: 1366, outerHeight: 728, devicePixelRatio: 1 };
var navigator = { webdriver: false, maxTouchPoints: 0, hardwareConcurrency: 4 };
var document = { createElement: function () { return { getContext: function () { return null; } }; } };
function requestAnimationFrame() {}
function mv(x, y, t, dx, dy, extra) {
  var ev = { clientX: x, clientY: y, timeStamp: t, movementX: dx, movementY: dy, isTrusted: true,
             getCoalescedEvents: function () { return [0, 0]; } };
  for (var k in (extra || {})) ev[k] = extra[k];
  listeners.pointermove(ev);
}
` + collector + events + "\nprocess.stdout.write(hsBody());\n"
		f := filepath.Join(t.TempDir(), "collector.js")
		if err := os.WriteFile(f, []byte(js), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(node, f).CombinedOutput()
		if err != nil {
			t.Fatalf("node: %v\n%s", err, out)
		}
		var m map[string]any
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatalf("hsBody is not JSON: %q", out)
		}
		// Whatever the page posts must parse server-side.
		if parseHumanityBody(out) == nil {
			t.Fatalf("the daemon cannot parse the page's body: %q", out)
		}
		return m
	}
	has := func(m map[string]any, keys ...string) bool {
		for _, k := range keys {
			if _, ok := m[k]; ok {
				return true
			}
		}
		return false
	}

	t.Run("no events: no trajectory keys", func(t *testing.T) {
		m := run(t, "")
		if m["ptr"] != float64(0) || m["mv"] != float64(0) || has(m, "ut", "co", "st", "dj", "mj", "pd") {
			t.Fatalf("untouched page: %v", m)
		}
	})
	t.Run("one event: counts only", func(t *testing.T) {
		m := run(t, "mv(10, 10, 100, 3, 4);")
		if m["ut"] != float64(0) || m["co"] != float64(2) || m["mj"] != float64(7) || has(m, "st", "dj", "pd") {
			t.Fatalf("one event: %v", m)
		}
	})
	t.Run("straight metronome", func(t *testing.T) {
		m := run(t, "for (var i = 0; i < 5; i++) mv(10 + 30 * i, 20 + 40 * i, 1000 + 16 * i, 30, 40);")
		if m["st"] != float64(1) || m["dj"] != float64(0) || m["pd"] != float64(64) || m["mj"] != float64(70) ||
			m["co"] != float64(10) || m["ptr"] != float64(5) {
			t.Fatalf("straight line: %v", m)
		}
	})
	t.Run("a wandering path with uneven timing", func(t *testing.T) {
		m := run(t, `mv(0, 0, 0, 0, 0); mv(100, 0, 16, 100, 0); mv(100, 100, 50, 0, 100); mv(0, 100, 58, 100, 0);`)
		// net 100 over a 300 px path; gaps 16/34/8.
		if m["st"] != 0.33 || m["pd"] != float64(58) {
			t.Fatalf("wandering path: %v", m)
		}
		if dj, _ := m["dj"].(float64); dj < 0.5 || dj > 0.7 {
			t.Fatalf("dj=%v, want the CV of 16/34/8 (~0.59)", m["dj"])
		}
	})
	t.Run("script-dispatched events are counted apart, never as input", func(t *testing.T) {
		m := run(t, `for (var i = 0; i < 8; i++) mv(40 * i, 0, 16 * i, 40, 0, { isTrusted: false });`)
		if m["ut"] != float64(8) || m["ptr"] != float64(0) || m["mv"] != float64(0) || has(m, "co", "st", "dj", "mj", "pd") {
			t.Fatalf("untrusted only: %v", m)
		}
		// Mixed: the trusted events alone make the readings.
		m = run(t, `mv(0, 0, 0, 3, 4); mv(500, 0, 5, 500, 0, { isTrusted: false }); mv(30, 40, 16, 30, 40);`)
		if m["ut"] != float64(1) || m["ptr"] != float64(2) || m["mv"] != float64(77) || m["mj"] != float64(70) || m["st"] != float64(1) {
			t.Fatalf("mixed: %v", m)
		}
	})
	t.Run("no coalescing API", func(t *testing.T) {
		m := run(t, `mv(0, 0, 0, 1, 1, { getCoalescedEvents: undefined }); mv(5, 5, 16, 5, 5, { getCoalescedEvents: undefined });`)
		if m["ut"] != float64(0) || has(m, "co") || m["ptr"] != float64(2) {
			t.Fatalf("no coalescing API: %v", m)
		}
	})
}
