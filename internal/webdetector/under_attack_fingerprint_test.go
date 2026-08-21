package webdetector

import (
	"math"
	"testing"
	"time"
)

func newFPTestEngine() *Engine {
	e := &Engine{}
	e.cfg.UnderAttack = true
	e.cfg.UnderAttackFingerprint = true
	e.cfg.UnderAttackFPCoverageMin = 0.60
	e.cfg.UnderAttackFPCollisionMax = 0.005
	e.attack = newUnderAttackTracker()
	e.fp = newFPState()
	return e
}

func findCand(cands []fpCandidate, kind, value string) (fpCandidate, bool) {
	for _, c := range cands {
		if c.kind == kind && (value == "" || c.value == value) {
			return c, true
		}
	}
	return fpCandidate{}, false
}

func TestFPBasePath(t *testing.T) {
	cases := map[string]string{
		"/shop/filters/x": "/shop/",
		"/shop/":          "/shop/",
		"/wp-login.php":   "/wp-login.php",
		"/":               "/",
		"":                "/",
		"/api/v1/users":   "/api/",
	}
	for in, want := range cases {
		if got := fpBasePath(in); got != want {
			t.Fatalf("fpBasePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFPNormEntropy(t *testing.T) {
	uniform := map[string]int{"a": 25, "b": 25, "c": 25, "d": 25}
	if h := fpNormEntropy(uniform, 100); h < 0.99 {
		t.Fatalf("uniform entropy = %.3f, want ~1", h)
	}
	skewed := map[string]int{"a": 970, "b": 10, "c": 10, "d": 10}
	if h := fpNormEntropy(skewed, 1000); h > 0.4 {
		t.Fatalf("skewed entropy = %.3f, want low", h)
	}
	if h := fpNormEntropy(map[string]int{"only": 100}, 100); h != 0 {
		t.Fatalf("single-key entropy = %.3f, want 0", h)
	}
}

func TestFPCapMap(t *testing.T) {
	m := map[string]float64{"a": 1, "b": 5, "c": 3, "d": 9, "e": 2}
	fpCapMap(m, 3)
	if len(m) != 3 {
		t.Fatalf("cap: len=%d want 3", len(m))
	}
	for _, k := range []string{"d", "b", "c"} { // the three highest
		if _, ok := m[k]; !ok {
			t.Fatalf("cap dropped a top-weight key %q: %v", k, m)
		}
	}
}

func TestFPBaselineDecayAndFold(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := newFPState()
	s.updateBaseline("h", &fpSnapshot{basePaths: map[string]int{"/a/": 100}, uas: map[string]int{"ua": 100}, total: 100}, 1.0, now)
	if _, tot := s.baselineCopy("h"); tot != 100 {
		t.Fatalf("first fold total = %.1f want 100", tot)
	}
	// Second fold with decay 0.5: prior 100 -> 50, plus new 100 -> 150.
	s.updateBaseline("h", &fpSnapshot{basePaths: map[string]int{"/a/": 100}, total: 100}, 0.5, now)
	if _, tot := s.baselineCopy("h"); math.Abs(tot-150) > 0.01 {
		t.Fatalf("decayed fold total = %.3f want 150", tot)
	}
}

// The e-athlos calibration for I2: attack concentrated on a path that is RARE in
// the baseline arms; a path that also carries legit traffic does not.
func TestFPCandidates_ArmOnlyWhenBaselineClean(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	e := newFPTestEngine()

	// --- clean case: attack on /wp-login.php, absent from a healthy baseline ---
	host := "clean.example"
	e.fp.updateBaseline(host, &fpSnapshot{
		basePaths: map[string]int{"/home/": 700, "/product/": 300},
		uas:       map[string]int{"chrome": 1000},
		total:     1000,
	}, 1.0, now)
	attack := &fpSnapshot{basePaths: map[string]int{"/wp-login.php": 950, "/home/": 50}, uas: map[string]int{"badbot": 1000}, total: 1000}
	cands, _, _, baseTotal, ok := e.fpCandidates(host, attack)
	if !ok || baseTotal < fpMinBaselineTotal {
		t.Fatalf("baseline should be sufficient: total=%.0f ok=%v", baseTotal, ok)
	}
	c, found := findCand(cands, "path", "/wp-login.php")
	if !found {
		t.Fatalf("no /wp-login.php candidate: %+v", cands)
	}
	if math.Abs(c.coverage-0.95) > 0.001 || c.collision != 0 {
		t.Fatalf("clean candidate: coverage=%.3f collision=%.4f want 0.95/0", c.coverage, c.collision)
	}
	if !e.fpWouldArm(c) {
		t.Fatalf("clean rare-path candidate should would-arm: %+v", c)
	}

	// --- collision case: attack on /shop/ which is 40%% of legit traffic ---
	host2 := "shop.example"
	e.fp.updateBaseline(host2, &fpSnapshot{
		basePaths: map[string]int{"/shop/": 400, "/home/": 600},
		total:     1000,
	}, 1.0, now)
	attack2 := &fpSnapshot{basePaths: map[string]int{"/shop/": 950, "/home/": 50}, total: 1000}
	cands2, _, _, _, _ := e.fpCandidates(host2, attack2)
	c2, found2 := findCand(cands2, "path", "/shop/")
	if !found2 {
		t.Fatalf("no /shop/ candidate: %+v", cands2)
	}
	if math.Abs(c2.collision-0.40) > 0.001 {
		t.Fatalf("collision candidate: collision=%.4f want 0.40", c2.collision)
	}
	if e.fpWouldArm(c2) {
		t.Fatalf("candidate colliding with 40%% of legit must NOT arm: %+v", c2)
	}
}

// A too-thin baseline yields no would-arm verdict (collision unmeasurable).
func TestFPCandidates_InsufficientBaseline(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	e := newFPTestEngine()
	host := "new.example"
	e.fp.updateBaseline(host, &fpSnapshot{basePaths: map[string]int{"/x/": 100}, total: 100}, 1.0, now) // < fpMinBaselineTotal
	attack := &fpSnapshot{basePaths: map[string]int{"/wp-login.php": 100}, total: 100}
	cands, _, _, _, ok := e.fpCandidates(host, attack)
	if ok {
		t.Fatal("baseline of 100 should be insufficient")
	}
	c, found := findCand(cands, "path", "/wp-login.php")
	if !found {
		t.Fatalf("no candidate: %+v", cands)
	}
	if c.baselineOK || e.fpWouldArm(c) {
		t.Fatalf("insufficient baseline must not arm: %+v", c)
	}
}

// runFingerprint routes by attack state: it FOLDS a normal vhost's traffic into
// its baseline, and does NOT fold an under-attack vhost's (the baseline stays
// frozen/pre-attack). Exercises the real on/off branch, not fingerprintVhost.
func TestRunFingerprint_RoutesByAttackState(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	e := newFPTestEngine()
	e.cfg.Window = time.Minute
	e.hosts = map[string]*hostState{
		"normal.example": {buckets: []bucketSW{{paths: map[string]int{"/home/": 1000}, total: 1000}}},
		"attack.example": {buckets: []bucketSW{{paths: map[string]int{"/wp/": 1000}, total: 1000}}},
	}
	// Seed a pre-attack baseline for the attack vhost, then mark it under attack.
	e.fp.updateBaseline("attack.example", &fpSnapshot{basePaths: map[string]int{"/legit/": 1000}, total: 1000}, 1.0, now)
	_, beforeAtk := e.fp.baselineCopy("attack.example")
	e.attack.hosts["attack.example"] = &attackVhost{on: true}

	e.runFingerprint(now)

	// Normal vhost: baseline folded (its window traffic is now present).
	if _, tot := e.fp.baselineCopy("normal.example"); tot <= 0 {
		t.Fatalf("normal vhost baseline not folded: total=%.1f", tot)
	}
	// Under-attack vhost: baseline unchanged (frozen — attack traffic not folded).
	if _, tot := e.fp.baselineCopy("attack.example"); tot != beforeAtk {
		t.Fatalf("under-attack vhost baseline mutated (not frozen): %.1f -> %.1f", beforeAtk, tot)
	}
}
