package webdetector

import (
	"fmt"
	"testing"
	"time"
)

func TestIsWellKnownChallengeExempt(t *testing.T) {
	cases := map[string]bool{
		"/.well-known/acme-challenge/0ebjUVe":  true,
		"/.WELL-KNOWN/acme-challenge/0ebjUVe":  true, // case-insensitive
		"/.well-known/pki-validation/abc.txt":  true,
		"/.well-known/security.txt":            true,
		"/.well-known/acme-challenge/x?foo=..": true, // query stripped before check
		"/index.php":                           false,
		"/well-known/x":                        false, // missing the leading dot
		"/app/.well-known/x":                   false, // not at the start
		"/.well-known/../../etc/passwd":        false, // literal traversal escapes the exemption
		"/.well-known/%2e%2e/wp-login.php":     false, // encoded traversal (raw URI) — must NOT exempt
		"/.well-known/%2E%2E/x":                false, // encoded traversal, upper hex
		"/.well-known/acme-challenge/%2f":      false, // any percent-encoding in the path → score it
		"":                                     false,
	}
	for in, want := range cases {
		if got := isWellKnownChallengeExempt(in); got != want {
			t.Errorf("isWellKnownChallengeExempt(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestChallenge_WellKnownExemptFromScoring reproduces the production incident
// (CHALLENGE_UNIQHOSTS_IP on a Let's Encrypt validator hitting /.well-known/
// across many domains) and asserts the fix: a /.well-known/-only IP never
// enters the challenge engine's per-host/per-IP accounting, while an identical
// pattern on normal paths still trips the scanner heuristic.
func TestChallenge_WellKnownExemptFromScoring(t *testing.T) {
	e := NewEngine(Config{
		Every:                       1 * time.Second,
		Window:                      2 * time.Minute,
		ChallengeIPUniqHostsEnabled: true,
		ChallengeIPUniqHostsMin:     5,
	})

	now := float64(time.Now().Unix())

	// ACME validator (AWS): one IP validates 12 domains → 12 distinct hosts,
	// every request under /.well-known/acme-challenge/, status 200.
	for i := 0; i < 12; i++ {
		e.ingest(LogRec{
			TS:     now + float64(i),
			IP:     "3.129.8.191",
			Host:   fmt.Sprintf("site%d.gr", i),
			Method: "get",
			URI:    fmt.Sprintf("/.well-known/acme-challenge/token-%d", i),
			Status: 200,
			UA:     "Mozilla/5.0 (compatible; Let's Encrypt validation server; +https://www.letsencrypt.org)",
		}, "raw")
	}

	// Control scanner: same fan-out (12 hosts) but on a normal path.
	for i := 0; i < 12; i++ {
		e.ingest(LogRec{
			TS:     now + float64(i),
			IP:     "9.9.9.9",
			Host:   fmt.Sprintf("site%d.gr", i),
			Method: "get",
			URI:    "/wp-login.php",
			Status: 200,
			UA:     "scanner",
		}, "raw")
	}

	rows := e.IPShort(0)
	var acmeSeen bool
	var acmeVhosts, scannerVhosts int
	scannerSeen := false
	for _, r := range rows {
		switch r.IP {
		case "3.129.8.191":
			acmeSeen = true
			acmeVhosts = r.Vhosts
		case "9.9.9.9":
			scannerSeen = true
			scannerVhosts = r.Vhosts
		}
	}

	// The ACME validator must be fully excluded — no vhost accrual (ideally the
	// IP doesn't appear at all, since /.well-known/ is skipped before any
	// per-host accounting).
	if acmeSeen && acmeVhosts > 0 {
		t.Fatalf("ACME validator on /.well-known/ accrued vhosts=%d — exemption failed (would trip CHALLENGE_UNIQHOSTS_IP)", acmeVhosts)
	}

	// The control scanner, doing the same fan-out on a normal path, must still
	// register its vhost diversity (proves the exemption is path-scoped, not a
	// blanket disable of the heuristic).
	if !scannerSeen {
		t.Fatalf("control scanner IP not found in IPShort rows")
	}
	if scannerVhosts < 5 {
		t.Fatalf("control scanner should accrue many vhosts (>=5), got %d", scannerVhosts)
	}
}
