package ngmauth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	core "cfm/internal/detectors/core"
)

func TestKVLineQuoteAware(t *testing.T) {
	// Leading RFC3339 token has no '=' and must be skipped; a quoted value with
	// spaces (reason=) must survive intact.
	f := kvLine(`2026-08-05T17:30:00Z event=FAIL user="bob smith" ip=1.2.3.4 role=admin reason="bad password"`)
	for k, want := range map[string]string{
		"event": "FAIL", "user": "bob smith", "ip": "1.2.3.4", "role": "admin", "reason": "bad password",
	} {
		if f[k] != want {
			t.Fatalf("kvLine[%q] = %q, want %q (full: %#v)", k, f[k], want, f)
		}
	}
	if _, ok := f["2026-08-05T17:30:00Z"]; ok {
		t.Fatalf("leading timestamp token should not become a key: %#v", f)
	}
}

// TestRunOnceEventAllowlistAndBuckets drives a real file through the detector and
// asserts: abuse events count (FAIL + RATELIMIT into the same per-IP bucket),
// audit events are ignored (SUCCESS / CONTAINER_*), and token events land in the
// TOKEN bucket keyed by IP.
func TestRunOnceEventAllowlistAndBuckets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	lines := []string{
		`2026-08-05T17:30:00Z event=FAIL user="bob" ip=1.2.3.4 role=user reason=bad_password`,
		`2026-08-05T17:30:01Z event=FAIL user="bob" ip=1.2.3.4 role=user reason=bad_password`,
		`2026-08-05T17:30:02Z event=FAIL user="bob" ip=1.2.3.4 role=user reason=bad_password`,
		`2026-08-05T17:30:03Z event=RATELIMIT user="bob" ip=1.2.3.4 role=user reason=too_many`,   // counts too
		`2026-08-05T17:30:04Z event=SUCCESS user="bob" ip=1.2.3.4 role=user reason=-`,            // ignored
		`2026-08-05T17:30:05Z event=CONTAINER_LOG_READ user="bob" ip=1.2.3.4 role=user reason=x`, // ignored
		`2026-08-05T17:30:06Z event=TOKEN_FAIL ip=9.9.9.9 role=token reason=bad_token`,
		`2026-08-05T17:30:07Z event=TOKEN_IP_REJECT ip=9.9.9.9 role=token reason=source_ip_not_allowed`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	a := New(AuthConfig{
		Mode: "file", LogPath: path,
		Every: time.Second, Window: time.Minute, Cooldown: time.Millisecond,
		SampleLimit:     10,
		AuthFailPerIP:   3,
		AuthFailPerUser: 100, // high, so only the per-IP bucket fires (simpler assert)
		AdminFailPerIP:  100,
		TokenFailPerIP:  2,
		// enrichment OFF (both) → enrichDisplay is a no-op → no DNS in tests
		UseEnrich: false, UsePTR: false,
	})
	a.SetName("ngm_auth")
	ft := core.NewFileTailer(path)
	ft.StartAtEnd = false // replay the file we just wrote (production tails from EOF)
	a.SetSource(ft)

	out := make(chan core.Alert, 16)
	if err := a.RunOnce(context.Background(), out); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	close(out)

	byKind := map[string]core.Alert{}
	var kinds []string
	for al := range out {
		byKind[string(al.Kind)] = al
		kinds = append(kinds, string(al.Kind))
	}

	af, ok := byKind["NGM/AUTHFAIL"]
	if !ok {
		t.Fatalf("expected NGM/AUTHFAIL; got kinds %v", kinds)
	}
	if af.Extra["ip"] != "1.2.3.4" {
		t.Fatalf("NGM/AUTHFAIL ip = %q, want 1.2.3.4", af.Extra["ip"])
	}
	if af.Count < 4 { // 3 FAIL + 1 RATELIMIT
		t.Fatalf("NGM/AUTHFAIL count = %d, want >= 4 (FAIL+RATELIMIT)", af.Count)
	}

	tk, ok := byKind["NGM/TOKEN"]
	if !ok {
		t.Fatalf("expected NGM/TOKEN; got kinds %v", kinds)
	}
	if tk.Extra["ip"] != "9.9.9.9" {
		t.Fatalf("NGM/TOKEN ip = %q, want 9.9.9.9", tk.Extra["ip"])
	}

	if _, ok := byKind["NGM/ADMIN"]; ok {
		t.Fatalf("unexpected NGM/ADMIN alert (no role=admin abuse in fixture)")
	}
}

// TestAuditOnlyProducesNothing confirms a log of purely audit/success events
// never fires (a new audit verb must not become a false ban).
func TestAuditOnlyProducesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	lines := []string{
		`2026-08-05T18:00:00Z event=SUCCESS user="alice" ip=5.5.5.5 role=admin reason=-`,
		`2026-08-05T18:00:01Z event=LOGOUT user="alice" ip=5.5.5.5 role=admin reason=webmail`,
		`2026-08-05T18:00:02Z event=MFA_SUCCESS user="alice" ip=5.5.5.5 role=admin reason=-`,
		`2026-08-05T18:00:03Z event=DAV_HOST user="alice" ip=5.5.5.5 role=admin reason=example.com`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New(AuthConfig{
		Mode: "file", LogPath: path, Window: time.Minute, Cooldown: time.Millisecond,
		AuthFailPerIP: 1, AuthFailPerUser: 1, AdminFailPerIP: 1, TokenFailPerIP: 1,
	})
	a.SetName("ngm_auth")
	ft := core.NewFileTailer(path)
	ft.StartAtEnd = false
	a.SetSource(ft)

	out := make(chan core.Alert, 8)
	if err := a.RunOnce(context.Background(), out); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	select {
	case al := <-out:
		t.Fatalf("expected no alert from audit-only log, got %s key=%q", al.Kind, al.Key)
	default:
	}
}
