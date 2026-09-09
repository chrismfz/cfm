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

// runOnce writes the fixture, replays it from BOF (production tails from EOF),
// and returns every alert emitted in one RunOnce.
func runOnce(t *testing.T, cfg AuthConfig, lines []string) []core.Alert {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Mode, cfg.LogPath = "file", path
	if cfg.Window == 0 {
		cfg.Window = time.Minute
	}
	if cfg.Cooldown == 0 {
		cfg.Cooldown = time.Millisecond
	}
	a := New(cfg)
	a.SetName("ngm_auth")
	ft := core.NewFileTailer(path)
	ft.StartAtEnd = false
	a.SetSource(ft)

	out := make(chan core.Alert, 32)
	if err := a.RunOnce(context.Background(), out); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	close(out)
	var got []core.Alert
	for al := range out {
		got = append(got, al)
	}
	return got
}

// TestRunOnceEventAllowlistAndBuckets: abuse events count (FAIL + RATELIMIT into
// the same per-IP bucket), audit events are ignored (SUCCESS / CONTAINER_*),
// TOKEN_FAIL lands in the TOKEN bucket, and TOKEN_IP_REJECT is NOT counted.
func TestRunOnceEventAllowlistAndBuckets(t *testing.T) {
	alerts := runOnce(t, AuthConfig{
		SampleLimit:     10,
		AuthFailPerIP:   3,
		AuthFailPerUser: 100, // high, so only the per-IP bucket fires (simpler assert)
		AdminFailPerIP:  100,
		TokenFailPerIP:  2,
	}, []string{
		`2026-08-05T17:30:00Z event=FAIL user="bob" ip=1.2.3.4 role=user reason=bad_password`,
		`2026-08-05T17:30:01Z event=FAIL user="bob" ip=1.2.3.4 role=user reason=bad_password`,
		`2026-08-05T17:30:02Z event=FAIL user="bob" ip=1.2.3.4 role=user reason=bad_password`,
		`2026-08-05T17:30:03Z event=RATELIMIT user="bob" ip=1.2.3.4 role=user reason=too_many`,   // counts too
		`2026-08-05T17:30:04Z event=SUCCESS user="bob" ip=1.2.3.4 role=user reason=-`,            // ignored
		`2026-08-05T17:30:05Z event=CONTAINER_LOG_READ user="bob" ip=1.2.3.4 role=user reason=x`, // ignored
		`2026-08-05T17:30:06Z event=TOKEN_FAIL ip=9.9.9.9 role=token reason=bad_token`,
		`2026-08-05T17:30:07Z event=TOKEN_FAIL ip=9.9.9.9 role=token reason=bad_token`,
		`2026-08-05T17:30:08Z event=TOKEN_IP_REJECT ip=8.8.8.8 role=token reason=source_ip_not_allowed`, // ignored (F3)
	})

	byKind := map[string]core.Alert{}
	for _, al := range alerts {
		byKind[string(al.Kind)] = al
		if al.Extra["ip"] == "8.8.8.8" {
			t.Fatalf("TOKEN_IP_REJECT must not produce an alert (F3): %s ip=8.8.8.8", al.Kind)
		}
	}

	af, ok := byKind["NGM/AUTHFAIL"]
	if !ok {
		t.Fatalf("expected NGM/AUTHFAIL; got %d alerts %v", len(alerts), alerts)
	}
	if af.Extra["ip"] != "1.2.3.4" || af.Count < 4 { // 3 FAIL + 1 RATELIMIT
		t.Fatalf("NGM/AUTHFAIL ip=%q count=%d, want 1.2.3.4 / >=4", af.Extra["ip"], af.Count)
	}

	tk, ok := byKind["NGM/TOKEN"]
	if !ok {
		t.Fatalf("expected NGM/TOKEN; got %d alerts %v", len(alerts), alerts)
	}
	if tk.Extra["ip"] != "9.9.9.9" {
		t.Fatalf("NGM/TOKEN ip=%q, want 9.9.9.9", tk.Extra["ip"])
	}

	if _, ok := byKind["NGM/ADMIN"]; ok {
		t.Fatalf("unexpected NGM/ADMIN alert (no role=admin abuse in fixture)")
	}
}

// TestAdminFailuresCountTowardPerIP (F1): a spray mixing role=admin and role=user
// failures from ONE IP must not evade detection by splitting across the ADMIN|ip
// and AUTHFAIL|ip buckets — every failure counts toward the general per-IP total.
func TestAdminFailuresCountTowardPerIP(t *testing.T) {
	alerts := runOnce(t, AuthConfig{
		AuthFailPerIP:   5,   // aggregate (3 admin + 2 user) = 5 → fires
		AuthFailPerUser: 100, // don't let a user bucket fire
		AdminFailPerIP:  100, // don't let the admin bucket fire on its own (3 < 100)
		TokenFailPerIP:  100,
	}, []string{
		`2026-08-05T19:00:00Z event=FAIL user="root" ip=7.7.7.7 role=admin reason=bad_password`,
		`2026-08-05T19:00:01Z event=FAIL user="root" ip=7.7.7.7 role=admin reason=bad_password`,
		`2026-08-05T19:00:02Z event=FAIL user="root" ip=7.7.7.7 role=admin reason=bad_password`,
		`2026-08-05T19:00:03Z event=FAIL user="carol" ip=7.7.7.7 role=user reason=bad_password`,
		`2026-08-05T19:00:04Z event=FAIL user="dave" ip=7.7.7.7 role=user reason=bad_password`,
	})

	var af *core.Alert
	for i := range alerts {
		if alerts[i].Kind == "NGM/AUTHFAIL" && alerts[i].Extra["ip"] == "7.7.7.7" {
			af = &alerts[i]
		}
		if alerts[i].Kind == "NGM/ADMIN" {
			t.Fatalf("NGM/ADMIN should not fire (3 admin fails < AdminFailPerIP=100)")
		}
	}
	if af == nil {
		t.Fatalf("expected NGM/AUTHFAIL for 7.7.7.7 (admin+user failures must aggregate); got %v", alerts)
	}
	if af.Count < 5 {
		t.Fatalf("NGM/AUTHFAIL count=%d, want >=5 (3 admin + 2 user)", af.Count)
	}
}

// TestUserBucketDeclaresHostScope (F2): a per-account alert (one username, many
// source IPs) must declare ip_scope=host so the sink treats it as a notify, not
// a ban of some arbitrary sample IP.
func TestUserBucketDeclaresHostScope(t *testing.T) {
	alerts := runOnce(t, AuthConfig{
		AuthFailPerIP:   100, // no single IP reaches this
		AuthFailPerUser: 3,   // the account does
		AdminFailPerIP:  100,
		TokenFailPerIP:  100,
	}, []string{
		`2026-08-05T20:00:00Z event=FAIL user="admin" ip=1.1.1.1 role=user reason=bad_password`,
		`2026-08-05T20:00:01Z event=FAIL user="admin" ip=2.2.2.2 role=user reason=bad_password`,
		`2026-08-05T20:00:02Z event=FAIL user="admin" ip=3.3.3.3 role=user reason=bad_password`,
	})

	var found bool
	for _, al := range alerts {
		if al.Kind == "NGM/AUTHFAIL" && al.Extra["user"] == "admin" {
			found = true
			if al.Extra[core.ExtraIPScope] != core.IPScopeHost {
				t.Fatalf("per-user alert must set ip_scope=host, got %q", al.Extra[core.ExtraIPScope])
			}
			if al.Extra["ip"] != "" {
				t.Fatalf("per-user alert must not carry a single ip, got %q", al.Extra["ip"])
			}
		}
	}
	if !found {
		t.Fatalf("expected a per-user NGM/AUTHFAIL for admin; got %v", alerts)
	}
}

// TestMailboxCredentialFailuresCount (F1/F2): DAV / password-reset / recovery
// verification failures are genuine credential-brute events NGM writes to
// auth.log and MUST count — while the audit DAV_*/PWRESET_* verbs must not.
func TestMailboxCredentialFailuresCount(t *testing.T) {
	alerts := runOnce(t, AuthConfig{
		AuthFailPerIP:   3,
		AuthFailPerUser: 100,
		AdminFailPerIP:  100,
		TokenFailPerIP:  100,
	}, []string{
		`2026-08-05T21:00:00Z event=DAV_FAIL user="bob@example.com" ip=4.4.4.4 role=mailbox reason=bad_password`,
		`2026-08-05T21:00:01Z event=PWRESET_FAILURE user="bob@example.com" ip=4.4.4.4 role=mailbox reason=bad_token`,
		`2026-08-05T21:00:02Z event=RECOVERY_VERIFY_FAILURE user="bob@example.com" ip=4.4.4.4 role=mailbox reason=bad_code`,
		// audit DAV/PWRESET verbs that must NOT count:
		`2026-08-05T21:00:03Z event=DAV_HOST user="bob@example.com" ip=4.4.4.4 role=mailbox reason=example.com`,
		`2026-08-05T21:00:04Z event=PWRESET_SENT user="bob@example.com" ip=4.4.4.4 role=mailbox reason=sent`,
		`2026-08-05T21:00:05Z event=DAV_IMPORT_FAIL user="bob@example.com" ip=4.4.4.4 role=mailbox reason=parse_error`,
	})
	var af *core.Alert
	for i := range alerts {
		if alerts[i].Kind == "NGM/AUTHFAIL" && alerts[i].Extra["ip"] == "4.4.4.4" {
			af = &alerts[i]
		}
	}
	if af == nil {
		t.Fatalf("expected NGM/AUTHFAIL for 4.4.4.4 (DAV_FAIL + PWRESET_FAILURE + RECOVERY_VERIFY_FAILURE); got %v", alerts)
	}
	if af.Count != 3 { // exactly the 3 credential failures; the 3 audit lines ignored
		t.Fatalf("NGM/AUTHFAIL count=%d, want 3 (audit DAV_HOST/PWRESET_SENT/DAV_IMPORT_FAIL must not count)", af.Count)
	}
}

// TestPrivilegedBucketFires (P3-F2/F6): admin AND reseller failures trip the
// stricter NGM/ADMIN bucket, earlier than the generic per-IP threshold.
func TestPrivilegedBucketFires(t *testing.T) {
	for _, role := range []string{"admin", "reseller"} {
		t.Run(role, func(t *testing.T) {
			alerts := runOnce(t, AuthConfig{
				AuthFailPerIP:   100, // generic bucket must NOT be what fires
				AuthFailPerUser: 100,
				AdminFailPerIP:  3,
				TokenFailPerIP:  100,
			}, []string{
				`2026-08-05T22:00:00Z event=FAIL user="x" ip=6.6.6.6 role=` + role + ` reason=bad_password`,
				`2026-08-05T22:00:01Z event=FAIL user="x" ip=6.6.6.6 role=` + role + ` reason=bad_password`,
				`2026-08-05T22:00:02Z event=FAIL user="x" ip=6.6.6.6 role=` + role + ` reason=bad_password`,
			})
			var admin *core.Alert
			for i := range alerts {
				if alerts[i].Kind == "NGM/ADMIN" {
					admin = &alerts[i]
				}
			}
			if admin == nil {
				t.Fatalf("role=%s: expected NGM/ADMIN to fire at AdminFailPerIP=3; got %v", role, alerts)
			}
			if admin.Extra["ip"] != "6.6.6.6" || admin.Count < 3 {
				t.Fatalf("role=%s: NGM/ADMIN ip=%q count=%d, want 6.6.6.6 / >=3", role, admin.Extra["ip"], admin.Count)
			}
		})
	}
}

// TestAuditOnlyProducesNothing confirms a log of purely audit/success events (and
// a TOKEN_IP_REJECT) never fires (a new audit verb must not become a false ban).
func TestAuditOnlyProducesNothing(t *testing.T) {
	alerts := runOnce(t, AuthConfig{
		AuthFailPerIP: 1, AuthFailPerUser: 1, AdminFailPerIP: 1, TokenFailPerIP: 1,
	}, []string{
		`2026-08-05T18:00:00Z event=SUCCESS user="alice" ip=5.5.5.5 role=admin reason=-`,
		`2026-08-05T18:00:01Z event=LOGOUT user="alice" ip=5.5.5.5 role=admin reason=webmail`,
		`2026-08-05T18:00:02Z event=MFA_SUCCESS user="alice" ip=5.5.5.5 role=admin reason=-`,
		`2026-08-05T18:00:03Z event=DAV_HOST user="alice" ip=5.5.5.5 role=admin reason=example.com`,
		`2026-08-05T18:00:04Z event=TOKEN_IP_REJECT ip=5.5.5.5 role=token reason=source_ip_not_allowed`,
	})
	if len(alerts) != 0 {
		t.Fatalf("expected no alerts from audit-only log, got %v", alerts)
	}
}
