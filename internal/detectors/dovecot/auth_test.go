package dovecot

import (
	"testing"
	"time"

	core "cfm/internal/detectors/core"
)

// TestProcessLineSyslogFramedLoginServices locks the pre-filter against the
// regression that left it inert: both sources (maillog + journalctl -o
// short-unix) emit a PID-tagged `dovecot[<pid>]:` tag, so the matcher must be
// PID-tolerant, and every dovecot login service (imap/pop3/managesieve/
// submission) shares the same failure line shape — so one anchor covers them all.
func TestProcessLineSyslogFramedLoginServices(t *testing.T) {
	real := []struct{ tag, line string }{
		{"managesieve pid", `Sep 10 17:14:04 ngm dovecot[2241633]: managesieve-login: Login aborted: Logged out (auth failed, 1 attempts in 2 secs) (auth_failed): user=<bogus@invalid.example>, method=PLAIN, rip=127.0.0.1, lip=127.0.0.1, TLS`},
		{"imap pid", `Sep 10 12:00:00 ngm dovecot[2241633]: imap-login: Login aborted: Logged out (auth failed, 1 attempts in 2 secs) (auth_failed): user=<a@b.com>, method=PLAIN, rip=5.6.7.8`},
		{"pop3 no-pid", `Sep 10 12:00:00 ngm dovecot: pop3-login: Login aborted: (auth failed): user=<x@y.gr>, rip=9.9.9.9`},
		{"submission pid", `Sep 10 12:00:00 ngm dovecot[42]: submission-login: Login aborted: (auth failed): user=<z@y.gr>, rip=8.8.8.8`},
	}
	for _, c := range real {
		a := NewAuth(Config{Mode: "file"})
		a.processLine(time.Now(), c.line)
		if len(a.pending) == 0 {
			t.Errorf("%s: expected a match (PID-tolerant, all login services), got none: %q", c.tag, c.line)
		}
	}

	// Pure-scan noise — a connection that never attempted a password. Must NOT
	// count (these are what a port scanner leaves behind on :4190/:143/etc.).
	noise := []string{
		`Sep 10 16:06:47 ngm dovecot[2174147]: managesieve-login: Login aborted: Connection closed (no auth attempts in 2 secs) (no_auth_attempts): user=<>, rip=84.54.49.6, lip=84.54.49.38`,
		`Sep 10 16:06:49 ngm dovecot[2174147]: managesieve-login: Login aborted: Too many invalid commands. (no auth attempts in 0 secs) (no_auth_attempts): user=<>, rip=84.54.49.6`,
		`Sep 10 16:56:15 ngm dovecot[2241633]: managesieve-login: Login aborted: Connection closed (disconnected before auth was ready, waited 0 secs) (auth_process_not_ready): user=<>, rip=84.54.49.6`,
	}
	for _, ln := range noise {
		a := NewAuth(Config{Mode: "file"})
		a.processLine(time.Now(), ln)
		if len(a.pending) != 0 {
			t.Errorf("pure-scan noise must not match, got %d pending: %q", len(a.pending), ln)
		}
	}
}

// TestProcessLineExtractsIPAndUser confirms a real failure produces BOTH buckets:
// per-IP keyed on rip= (the primary, unambiguous abuse signal) and per-user keyed
// on the attempted mailbox (reUser no longer dies on the `user=<addr>,` shape).
func TestProcessLineExtractsIPAndUser(t *testing.T) {
	a := NewAuth(Config{Mode: "file"})
	a.processLine(time.Now(), `Sep 10 17:14:04 ngm dovecot[2241633]: managesieve-login: Login aborted: Logged out (auth failed, 1 attempts in 2 secs) (auth_failed): user=<bogus@invalid.example>, method=PLAIN, rip=203.0.113.7, lip=127.0.0.1, TLS`)
	var haveIP, haveUser bool
	for _, p := range a.pending {
		switch {
		case p.kindKey == "AUTHFAIL|ip" && p.key == "203.0.113.7":
			haveIP = true
		case p.kindKey == "AUTHFAIL|user" && p.key == "bogus@invalid.example":
			haveUser = true
		}
	}
	if !haveIP {
		t.Errorf("expected AUTHFAIL|ip keyed on rip=203.0.113.7, pending=%v", a.pending)
	}
	if !haveUser {
		t.Errorf("expected AUTHFAIL|user keyed on the attempted mailbox, pending=%v", a.pending)
	}
}

// TestAlertScopes locks the enforcement stance: a per-IP finding carries the IP
// (the sink bans it), while a per-USER finding is HOST-scoped (ip_scope=host) so
// the sink notifies instead of banning an arbitrary source IP from a spray.
func TestAlertScopes(t *testing.T) {
	line := `Sep 10 17:14:04 ngm dovecot[2241633]: managesieve-login: Login aborted: Logged out (auth failed, 1 attempts in 2 secs) (auth_failed): user=<bogus@invalid.example>, method=PLAIN, rip=203.0.113.7, lip=127.0.0.1, TLS`

	// Per-IP alert: has the ip, is NOT host-scoped (→ bannable).
	ipOnly := NewAuth(Config{Mode: "file", AuthFailPerIP: 1, AuthFailPerUser: 0})
	ipOnly.processLine(time.Now(), line)
	ipCh := make(chan core.Alert, 4)
	ipOnly.flush(time.Now(), ipCh)
	close(ipCh)
	gotIP := false
	for a := range ipCh {
		gotIP = true
		if a.Extra[core.ExtraIPScope] == core.IPScopeHost {
			t.Errorf("per-IP alert must NOT be host-scoped (must remain bannable), extra=%v", a.Extra)
		}
		if a.Extra["ip"] != "203.0.113.7" {
			t.Errorf("per-IP alert should carry the source IP, extra=%v", a.Extra)
		}
	}
	if !gotIP {
		t.Fatal("expected a per-IP alert at threshold 1")
	}

	// Per-user alert: host-scoped (→ notify, no arbitrary ban).
	userOnly := NewAuth(Config{Mode: "file", AuthFailPerIP: 0, AuthFailPerUser: 1})
	userOnly.processLine(time.Now(), line)
	uCh := make(chan core.Alert, 4)
	userOnly.flush(time.Now(), uCh)
	close(uCh)
	gotUser := false
	for a := range uCh {
		gotUser = true
		if a.Extra[core.ExtraIPScope] != core.IPScopeHost {
			t.Errorf("per-user alert must be host-scoped (ip_scope=host), extra=%v", a.Extra)
		}
	}
	if !gotUser {
		t.Fatal("expected a per-user alert at threshold 1")
	}
}
