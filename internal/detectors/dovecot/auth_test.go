package dovecot

import (
	"testing"
	"time"
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

// TestProcessLineExtractsIP confirms a real failure produces the per-IP bucket
// keyed on the rip= field — the primary, unambiguous abuse signal (an IP doing
// many auth failures). This is what the PID-anchor fix revives for managesieve.
//
// NOTE: the per-USER bucket (AuthFailPerUser) is a SEPARATE, still-broken matter
// — `reUser` ends with `>\b`, and a real line is `user=<addr>,`, where there is
// no word boundary between `>` and `,`, so it never fires. Fixing that safely
// needs a host-scope pass (a single-mailbox spray from many IPs must notify, not
// ban an arbitrary sample IP), so it is deliberately a follow-up, not this PR.
func TestProcessLineExtractsIP(t *testing.T) {
	a := NewAuth(Config{Mode: "file"})
	a.processLine(time.Now(), `Sep 10 17:14:04 ngm dovecot[2241633]: managesieve-login: Login aborted: Logged out (auth failed, 1 attempts in 2 secs) (auth_failed): user=<bogus@invalid.example>, method=PLAIN, rip=203.0.113.7, lip=127.0.0.1, TLS`)
	var haveIP bool
	for _, p := range a.pending {
		if p.kindKey == "AUTHFAIL|ip" && p.key == "203.0.113.7" {
			haveIP = true
		}
	}
	if !haveIP {
		t.Errorf("expected AUTHFAIL|ip keyed on rip=203.0.113.7, pending=%v", a.pending)
	}
}
