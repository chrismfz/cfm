package dovecot

import (
	"strings"
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

// The Imunify RBL lock as dovecot logs it on earth (2026-11-17): a login refused
// before any password check. It feeds only the user_disabled bucket, never the
// password-failure ones, and its alert carries a capped ban and no mail.
const userDisabledLine = `Nov 17 17:15:05 earth dovecot[357175]: imap-login: Login aborted: Connection closed (user disabled, 1 attempts in 2 secs) (user_disabled): user=<info@romylos.gr>, method=PLAIN, rip=103.199.18.15, lip=84.54.49.203, TLS, session=<x>`

func TestUserDisabledBucket(t *testing.T) {
	a := NewAuth(Config{Mode: "file", AuthFailPerIP: 1, AuthFailPerUser: 1, UserDisabledPerIP: 2})
	now := time.Now()
	a.processLine(now, userDisabledLine)
	if len(a.pending) != 1 {
		t.Fatalf("want only the user_disabled bucket, got %v", a.pending)
	}
	for _, p := range a.pending {
		if p.kindKey != kindDisabledIP || p.key != "103.199.18.15" {
			t.Fatalf("pending %+v, want %s:103.199.18.15", p, kindDisabledIP)
		}
	}
	ch := make(chan core.Alert, 4)
	a.flush(now, ch)
	if len(ch) != 0 {
		t.Fatalf("one line must stay under USER_DISABLED_IP=2, got %d alert(s)", len(ch))
	}

	// The same address an hour later (Imunify's locks repeat over hours): the
	// 24h window still holds the first line.
	later := now.Add(time.Hour)
	a.processLine(later, userDisabledLine)
	a.flush(later, ch)
	close(ch)
	var got []core.Alert
	for al := range ch {
		got = append(got, al)
	}
	if len(got) != 1 {
		t.Fatalf("want one alert at the second line, got %d", len(got))
	}
	al := got[0]
	if al.Kind != "DOVECOT/USER_DISABLED" || al.Count != 2 {
		t.Errorf("alert kind=%s count=%d", al.Kind, al.Count)
	}
	if al.Extra["ip"] != "103.199.18.15" {
		t.Errorf("extra ip=%q", al.Extra["ip"])
	}
	if al.Extra[core.ExtraMaxBlockTTL] != "24h0m0s" {
		t.Errorf("max_block_ttl=%q, want the 24h default", al.Extra[core.ExtraMaxBlockTTL])
	}
	if al.Extra[core.ExtraNotify] != core.NotifyNo {
		t.Errorf("notify=%q, want no by default", al.Extra[core.ExtraNotify])
	}
	if al.Extra["window"] != "24h0m0s" {
		t.Errorf("window=%q, want the user_disabled window", al.Extra["window"])
	}
}

func TestUserDisabledVariantsAndOff(t *testing.T) {
	lines := []string{
		userDisabledLine,
		`Nov 17 17:15:05 earth dovecot[1]: pop3-login: Login aborted: Connection closed (user disabled, 1 attempts in 2 secs) (user_disabled): user=<a@b.gr>, rip=203.0.113.9`,
		// an older dovecot without the trailing code
		`Nov 17 17:15:05 earth dovecot: imap-login: Aborted login (user disabled): user=<a@b.gr>, rip=203.0.113.9`,
	}
	for _, ln := range lines {
		a := NewAuth(Config{Mode: "file", UserDisabledPerIP: 1})
		a.processLine(time.Now(), ln)
		if len(a.pending) != 1 {
			t.Errorf("want one user_disabled bucket, got %v: %q", a.pending, ln)
			continue
		}
		for _, p := range a.pending {
			if p.kindKey != kindDisabledIP {
				t.Errorf("bucket %s, want %s: %q", p.kindKey, kindDisabledIP, ln)
			}
		}
	}
	// USER_DISABLED_IP = 0 turns the bucket off, and the line still never
	// counts as a password failure.
	a := NewAuth(Config{Mode: "file", AuthFailPerIP: 1, AuthFailPerUser: 1})
	a.processLine(time.Now(), userDisabledLine)
	if len(a.pending) != 0 {
		t.Errorf("bucket off: want nothing pending, got %v", a.pending)
	}
	// A password failure is untouched by the new bucket.
	b := NewAuth(Config{Mode: "file", UserDisabledPerIP: 1})
	b.processLine(time.Now(), `Sep 10 12:00:00 ngm dovecot[1]: imap-login: Login aborted: Logged out (auth failed, 1 attempts in 2 secs) (auth_failed): user=<a@b.com>, method=PLAIN, rip=5.6.7.8`)
	for _, p := range b.pending {
		if p.kindKey == kindDisabledIP {
			t.Errorf("auth_failed counted as user_disabled: %v", b.pending)
		}
	}

	// UserDisabledNotify keeps the mail.
	c := NewAuth(Config{Mode: "file", UserDisabledPerIP: 1, UserDisabledNotify: true})
	c.processLine(time.Now(), userDisabledLine)
	ch := make(chan core.Alert, 2)
	c.flush(time.Now(), ch)
	close(ch)
	for al := range ch {
		if _, ok := al.Extra[core.ExtraNotify]; ok {
			t.Errorf("USER_DISABLED_NOTIFY=1 must not suppress the mail: %v", al.Extra)
		}
	}
}

// The username is client-chosen text after `user=<`: it must not change the
// verdict or name the address. A brute force with "(user_disabled)" in the
// username stays a password failure (permanent ban, not the capped one), a
// "rip=" in it does not frame another address, and a noise phrase in it does
// not silence the failure.
func TestUsernameCannotSteerTheVerdict(t *testing.T) {
	cases := []struct {
		name, line, wantKind, wantIP string
	}{
		{"user_disabled in the username",
			`Nov 17 12:00:00 earth dovecot[1]: imap-login: Login aborted: Logged out (auth failed, 1 attempts in 2 secs) (auth_failed): user=<x(user_disabled)@victim.gr>, method=PLAIN, rip=198.51.100.7, lip=84.54.49.203`,
			"AUTHFAIL|ip", "198.51.100.7"},
		{"rip= in the username",
			`Nov 17 12:00:00 earth dovecot[1]: imap-login: Login aborted: Logged out (auth failed, 1 attempts in 2 secs) (auth_failed): user=<rip=203.0.113.50,a@b.gr>, method=PLAIN, rip=198.51.100.7, lip=84.54.49.203`,
			"AUTHFAIL|ip", "198.51.100.7"},
		{"rip= in the username of a user_disabled line",
			`Nov 17 12:00:00 earth dovecot[1]: imap-login: Login aborted: Connection closed (user disabled, 1 attempts in 2 secs) (user_disabled): user=<rip=203.0.113.50,a@b.gr>, method=PLAIN, rip=198.51.100.7, lip=84.54.49.203`,
			kindDisabledIP, "198.51.100.7"},
		{"noise phrase in the username",
			`Nov 17 12:00:00 earth dovecot[1]: imap-login: Login aborted: Logged out (auth failed, 1 attempts in 2 secs) (auth_failed): user=<no auth attempts in 0 secs>, method=PLAIN, rip=198.51.100.7`,
			"AUTHFAIL|ip", "198.51.100.7"},
	}
	for _, c := range cases {
		a := NewAuth(Config{Mode: "file", AuthFailPerIP: 1, AuthFailPerUser: 1, UserDisabledPerIP: 1})
		a.processLine(time.Now(), c.line)
		var ipKinds []string
		for _, p := range a.pending {
			if strings.HasSuffix(p.kindKey, "|ip") {
				ipKinds = append(ipKinds, p.kindKey+"="+p.key)
			}
		}
		if len(ipKinds) != 1 || ipKinds[0] != c.wantKind+"="+c.wantIP {
			t.Errorf("%s: ip buckets %v, want [%s=%s]", c.name, ipKinds, c.wantKind, c.wantIP)
		}
	}
}
