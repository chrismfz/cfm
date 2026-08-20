package mailruntime

import "testing"

// All fixtures are VERBATIM fleet lines (see sig_test.go) so the counting layer
// is exercised against real Exim mainlog formats, not guessed ones.

func TestCountEximSignatures(t *testing.T) {
	lines := []string{
		// two spamd errors (one crond-wrapped)
		`2026-08-15 16:51:48 1wvEkk-0000000D5zb-42By spam acl condition: error reading from spamd [127.0.0.1]:783, socket: Connection timed out`,
		`Aug 18 02:18:02 mars crond[303111]: 2026-08-18 02:18:02 1ww6Xm-00000001Gqt-0jpJ spam acl condition: error reading from spamd [127.0.0.1]:783, socket: Connection timed out`,
		// one inbound cap rejection
		`2026-08-14 17:16:07 Connection from [51.89.47.4]:24244 refused: too many connections`,
		// a remote-MX 421 (deliverability) — must NOT count
		`2026-08-16 13:41:09 1wvYIb-00000005S1o-3buz H=smtp.isdisadown.com [40.83.44.179]: SMTP error from remote mail server after initial connection: 421 Too many concurrent SMTP connections; please try again later.`,
		// an ordinary delivery — must NOT count
		`2026-08-19 05:22:47 1abc-000-xy <= sender@example.com H=mail.example.com [1.2.3.4] P=esmtps`,
	}
	got := CountEximSignatures(lines)
	if got.SpamdError != 2 {
		t.Errorf("SpamdError = %d, want 2", got.SpamdError)
	}
	if got.InboundConnRefused != 1 {
		t.Errorf("InboundConnRefused = %d, want 1", got.InboundConnRefused)
	}
	// v1 never counts child-kills from an exim line.
	if got.SpamdChildKilled != 0 {
		t.Errorf("SpamdChildKilled = %d, want 0 (exim collector never sets it)", got.SpamdChildKilled)
	}
}

func TestCountEximSignaturesEmpty(t *testing.T) {
	if got := CountEximSignatures(nil); got != (SigCounts{}) {
		t.Errorf("empty input = %+v, want zero", got)
	}
}

func TestEximLineTime(t *testing.T) {
	if _, ok := EximLineTime(`2026-08-15 16:51:48 1wvEkk spam acl condition: ...`); !ok {
		t.Errorf("native exim line should parse a timestamp")
	}
	// crond-wrapped (leading syslog stamp, no year) does NOT anchor the window.
	if _, ok := EximLineTime(`Aug 18 02:18:02 mars crond[303111]: 2026-08-18 02:18:02 ...`); ok {
		t.Errorf("crond-wrapped line must not parse as a native leading stamp")
	}
	// too short / blank
	if _, ok := EximLineTime(`short`); ok {
		t.Errorf("short line must not parse")
	}
	if _, ok := EximLineTime(``); ok {
		t.Errorf("blank line must not parse")
	}
}

func TestEximWindowSeconds(t *testing.T) {
	var w EximWindow
	if w.Seconds() != 0 {
		t.Errorf("empty window = %d, want 0", w.Seconds())
	}
	w.Observe(`2026-08-15 16:50:20 Connection from [127.0.0.1]:37050 refused: too many connections`)
	// a single stamp → span 0
	if w.Seconds() != 0 {
		t.Errorf("single-stamp window = %d, want 0", w.Seconds())
	}
	w.Observe(`2026-08-15 16:51:48 1wvEkk-0000000D5zb-42By spam acl condition: error reading from spamd`)
	// 16:50:20 → 16:51:48 == 88s
	if w.Seconds() != 88 {
		t.Errorf("window span = %d, want 88", w.Seconds())
	}
	// an unparseable line (crond-wrapped) does not move the window.
	w.Observe(`Aug 18 02:18:02 mars crond[303111]: 2026-08-18 02:18:02 spam acl condition: error reading from spamd`)
	if w.Seconds() != 88 {
		t.Errorf("window span after unparseable line = %d, want 88 (unchanged)", w.Seconds())
	}
}

func TestEximWindowOutOfOrder(t *testing.T) {
	// Feed newest-first (as a reverse tail might, defensively): the window must
	// still bracket first→last correctly and never go negative.
	var w EximWindow
	w.Observe(`2026-08-15 16:51:48 later line`)
	w.Observe(`2026-08-15 16:50:20 earlier line`)
	if w.Seconds() != 88 {
		t.Errorf("out-of-order window = %d, want 88", w.Seconds())
	}
}
