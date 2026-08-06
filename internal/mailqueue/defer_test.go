package mailqueue

import "testing"

// Real exim mainlog lines from a live server (titan) — the exact formats the
// normalizer must collapse.
var sampleMainlog = []string{
	`2026-08-06 15:22:41 1wrCbT-x == info@greece-carrentals.com R=dkim_lookuphost T=dkim_remote_smtp defer (-54): retry time not reached for any host for 'greece-carrentals.com'`,
	`2026-08-06 15:22:41 1wrqBa-x == afroditiletsou1959@gmail.com routing defer (-52): retry time not reached`,
	`2026-08-06 15:22:41 1wqXY7-x == support@biziip.shop R=dkim_lookuphost T=dkim_remote_smtp defer (-54): retry time not reached for any host for 'biziip.shop'`,
	`2026-08-06 15:22:42 1wrXIG-x == info@libre.gr R=lookuphost T=remote_smtp defer (-54): retry time not reached for any host for 'libre.gr'`,
	`2026-08-06 15:22:42 1wquUf-x == support@buenamano.ph R=dkim_lookuphost T=dkim_remote_smtp defer (-54): retry time not reached for any host for 'buenamano.ph'`,
	`2026-08-06 15:22:42 1wrSQ0-x == no-reply@boenrnedical.com R=dkim_lookuphost T=dkim_remote_smtp defer (111): Connection refused`,
	`2026-08-03 10:30:32 1wqmhq-x == support@x.sbs R=dkim_lookuphost T=dkim_remote_smtp defer (101): Network is unreachable`,
	`2026-08-06 15:24:02 1wrx8k-x ** childsite_ef78fdd+babanisprint@gmail.com R=dkim_lookuphost T=dkim_remote_smtp H=gmail-smtp-in.l.google.com [66.102.1.26] X=TLS1.3:TLS_AES_256_GCM_SHA384:256 CV=yes : SMTP error from remote mail server after RCPT TO:<childsite_ef78fdd+babanisprint@gmail.com>: 550-5.1.1 The email account that you tried to reach does not exist. Please try\n550-5.1.1 double-checking the recipient's email address for typos or\n550 5.1.1  https://support.google.com/mail/?p=NoSuchUser ffacd0b85a97d-47ff7ba699dsi3837756f8f.471 - gsmtp`,
	`2026-08-06 15:24:04 1wrx8m-x ** othersite+foo@gmail.com R=dkim_lookuphost T=dkim_remote_smtp H=gmail-smtp-in.l.google.com [66.102.1.26] X=TLS1.3:TLS_AES_256_GCM_SHA384:256 CV=yes : SMTP error from remote mail server after RCPT TO:<othersite+foo@gmail.com>: 550-5.1.1 The email account that you tried to reach does not exist. Please try\n550-5.1.1 double-checking the recipient's email address for typos or\n550 5.1.1  https://support.google.com/mail/?p=NoSuchUser ffacd0b85a97d-47ff79b49cesi3818750f8f.65 - gsmtp`,
	`2026-08-06 15:00:00 1wxx-x noise line without a marker`,
}

func TestParseEximDeferReasons(t *testing.T) {
	got := ParseEximDeferReasons(sampleMainlog, 10)

	byReason := map[string]DeferReason{}
	for _, r := range got {
		byReason[r.Reason] = r
	}

	// All "retry time not reached …" variants (with/without host+domain, and the
	// routing form) collapse into ONE deferred reason.
	retry, ok := byReason["retry time not reached"]
	if !ok || retry.Category != "deferred" {
		t.Fatalf("retry reason missing/miscategorized: %+v", got)
	}
	if retry.Count != 5 { // 4 host-form + 1 routing-form
		t.Fatalf("retry count = %d, want 5", retry.Count)
	}

	// Distinct transient causes stay separate.
	if byReason["Connection refused"].Count != 1 || byReason["Network is unreachable"].Count != 1 {
		t.Fatalf("connection/network reasons wrong: %+v", got)
	}

	// The two gmail 550 bounces (different recipients) collapse to ONE failed
	// reason (addresses stripped, tail truncated).
	var failed *DeferReason
	for i := range got {
		if got[i].Category == "failed" {
			failed = &got[i]
		}
	}
	if failed == nil || failed.Count != 2 {
		t.Fatalf("expected one failed reason with count 2, got %+v", got)
	}
	if !contains(failed.Reason, "does not exist") {
		t.Fatalf("failed reason should mention the SMTP cause: %q", failed.Reason)
	}

	// The marker-less noise line is ignored.
	for _, r := range got {
		if contains(r.Reason, "noise line") {
			t.Fatalf("noise line should not produce a reason")
		}
	}
}

// Two SHORT gmail-style bounces (under maxReasonLen) that differ only in a
// trailing per-session id + provider tag must still collapse to one reason —
// they don't rely on truncation, they rely on the session-tail strip.
func TestParseEximDeferReasons_ShortBounceCollapse(t *testing.T) {
	lines := []string{
		`2026-08-06 15:24:02 1a-x ** a@gmail.com R=r T=t H=h : mailbox unavailable ffacd0b85a97d-47ff7ba699dsi - gsmtp`,
		`2026-08-06 15:24:04 1b-x ** b@gmail.com R=r T=t H=h : mailbox unavailable 771b2c3d4e5f6a-33aa11bb22cc - gsmtp`,
	}
	got := ParseEximDeferReasons(lines, 10)
	if len(got) != 1 {
		t.Fatalf("expected 1 collapsed failed reason, got %d: %+v", len(got), got)
	}
	if got[0].Count != 2 || got[0].Category != "failed" {
		t.Fatalf("collapse wrong: %+v", got[0])
	}
}

func TestNormalizeDeferReason(t *testing.T) {
	cases := map[string]string{
		"retry time not reached for any host for 'example.com'": "retry time not reached",
		"retry time not reached":                                "retry time not reached",
		"Connection refused":                                    "Connection refused",
		"Network is unreachable":                                "Network is unreachable",
		// session-id tail (has internal '-') IS stripped:
		"mailbox full deadbeef12-99aa - gsmtp": "mailbox full",
		// a normal reason ending "<word> - <word>" (no id-shaped token) is NOT eaten:
		"unexpected end of data - retry": "unexpected end of data - retry",
	}
	for in, want := range cases {
		if got := normalizeDeferReason(in); got != want {
			t.Errorf("normalizeDeferReason(%q) = %q, want %q", in, got, want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
