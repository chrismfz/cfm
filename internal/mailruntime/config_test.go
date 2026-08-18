package mailruntime

import "testing"

func TestParseEximMaxima(t *testing.T) {
	cfg := `
# Exim main configuration (excerpt)
smtp_accept_max = 150            # busy shared box
smtp_accept_max_per_host = 20
acl_smtp_rcpt = acl_check_rcpt
`
	m := ParseEximMaxima(cfg)
	if !m.SMTPAcceptMaxFound || m.SMTPAcceptMax != 150 {
		t.Fatalf("smtp_accept_max = (%d, found=%v), want (150, true)", m.SMTPAcceptMax, m.SMTPAcceptMaxFound)
	}
	if m.Unlimited {
		t.Error("150 must not be flagged Unlimited")
	}
	if !m.PerHostFound || m.PerHost != 20 {
		t.Errorf("per_host = (%d, found=%v), want (20, true)", m.PerHost, m.PerHostFound)
	}
}

func TestParseEximMaximaUnlimitedAndAbsent(t *testing.T) {
	m := ParseEximMaxima("smtp_accept_max = 0\n")
	if !m.SMTPAcceptMaxFound || !m.Unlimited {
		t.Errorf("smtp_accept_max=0 must be found+Unlimited, got %+v", m)
	}

	none := ParseEximMaxima("acl_smtp_rcpt = acl_check_rcpt\n")
	if none.SMTPAcceptMaxFound || none.PerHostFound {
		t.Errorf("absent options must not be found, got %+v", none)
	}
}

func TestParseEximMaximaIgnoresCommentsAndExpansions(t *testing.T) {
	// A commented-out line must be ignored; a per-host string expansion has no
	// plain integer, so PerHostFound stays false (unknown, not a bogus value).
	cfg := `# smtp_accept_max = 999
smtp_accept_max = 100
smtp_accept_max_per_host = ${if eq{$acl_c0}{1}{5}{0}}
`
	m := ParseEximMaxima(cfg)
	if m.SMTPAcceptMax != 100 {
		t.Errorf("commented line leaked or wrong value: %+v", m)
	}
	if m.PerHostFound {
		t.Errorf("string-expansion per_host must be unknown, got %d", m.PerHost)
	}
}

func TestParseEximMaximaLastAssignmentWins(t *testing.T) {
	m := ParseEximMaxima("smtp_accept_max = 20\nsmtp_accept_max = 200\n")
	if m.SMTPAcceptMax != 200 {
		t.Errorf("last assignment should win, got %d", m.SMTPAcceptMax)
	}
}

func TestParseSpamdMaxChildren(t *testing.T) {
	tests := []struct {
		name    string
		cmdline string
		want    int
		found   bool
	}{
		{"long equals", "/usr/local/cpanel/3rdparty/bin/spamd --max-children=10 --daemonize", 10, true},
		{"long space", "spamd --max-children 8 -x", 8, true},
		{"short space", "spamd -m 12", 12, true},
		{"short glued", "spamd -m12", 12, true},
		{"absent", "spamd --daemonize --pidfile=/var/run/spamd.pid", 0, false},
		{"not confused by --max-children in another token", "spamd --max-children=3", 3, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, found := ParseSpamdMaxChildren(tc.cmdline)
			if found != tc.found || n != tc.want {
				t.Fatalf("ParseSpamdMaxChildren(%q) = (%d,%v), want (%d,%v)", tc.cmdline, n, found, tc.want, tc.found)
			}
		})
	}
}
