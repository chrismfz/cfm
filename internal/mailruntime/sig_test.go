package mailruntime

import "testing"

// All fixtures below are VERBATIM lines captured from the live fleet
// (orion/titan/virgo/earth/mars/rigel), so the classifier is grounded in the
// real formats, not guessed.

func TestClassifyEximLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want SigKind
	}{
		{
			"spamd read timeout (the smoking gun)",
			`2026-08-15 16:51:48 1wvEkk-0000000D5zb-42By spam acl condition: error reading from spamd [127.0.0.1]:783, socket: Connection timed out`,
			SigSpamdError,
		},
		{
			"spamd cannot parse output",
			`2026-07-21 00:45:30 1wlvnn-00000000hNx-2Q80 spam acl condition: cannot parse spamd [127.0.0.1]:783 output`,
			SigSpamdError,
		},
		{
			"spamd error wrapped by crond",
			`Aug 18 02:18:02 mars crond[303111]: 2026-08-18 02:18:02 1ww6Xm-00000001Gqt-0jpJ spam acl condition: error reading from spamd [127.0.0.1]:783, socket: Connection timed out`,
			SigSpamdError,
		},
		{
			"our inbound cap rejection (external ip)",
			`2026-08-14 17:16:07 Connection from [51.89.47.4]:24244 refused: too many connections`,
			SigInboundConnRefused,
		},
		{
			"our inbound cap rejection (loopback)",
			`2026-08-15 16:50:20 Connection from [127.0.0.1]:37050 refused: too many connections`,
			SigInboundConnRefused,
		},
		{
			// A REMOTE MX refusing OUR outbound delivery — deliverability, not our
			// saturation. Must NOT be classified as an inbound cap hit.
			"remote MX 421 too many concurrent — NOT ours",
			`2026-08-16 13:41:09 1wvYIb-00000005S1o-3buz H=smtp.isdisadown.com [40.83.44.179]: SMTP error from remote mail server after initial connection: 421 Too many concurrent SMTP connections; please try again later.`,
			SigNone,
		},
		{
			// More real remote-MX 421 variants (earth/rigel/titan) — all deliverability,
			// all must stay SigNone. These pin the two-substring guard against a future
			// loosening of the reject-phrase rule.
			"remote MX 421 #4.4.5 to this listener — NOT ours",
			`2026-07-24 13:32:20 1wnDCV-000000033gn-0kpU H=cloudmx2.spxs.net [212.211.181.135]: SMTP error from remote mail server after initial connection: 421 #4.4.5 Too many connections to this listener.`,
			SigNone,
		},
		{
			"remote MX 421 #4.4.5 from your host — NOT ours",
			`2026-08-07 16:49:33 1wsKx0-00000009ez3-3TZz H=mx2.hc2362-53.eu.iphmx.com [23.90.116.161]: SMTP error from remote mail server after initial connection: 421 #4.4.5 Too many connections from your host.`,
			SigNone,
		},
		{
			"remote MX 421 hostname-prefixed concurrent — NOT ours",
			`2026-08-11 20:56:08 1wtoQL-00000009SMR-0BV9 H=mx.qfilter.nl [217.18.64.80]: SMTP error from remote mail server after initial connection: 421 mx01.spam-filter.email: Too many concurrent SMTP connections; please try again later`,
			SigNone,
		},
		{
			"ordinary delivery line",
			`2026-08-19 05:22:47 1abc-000-xy <= sender@example.com H=mail.example.com [1.2.3.4] P=esmtps`,
			SigNone,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyEximLine(tc.line); got != tc.want {
				t.Errorf("ClassifyEximLine = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestClassifySpamdLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want SigKind
	}{
		{
			"killing failed child",
			`Aug 16 03:46:48 orion spamd[1782837]: prefork: killing failed child 1806856 fd=7 at /usr/local/cpanel/3rdparty/perl/542/cpanel-lib/Mail/SpamAssassin/SpamdForkScaling.pm line 169.`,
			SigSpamdChildKilled,
		},
		{
			"killed child",
			`Aug 16 03:46:48 orion spamd[1782837]: prefork: killed child 1806856`,
			SigSpamdChildKilled,
		},
		{
			"routine child states — noise",
			`Aug 16 03:15:24 orion spamd[1782837]: prefork: child states: II`,
			SigNone,
		},
		{
			"routine scaler adjust — noise",
			`Aug 16 04:21:32 orion spamd[1782837]: prefork: adjust: 0 idle children less than 1 minimum idle children.  Increasing spamd children: 1833371 started.`,
			SigNone,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifySpamdLine(tc.line); got != tc.want {
				t.Errorf("ClassifySpamdLine = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestSigKindString(t *testing.T) {
	cases := map[SigKind]string{
		SigNone:               "none",
		SigSpamdError:         "spamd_error",
		SigInboundConnRefused: "inbound_conn_refused",
		SigSpamdChildKilled:   "spamd_child_killed",
	}
	for k, want := range cases {
		if k.String() != want {
			t.Errorf("%d.String() = %q, want %q", int(k), k.String(), want)
		}
	}
}
