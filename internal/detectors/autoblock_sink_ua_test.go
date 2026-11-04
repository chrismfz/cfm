package detectors

import "testing"

func TestExtractUserAgentWebdetTSV(t *testing.T) {
	base := "1000.5\t1.2.3.4\th.gr\tPOST\t/wp-login.php\tHTTP/1.1\t200\t0\t0.1\t0.1\t-\tMozilla/5.0 X"
	for _, ln := range []string{
		base,
		base + "\tcfm_apache",
		base + "\tcfm_apache\t0",
		base + "\tcfm_apache\t0\tWP_LOGIN;li=0;l=;c=",
	} {
		if got := extractUserAgent([]string{ln}); got != "Mozilla/5.0 X" {
			t.Errorf("%q → %q", ln, got)
		}
	}
	if got := extractUserAgent([]string{"a\tb\tcurl/8"}); got != "curl/8" {
		t.Errorf("short TSV: %q", got)
	}
}
