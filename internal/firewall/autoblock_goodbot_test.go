package firewall

import "testing"

func TestAutoblockGoodBot(t *testing.T) {
	ptrs := map[string]string{
		"69.63.184.14":  "fwdproxy-ncg-014.fbsv.net",
		"198.51.100.7":  "spoof.fbsv.net",
		"198.51.100.8":  "host.example.net",
		"198.51.100.9":  "",
		"198.51.100.10": "flaky.fbsv.net",
	}
	calls := map[string]int{}
	restore := SetAutoblockGoodBotForTest(
		func(ip string) string { return ptrs[ip] },
		func(ptr, ip string) (string, bool) {
			calls[ip]++
			switch ip {
			case "69.63.184.14":
				return "meta", true
			case "198.51.100.10":
				return "", false // resolver timeout
			}
			return "", true // forward-confirm failed: spoofed
		})
	defer restore()

	skip := func(ip string, off bool) bool { s, _ := AutoblockGoodBot(nil, ip, off); return s }
	if !skip("69.63.184.14", false) {
		t.Errorf("verified Meta proxy not skipped")
	}
	if _, why := AutoblockGoodBot(nil, "69.63.184.14", false); why != "FCrDNS-verified good bot meta" || calls["69.63.184.14"] != 1 {
		t.Errorf("second crossing: why=%q after %d verifies, want the cached verdict (1 verify)", why, calls["69.63.184.14"])
	}
	if skip("69.63.184.14", true) {
		t.Errorf("THROTTLE_GOODBOT_EXEMPT=0 still skipped the Meta proxy")
	}
	if skip("198.51.100.7", false) {
		t.Errorf("spoofed suffix PTR skipped")
	}
	for _, ip := range []string{"198.51.100.8", "198.51.100.9"} {
		if skip(ip, false) || calls[ip] != 0 {
			t.Errorf("%s (PTR %q) skipped or verified (%d), want a ban with no DNS", ip, ptrs[ip], calls[ip])
		}
	}
	// Inconclusive: this crossing is skipped (one DNS blip must not ban a real
	// crawler), and nothing is cached: the next crossing verifies again.
	if !skip("198.51.100.10", false) || !skip("198.51.100.10", false) || calls["198.51.100.10"] != 2 {
		t.Errorf("inconclusive: want skipped and re-verified each crossing, got %d verifies", calls["198.51.100.10"])
	}
}
