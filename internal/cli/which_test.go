package cli

import "testing"

func TestSummarizeHistory_Empty(t *testing.T) {
	// The key case for the Greek permanent bans: no detection events → the tool
	// says plainly it's a manual/blocklist ban, not WAF/detector.
	s := summarizeHistory(nil)
	if s.Total != 0 || len(s.Groups) != 0 {
		t.Fatalf("empty history should have no groups: %+v", s)
	}
	if !contains(s.Note, "manual") || !contains(s.Note, "blocklist") {
		t.Fatalf("empty note should point at manual/blocklist origin: %q", s.Note)
	}
}

func TestSummarizeHistory_GroupsAndRanks(t *testing.T) {
	rows := []histEvent{
		{EventType: "waf", Reason: "WAF_SQLI", Host: "shop.gr", TsUTC: "2026-08-06T15:00:00Z"},
		{EventType: "waf", Reason: "WAF_SQLI", Host: "shop.gr", TsUTC: "2026-08-06T15:04:00Z"},
		{EventType: "waf", Reason: "WAF_SQLI", Host: "other.gr", TsUTC: "2026-08-06T14:00:00Z"},
		{EventType: "challenge_issued", Reason: "CHALLENGE_SUBNET", Host: "shop.gr", TsUTC: "2026-08-06T13:00:00Z"},
	}
	s := summarizeHistory(rows)
	if s.Total != 4 || len(s.Groups) != 2 {
		t.Fatalf("want total=4, 2 groups: %+v", s)
	}
	// Most frequent group first: waf/WAF_SQLI (3) before challenge (1).
	g := s.Groups[0]
	if g.EventType != "waf" || g.Reason != "WAF_SQLI" || g.Count != 3 {
		t.Fatalf("top group wrong: %+v", g)
	}
	// Latest timestamp in the group is kept.
	if g.LastUTC != "2026-08-06T15:04:00Z" {
		t.Fatalf("last_utc = %q, want the newest", g.LastUTC)
	}
	if g.SampleHost == "" {
		t.Fatalf("expected a sample host")
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
