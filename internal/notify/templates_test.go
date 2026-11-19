package notify

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"text/template"
	"time"
)

// A kept ban (ExtendBlock found a longer one in place) says so in the default
// subject and body; the TTL alone read like the ban's length.
func TestDefaultTemplatesShowKeptBan(t *testing.T) {
	ev := Event{Kind: "WAF/SQLI", SrcIP: "203.0.113.9", TTL: time.Hour, Extra: map[string]string{"block_kept": "longer"}}
	subj, err := renderSubject("", ev)
	if err != nil || !strings.Contains(subj, "ttl=1h0m0s (longer ban kept)") {
		t.Fatalf("subject = %q, %v", subj, err)
	}
	body, err := render("", ev)
	if err != nil || !strings.Contains(body, "TTL: 1h0m0s (a longer ban was already in place and stays)") {
		t.Fatalf("body = %q, %v", body, err)
	}
	ev.Extra = nil
	if subj, _ = renderSubject("", ev); strings.Contains(subj, "kept") {
		t.Fatalf("no kept ban, subject = %q", subj)
	}
}

// The reference notify.conf subject renders, and shows a kept ban.
func TestReferenceSubjectShowsKeptBan(t *testing.T) {
	raw, err := os.ReadFile("../../configs/notify.conf")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^subject_template = (.+)$`).FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatal("no subject_template in configs/notify.conf")
	}
	if _, err := template.New("s").Parse(m[1]); err != nil {
		t.Fatal(err)
	}
	ev := Event{Kind: "WAF/SQLI", SrcIP: "203.0.113.9", Extra: map[string]string{"block_mode": "ttl", "ttl_text": "1h0m0s", "block_kept": "longer"}}
	subj, err := renderSubject(m[1], ev)
	if err != nil || !strings.Contains(subj, "ttl=1h0m0s (longer ban kept)") {
		t.Fatalf("subject = %q, %v", subj, err)
	}
}

// An IPv6 client banned as its /64 says what was banned; an address ban says
// nothing more.
func TestDefaultBodyShowsTheBannedSlash64(t *testing.T) {
	ev := Event{Kind: "WAF/SQLI", SrcIP: "2001:db8:1:2::a", TTL: time.Hour, Extra: map[string]string{"block_net": "2001:db8:1:2::/64"}}
	body, err := render("", ev)
	if err != nil || !strings.Contains(body, "TTL: 1h0m0s\nBanned as: 2001:db8:1:2::/64 (the client's IPv6 /64)\nCount:") {
		t.Fatalf("body = %q, %v", body, err)
	}
	ev.Extra = nil
	if body, _ = render("", ev); strings.Contains(body, "Banned as") || !strings.Contains(body, "TTL: 1h0m0s\nCount:") {
		t.Fatalf("no /64, body = %q", body)
	}
}
