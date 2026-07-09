package dnat

import "testing"

// chainWithAccepts mimics `nft -a list chain inet cfm input` output. nft
// reorders `ct state new` to the front and appends `# handle N`; the parser
// must tolerate both. The panel and per-IP challenge accepts are included to
// prove the web report ignores them.
const chainWithAccepts = `table inet cfm {
	chain input { # handle 1
		type filter hook input priority -50; policy accept;
		ct state established,related accept # handle 2
		ct state new tcp dport 9080 ct status dnat ct original proto-dst 80 accept comment "cfm_dnat_accept:web_http_tcp:80:9080" # handle 3
		ct state new tcp dport 9043 ct status dnat ct original proto-dst 443 accept comment "cfm_dnat_accept:web_https_tcp:443:9043" # handle 4
		ct state new udp dport 9043 ct status dnat ct original proto-dst 443 accept comment "cfm_dnat_accept:web_https_udp:443:9043" # handle 5
		ct state new tcp dport 12082 ct status dnat ct original proto-dst 2082 accept comment "cfm_cpanel_dnat:2082:12082" # handle 6
		ct state new tcp dport 9080 ct status dnat ct original proto-dst 80 accept comment "cfm_challenge_dnat_accept:web_http_ip_tcp:80:9080" # handle 7
		ct state new tcp dport 0-65535 drop # handle 8
		ct state new udp dport 0-65535 drop # handle 9
		ct state invalid drop # handle 10
	}
}`

func stateFor(t *testing.T, states []webDNATAcceptStatus, proto string, from, to int) string {
	t.Helper()
	for _, s := range states {
		if s.Proto == proto && s.From == from && s.To == to {
			return s.State
		}
	}
	t.Fatalf("no status for %s %d->%d in %#v", proto, from, to, states)
	return ""
}

func TestResolveWebDNATAcceptStateAllOpen(t *testing.T) {
	states := resolveWebDNATAcceptState(chainWithAccepts, 9080, 9043)
	if len(states) != 3 {
		t.Fatalf("expected 3 web mappings, got %d", len(states))
	}
	if got := stateFor(t, states, "tcp", 80, 9080); got != "open" {
		t.Errorf("80->9080 tcp = %q, want open", got)
	}
	if got := stateFor(t, states, "tcp", 443, 9043); got != "open" {
		t.Errorf("443->9043 tcp = %q, want open", got)
	}
	if got := stateFor(t, states, "udp", 443, 9043); got != "open" {
		t.Errorf("443->9043 udp = %q, want open", got)
	}
}

func TestResolveWebDNATAcceptStateAbsent(t *testing.T) {
	chain := `table inet cfm {
	chain input {
		type filter hook input priority -50; policy accept;
		ct state established,related accept
		ct state new tcp dport @tcp_in_ports accept
		ct state new tcp dport 0-65535 drop # handle 8
		ct state new udp dport 0-65535 drop # handle 9
	}
}`
	for _, st := range resolveWebDNATAcceptState(chain, 9080, 9043) {
		if st.State != "absent" {
			t.Errorf("%s = %q, want absent", st.mapping(), st.State)
		}
	}
}

// A scoped accept that was appended AFTER the default drop is present but never
// reached, so it must report "blocked", not "open".
func TestResolveWebDNATAcceptStateBlockedWhenAfterDrop(t *testing.T) {
	chain := `table inet cfm {
	chain input {
		type filter hook input priority -50; policy accept;
		ct state established,related accept
		ct state new tcp dport 0-65535 drop # handle 8
		ct state new udp dport 0-65535 drop # handle 9
		ct state new tcp dport 9080 ct status dnat ct original proto-dst 80 accept comment "cfm_dnat_accept:web_http_tcp:80:9080" # handle 10
	}
}`
	if got := stateFor(t, resolveWebDNATAcceptState(chain, 9080, 9043), "tcp", 80, 9080); got != "blocked" {
		t.Errorf("80->9080 after drop = %q, want blocked", got)
	}
}

// The nftlib backend tags its edge accepts with cfm_edge_dnat_accept; the same
// report must recognize them.
func TestResolveWebDNATAcceptStateNftlibComment(t *testing.T) {
	chain := `table inet cfm {
	chain input {
		type filter hook input priority -50; policy accept;
		ct state new tcp dport 9080 ct status dnat ct original proto-dst 80 accept comment "cfm_edge_dnat_accept:web_http_tcp:80:9080" # handle 3
		ct state new tcp dport 0-65535 drop # handle 8
	}
}`
	if got := stateFor(t, resolveWebDNATAcceptState(chain, 9080, 9043), "tcp", 80, 9080); got != "open" {
		t.Errorf("80->9080 (nftlib comment) = %q, want open", got)
	}
}

// Custom listener ports must be honoured: an accept for the default 9080 does
// not satisfy a report expecting 9000.
func TestResolveWebDNATAcceptStateCustomPorts(t *testing.T) {
	if got := stateFor(t, resolveWebDNATAcceptState(chainWithAccepts, 9000, 9043), "tcp", 80, 9000); got != "absent" {
		t.Errorf("80->9000 against a 9080 chain = %q, want absent", got)
	}
}

func TestParseWebDNATAcceptCommentIgnoresNonEdge(t *testing.T) {
	// Panel accept and per-IP challenge accept must not be parsed as edge.
	for _, line := range []string{
		`ct state new tcp dport 12082 ct status dnat ct original proto-dst 2082 accept comment "cfm_cpanel_dnat:2082:12082"`,
		`ct state new tcp dport 9080 ct status dnat ct original proto-dst 80 accept comment "cfm_challenge_dnat_accept:web_http_ip_tcp:80:9080"`,
	} {
		if _, _, _, ok := parseWebDNATAcceptComment(line); ok {
			t.Errorf("parseWebDNATAcceptComment(%q) ok=true, want false", line)
		}
	}
	label, from, to, ok := parseWebDNATAcceptComment(`... accept comment "cfm_dnat_accept:web_https_udp:443:9043" # handle 5`)
	if !ok || label != "web_https_udp" || from != 443 || to != 9043 {
		t.Fatalf("parse edge = (%q,%d,%d,%v), want (web_https_udp,443,9043,true)", label, from, to, ok)
	}
}
