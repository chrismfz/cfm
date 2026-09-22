package firewall

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// fakeInputChain is an `inet cfm input` chain driven through NFTTextOps: it
// renders `nft -a list` text and applies add/insert/delete by handle, so the
// shared accept code runs against realistic listings.
type fakeInputChain struct {
	rules   []fakeRule
	next    int
	cmds    []string
	listErr error
	runErr  func(cmd string) error
}

type fakeRule struct {
	handle int
	text   string
}

func newFakeInputChain(texts ...string) *fakeInputChain {
	c := &fakeInputChain{next: 2}
	for _, t := range texts {
		c.rules = append(c.rules, fakeRule{handle: c.next, text: t})
		c.next++
	}
	return c
}

func (c *fakeInputChain) ops() NFTTextOps {
	return NFTTextOps{ListInput: c.list, Run: c.run}
}

func (c *fakeInputChain) list() (string, error) {
	if c.listErr != nil {
		return "", c.listErr
	}
	var b strings.Builder
	b.WriteString("table inet cfm {\n\tchain input { # handle 1\n\t\ttype filter hook input priority filter; policy accept;\n")
	for _, r := range c.rules {
		fmt.Fprintf(&b, "\t\t%s # handle %d\n", r.text, r.handle)
	}
	b.WriteString("\t}\n}\n")
	return b.String(), nil
}

func (c *fakeInputChain) run(cmd string) error {
	c.cmds = append(c.cmds, cmd)
	if c.runErr != nil {
		if err := c.runErr(cmd); err != nil {
			return err
		}
	}
	switch {
	case strings.HasPrefix(cmd, "add table "), strings.HasPrefix(cmd, "add chain "):
		return nil
	case strings.HasPrefix(cmd, "delete rule inet cfm input handle "):
		h, _ := strconv.Atoi(strings.TrimPrefix(cmd, "delete rule inet cfm input handle "))
		for i, r := range c.rules {
			if r.handle == h {
				c.rules = append(c.rules[:i], c.rules[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("no rule with handle %d", h)
	case strings.HasPrefix(cmd, "insert rule inet cfm input position "):
		rest := strings.TrimPrefix(cmd, "insert rule inet cfm input position ")
		hs, text, _ := strings.Cut(rest, " ")
		h, _ := strconv.Atoi(hs)
		for i, r := range c.rules {
			if r.handle == h {
				nr := fakeRule{handle: c.next, text: text}
				c.next++
				c.rules = append(c.rules[:i], append([]fakeRule{nr}, c.rules[i:]...)...)
				return nil
			}
		}
		return fmt.Errorf("no rule with handle %d", h)
	case strings.HasPrefix(cmd, "add rule inet cfm input "):
		c.rules = append(c.rules, fakeRule{handle: c.next, text: strings.TrimPrefix(cmd, "add rule inet cfm input ")})
		c.next++
		return nil
	}
	return fmt.Errorf("unexpected command %q", cmd)
}

// cmdIndex is the position of the first command containing needle, or -1.
func (c *fakeInputChain) cmdIndex(needle string) int {
	for i, cmd := range c.cmds {
		if strings.Contains(cmd, needle) {
			return i
		}
	}
	return -1
}

const (
	defaultDropTCP = "ct state new tcp dport 0-65535 drop"
	defaultDropUDP = "ct state new udp dport 0-65535 drop"
)

func taggedAccept(from, to int) string {
	return fmt.Sprintf(`tcp dport %d ct state new ct status dnat ct original proto-dst %d accept comment "%s"`, to, from, PanelDNATAcceptComment(from, to))
}

// legacyAccept is how nft 1.0.x renders a rule the nftlib backend wrote over
// netlink (no comment: nft can't show its raw user data as one).
func legacyAccept(from, to int) string {
	return fmt.Sprintf("ct state new ct status dnat ct original proto-dst %d tcp dport %d accept", from, to)
}

// legacyAcceptHex is the same rule as older nft renders it (seen on an EL8
// node): the original port in hex, flagged "[invalid type]".
func legacyAcceptHex(from, to int) string {
	return fmt.Sprintf("ct state new ct status dnat ct original proto-dst %#x [invalid type] tcp dport %d accept", from, to)
}

func TestParsePanelAcceptLine(t *testing.T) {
	cases := []struct {
		name       string
		line       string
		wantKey    string
		wantLegacy bool
		wantOK     bool
	}{
		{"tagged", taggedAccept(2083, 12083) + " # handle 7", "2083:12083", false, true},
		{"legacy nft 1.0", legacyAccept(2083, 12083) + " # handle 7", "2083:12083", true, true},
		{"legacy older nft (hex)", legacyAcceptHex(2222, 12222) + " # handle 320", "2222:12222", true, true},
		{"legacy with l4proto dependency", "ct state new ct status dnat ct original proto-dst 2083 meta l4proto tcp tcp dport 12083 accept # handle 7", "2083:12083", true, true},
		{"no handle", legacyAccept(2083, 12083), "", false, false},
		{"web dnat accept", `tcp dport 9080 ct state new ct status dnat ct original proto-dst 80 accept comment "cfm_edge_dnat_accept:web_http_tcp:80:9080" # handle 9`, "", false, false},
		{"untagged with an extra match", "ct state new ct status dnat ct original proto-dst 2083 ip saddr 192.0.2.1 tcp dport 12083 accept # handle 7", "", false, false},
		{"untagged udp", "ct state new ct status dnat ct original proto-dst 2083 udp dport 12083 accept # handle 7", "", false, false},
		{"untagged drop", "ct state new ct status dnat ct original proto-dst 2083 tcp dport 12083 drop # handle 7", "", false, false},
		{"foreign comment", legacyAccept(2083, 12083) + ` comment "operator" # handle 7`, "", false, false},
		{"default drop", defaultDropTCP + " # handle 7", "", false, false},
	}
	for _, tc := range cases {
		r, ok := parsePanelAcceptLine(tc.line)
		if ok != tc.wantOK || r.key != tc.wantKey || r.legacy != tc.wantLegacy {
			t.Errorf("%s: got (key=%q legacy=%v ok=%v), want (key=%q legacy=%v ok=%v)", tc.name, r.key, r.legacy, ok, tc.wantKey, tc.wantLegacy, tc.wantOK)
		}
		if ok && r.handle != "7" && r.handle != "320" {
			t.Errorf("%s: handle %q", tc.name, r.handle)
		}
	}
}

// The chain on a node the nftlib backend managed before this change: its
// panel accepts are untagged, and one mapping has none at all.
func legacyNodeChain() *fakeInputChain {
	var texts []string
	for _, m := range PanelDNATMappings()[1:] {
		texts = append(texts, legacyAcceptHex(m.From, m.To))
	}
	return newFakeInputChain(append(texts, defaultDropTCP, defaultDropUDP)...)
}

// assertOneTaggedAcceptEach checks every mapping has exactly one accept, tagged
// and before the default drop, and that no legacy rule is left.
func assertOneTaggedAcceptEach(t *testing.T, c *fakeInputChain) {
	t.Helper()
	out, _ := c.list()
	rules := panelAcceptRules(out)
	for _, m := range PanelDNATMappings() {
		key := panelDNATAcceptKey(m.From, m.To)
		n := 0
		for _, r := range rules {
			if r.key != key {
				continue
			}
			n++
			if r.legacy || !r.beforeDrop {
				t.Errorf("%s: rule %+v, want tagged and before the drop", key, r)
			}
		}
		if n != 1 {
			t.Errorf("%s: %d accepts, want exactly 1\n%s", key, n, out)
		}
	}
}

func TestEnsurePanelDNATAccepts_ReplacesLegacyRules(t *testing.T) {
	c := legacyNodeChain()
	before, _ := c.list()
	legacyHandle := map[string]string{}
	for _, r := range panelAcceptRules(before) {
		legacyHandle[r.key] = r.handle
	}
	changes, err := EnsurePanelDNATAccepts(c.ops())
	if err != nil {
		t.Fatal(err)
	}
	assertOneTaggedAcceptEach(t, c)
	if want := len(PanelDNATMappings()); len(changes) != want {
		t.Errorf("changes = %q, want one per mapping (%d)", changes, want)
	}
	// Each replacement is inserted before its legacy rule is deleted, so the
	// port never goes without an accept.
	for _, m := range PanelDNATMappings()[1:] {
		key := panelDNATAcceptKey(m.From, m.To)
		ins := c.cmdIndex(PanelDNATAcceptComment(m.From, m.To))
		del := c.cmdIndex("delete rule inet cfm input handle " + legacyHandle[key])
		if ins < 0 || del < 0 || del < ins {
			t.Errorf("%s: insert at %d, legacy delete at %d; want insert first: %q", key, ins, del, c.cmds)
		}
	}

	// A second run finds everything in place and changes nothing.
	c.cmds = nil
	changes, err = EnsurePanelDNATAccepts(c.ops())
	if err != nil || len(changes) != 0 {
		t.Fatalf("second run: changes=%q err=%v, want none", changes, err)
	}
	for _, cmd := range c.cmds {
		if !strings.HasPrefix(cmd, "add table") && !strings.HasPrefix(cmd, "add chain") {
			t.Errorf("second run changed the chain: %q", cmd)
		}
	}
}

func TestEnsurePanelDNATAccepts_FixesMisplacedAndDuplicateTagged(t *testing.T) {
	maps := PanelDNATMappings()
	c := newFakeInputChain(
		taggedAccept(maps[0].From, maps[0].To),
		taggedAccept(maps[1].From, maps[1].To),
		taggedAccept(maps[1].From, maps[1].To), // duplicate
		defaultDropTCP,
		taggedAccept(maps[2].From, maps[2].To), // after the drop: never reached
	)
	if _, err := EnsurePanelDNATAccepts(c.ops()); err != nil {
		t.Fatal(err)
	}
	assertOneTaggedAcceptEach(t, c)
	if strings.Contains(strings.Join(c.cmds, "\n"), fmt.Sprintf("proto-dst %d ", maps[0].From)) {
		t.Errorf("a tagged accept already in place must be kept, not rewritten: %q", c.cmds)
	}
}

func TestEnsurePanelDNATAccepts_ListErrorChangesNothing(t *testing.T) {
	c := legacyNodeChain()
	c.listErr = errors.New("nft: exit status 1")
	if _, err := EnsurePanelDNATAccepts(c.ops()); err == nil {
		t.Fatal("want an error: without a listing the accepts would land after the drop")
	}
	for _, cmd := range c.cmds {
		if !strings.HasPrefix(cmd, "add table") && !strings.HasPrefix(cmd, "add chain") {
			t.Errorf("ran %q after a failed listing", cmd)
		}
	}
}

// If the tagged replacement can't be inserted, the legacy accept must stay:
// it is the only thing keeping the port open.
func TestEnsurePanelDNATAccepts_InsertFailureKeepsLegacy(t *testing.T) {
	c := legacyNodeChain()
	c.runErr = func(cmd string) error {
		if strings.HasPrefix(cmd, "insert ") {
			return errors.New("insert failed")
		}
		return nil
	}
	if _, err := EnsurePanelDNATAccepts(c.ops()); err == nil {
		t.Fatal("want the insert error")
	}
	if i := c.cmdIndex("delete "); i >= 0 {
		t.Fatalf("deleted a working accept after its replacement failed: %q", c.cmds)
	}
}

// A stale extra that won't delete must not fail the call: `cfm dnat cpanel on`
// rolls the whole panel redirect back on an error, though the tagged accept
// is already in place.
func TestEnsurePanelDNATAccepts_DeleteFailureIsNotAnError(t *testing.T) {
	c := legacyNodeChain()
	c.runErr = func(cmd string) error {
		if strings.HasPrefix(cmd, "delete ") {
			return errors.New("No such file or directory")
		}
		return nil
	}
	changes, err := EnsurePanelDNATAccepts(c.ops())
	if err != nil {
		t.Fatalf("a failed delete of a legacy extra must not be an error: %v", err)
	}
	if n := strings.Count(strings.Join(c.cmds, "\n"), "insert rule"); n != len(PanelDNATMappings()) {
		t.Errorf("%d inserts, want every mapping handled despite the failed deletes: %q", n, c.cmds)
	}
	if !strings.Contains(strings.Join(changes, "\n"), "could not remove") {
		t.Errorf("changes %q don't report the failed delete", changes)
	}
}

func TestRemovePanelDNATAccepts_RemovesTaggedAndLegacy(t *testing.T) {
	maps := PanelDNATMappings()
	c := newFakeInputChain(
		taggedAccept(maps[0].From, maps[0].To),
		legacyAccept(maps[1].From, maps[1].To),
		legacyAcceptHex(maps[2].From, maps[2].To),
		taggedAccept(maps[2].From, maps[2].To),
		`tcp dport 9080 ct state new ct status dnat ct original proto-dst 80 accept comment "cfm_edge_dnat_accept:web_http_tcp:80:9080"`,
		defaultDropTCP,
	)
	changes, err := RemovePanelDNATAccepts(c.ops())
	if err != nil {
		t.Fatal(err)
	}
	out, _ := c.list()
	if rules := panelAcceptRules(out); len(rules) != 0 {
		t.Fatalf("left panel accepts behind: %+v\n%s", rules, out)
	}
	if !strings.Contains(out, "cfm_edge_dnat_accept") || !strings.Contains(out, "0-65535 drop") {
		t.Fatalf("removed a rule that isn't a panel accept:\n%s", out)
	}
	got := strings.Join(changes, "\n")
	for _, want := range []string{
		fmt.Sprintf("scoped %d->%d removed", maps[1].From, maps[1].To),
		fmt.Sprintf("scoped %d->%d not found", maps[3].From, maps[3].To),
	} {
		if !strings.Contains(got, want) {
			t.Errorf("changes %q missing %q", changes, want)
		}
	}

	c.listErr = errors.New("nft: exit status 1")
	if changes, err := RemovePanelDNATAccepts(c.ops()); changes != nil || err != nil {
		t.Errorf("unlistable chain: got (%q, %v), want (nil, nil) as before", changes, err)
	}
}

func TestPanelDNATAcceptState(t *testing.T) {
	maps := PanelDNATMappings()
	c := newFakeInputChain(
		taggedAccept(maps[0].From, maps[0].To),
		legacyAcceptHex(maps[1].From, maps[1].To),
		defaultDropTCP,
		taggedAccept(maps[2].From, maps[2].To),
	)
	st := PanelDNATAcceptState(c.ops())
	want := map[int]string{
		maps[0].To: "open",    // tagged, before the drop
		maps[1].To: "open",    // legacy, before the drop: it admits traffic
		maps[2].To: "blocked", // stranded after the drop
		maps[3].To: "blocked", // absent
	}
	for port, w := range want {
		if st[port] != w {
			t.Errorf("port %d: %q, want %q", port, st[port], w)
		}
	}

	c.listErr = errors.New("nft: exit status 1")
	for port, s := range PanelDNATAcceptState(c.ops()) {
		if s != "unknown" {
			t.Errorf("unlistable chain: port %d = %q, want unknown", port, s)
		}
	}
}

func TestFirstInputDefaultDropHandle(t *testing.T) {
	c := newFakeInputChain(taggedAccept(2083, 12083), defaultDropTCP, defaultDropUDP)
	out, _ := c.list()
	if h := FirstInputDefaultDropHandle(out); h != "3" {
		t.Fatalf("got %q, want 3", h)
	}
	if h := FirstInputDefaultDropHandle(strings.ReplaceAll(out, "0-65535", "22")); h != "" {
		t.Fatalf("no default drop: got %q, want \"\"", h)
	}
}
