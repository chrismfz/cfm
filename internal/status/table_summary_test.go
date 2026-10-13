package status

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"cfm/internal/firewall"
)

// fakeBE answers the three reads readTableSummary makes; any other Backend
// method panics (nil embedded interface).
type fakeBE struct {
	firewall.Backend
	tableJSON    string
	tableJSONErr error
	text         string
	textErr      error
	elems        map[string][]string
	elemErr      map[string]error
}

func (b *fakeBE) ListTableJSON(string, string) ([]byte, error) {
	return []byte(b.tableJSON), b.tableJSONErr
}

func (b *fakeBE) ListTableTextNoDNS(string, string) (string, error) {
	return b.text, b.textErr
}

func (b *fakeBE) ListSetElementsRaw(set string) ([]string, error) {
	if err := b.elemErr[set]; err != nil {
		return nil, err
	}
	return b.elems[set], nil
}

// A text dump as `nft -t -n list table inet cfm` prints it: sets (terse, no
// elements), a named counter, chains whose rules include a ct original accept
// and an anonymous set wrapped over lines.
const tableText = `table inet cfm {
	set allow_v4 {
		type ipv4_addr
		flags timeout
	}
	set block_v4 {
		type ipv4_addr
		flags timeout
	}
	set block_ext_v4_nets_FIREHOL {
		type ipv4_addr
		flags interval
	}
	set block_v6 {
		type ipv6_addr
		flags timeout
	}
	counter synrate_v4 {
		packets 25 bytes 1300
	}
	chain input {
		type filter hook input priority filter; policy drop;
		# a comment
		ct original ip daddr 10.0.0.1 tcp dport 9043 accept
		ip saddr @block_v4 drop
		tcp dport { 21, 22, 25,
			    80, 443 } accept

	}
	chain output {
		type filter hook output priority filter; policy accept;
		oif "lo" accept
	}
}
`

func nftlibShape() *fakeBE {
	return &fakeBE{
		tableJSON: `{"family":"inet","table":"cfm","sets":["allow_v4","block_ext_v4_nets_FIREHOL","block_v4","block_v6","syn_v4"],` +
			`"set_info":[{"name":"allow_v4","type":"ipv4_addr"},{"name":"block_ext_v4_nets_FIREHOL","type":"ipv4_addr"},` +
			`{"name":"block_v4","type":"ipv4_addr"},{"name":"block_v6","type":"ipv6_addr"}]}`,
		text: tableText,
		elems: map[string][]string{
			"allow_v4":                  {"192.0.2.1"},
			"block_v4":                  {"198.51.100.1", "198.51.100.2", "198.51.100.3"},
			"block_ext_v4_nets_FIREHOL": {"203.0.113.0/24", "198.18.0.1-198.18.0.9", "192.0.2.77"},
			"block_v6":                  {"2001:db8::1"},
		},
	}
}

func rowOf(t *testing.T, st statusOut, set string) statusRow {
	t.Helper()
	for _, r := range st.Sets {
		if r.Set == set {
			return r
		}
	}
	t.Fatalf("set %s not in summary: %+v", set, st.Sets)
	return statusRow{}
}

func captureSummary(t *testing.T, st statusOut) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	printSummary(st)
	w.Close()
	os.Stdout = old
	b, _ := io.ReadAll(r)
	return string(b)
}

// The nftlib backend's ListTableJSON carries set names only. The summary used
// to read it as "no rules, no elements" over a full firewall (orion,
// 2026-10-13: 174 rules, 110 000+ entries shown as 0).
func TestReadTableSummary_NftlibShape(t *testing.T) {
	st := readTableSummary(nftlibShape())
	if !st.TablePresent || !st.RulesPresent || st.ReadError != "" {
		t.Fatalf("want present + rules + no error, got %+v", st)
	}
	if got := rowOf(t, st, "block_v4"); got.Hosts != 3 || got.Prefixes != 0 || got.Family != "v4" {
		t.Errorf("block_v4 = %+v", got)
	}
	if got := rowOf(t, st, "block_ext_v4_nets_FIREHOL"); got.Hosts != 1 || got.Prefixes != 2 {
		t.Errorf("block_ext_v4_nets_FIREHOL = %+v (a CIDR and a range are prefixes)", got)
	}
	if got := rowOf(t, st, "block_v6"); got.Hosts != 1 || got.Family != "v6" {
		t.Errorf("block_v6 = %+v", got)
	}
	if st.Totals.Allow.Entries != 1 || st.Totals.Block.Hosts != 5 || st.Totals.Block.Prefixes != 2 || st.Totals.Overall != 8 {
		t.Errorf("totals = %+v", st.Totals)
	}
	for _, r := range st.Sets {
		if r.Set == "syn_v4" {
			t.Errorf("a meter set is not a list: %+v", r)
		}
	}
	out := captureSummary(t, st)
	if !strings.Contains(out, "Firewall: active") || strings.Contains(out, "no rules found") {
		t.Errorf("summary:\n%s", out)
	}
}

func TestCountChainRules(t *testing.T) {
	// input: ct original accept, @block_v4 drop, the wrapped tcp dport set
	// (once); output: oif lo. Not: type/policy lines, the comment, the blank
	// line, set and counter bodies.
	if got := countChainRules(tableText); got != 4 {
		t.Fatalf("countChainRules = %d, want 4", got)
	}
	if got := countChainRules("table inet cfm {\n\tset block_v4 {\n\t\ttype ipv4_addr\n\t}\n}\n"); got != 0 {
		t.Fatalf("a table with sets only has no rules, got %d", got)
	}
}

// The exec backend's `nft -j` dump: rules and elements in one read. An element
// that carries a timeout comes wrapped as {"elem":{"val":…}} and was not
// counted before; a range is a prefix.
func TestReadTableSummary_NftJSONShape(t *testing.T) {
	be := &fakeBE{tableJSON: `{"nftables":[{"metainfo":{"json_schema_version":1}},
		{"table":{"family":"inet","name":"cfm"}},
		{"set":{"family":"inet","name":"block_v4","table":"cfm","type":"ipv4_addr","elem":[
			"198.51.100.1",
			{"elem":{"val":"198.51.100.2","timeout":3600,"expires":3500}},
			{"elem":{"val":{"prefix":{"addr":"203.0.113.0","len":24}},"timeout":60}}]}},
		{"set":{"family":"inet","name":"block_ext_v4_nets_FIREHOL","table":"cfm","type":"ipv4_addr","elem":[
			{"prefix":{"addr":"192.0.2.0","len":24}},{"range":["198.18.0.1","198.18.0.9"]}]}},
		{"rule":{"family":"inet","table":"cfm","chain":"input","expr":[]}}]}`}
	st := readTableSummary(be)
	if !st.TablePresent || !st.RulesPresent || st.ReadError != "" {
		t.Fatalf("got %+v", st)
	}
	if got := rowOf(t, st, "block_v4"); got.Hosts != 2 || got.Prefixes != 1 {
		t.Errorf("block_v4 = %+v (timeout-wrapped elements count)", got)
	}
	if got := rowOf(t, st, "block_ext_v4_nets_FIREHOL"); got.Prefixes != 2 {
		t.Errorf("block_ext_v4_nets_FIREHOL = %+v", got)
	}
}

// `nft -j` output that does not parse (a warning on stderr, an nft built
// without JSON) falls back to the text dump instead of reading as empty.
func TestReadTableSummary_UnparseableJSONFallsBackToText(t *testing.T) {
	be := nftlibShape()
	be.tableJSON = "Warning: table ip filter is managed by iptables-nft, do not touch!\n{\"nftables\":[]}"
	st := readTableSummary(be)
	if !st.TablePresent || !st.RulesPresent || st.Totals.Overall != 8 {
		t.Fatalf("got %+v", st)
	}
}

func TestReadTableSummary_ReadFailuresAreNotZero(t *testing.T) {
	t.Run("table absent", func(t *testing.T) {
		be := &fakeBE{
			tableJSONErr: errors.New("Error: No such file or directory; did you mean table 'cfm' in family ip?"),
			textErr:      errors.New("exit status 1"),
			text:         "Error: No such file or directory",
		}
		st := readTableSummary(be)
		if st.TablePresent || st.ReadError != "" {
			t.Fatalf("got %+v", st)
		}
		if out := captureSummary(t, st); !strings.Contains(out, "inactive") {
			t.Errorf("summary:\n%s", out)
		}
	})
	t.Run("table unreadable", func(t *testing.T) {
		be := &fakeBE{tableJSONErr: errors.New("nftlib ListTableJSON: netlink: permission denied"), textErr: errors.New("nft: not found")}
		st := readTableSummary(be)
		if st.TablePresent || st.ReadError == "" {
			t.Fatalf("an unreadable table must be an error, not 'absent': %+v", st)
		}
		out := captureSummary(t, st)
		if !strings.Contains(out, "UNKNOWN") || strings.Contains(out, "inactive") || strings.Contains(out, "no rules found") {
			t.Errorf("summary:\n%s", out)
		}
	})
	t.Run("one set unreadable", func(t *testing.T) {
		be := nftlibShape()
		be.elemErr = map[string]error{"block_v4": errors.New("netlink: message truncated")}
		st := readTableSummary(be)
		r := rowOf(t, st, "block_v4")
		if r.Err == "" || r.Hosts != 0 {
			t.Fatalf("block_v4 = %+v", r)
		}
		out := captureSummary(t, st)
		if !strings.Contains(out, "READ FAILED") || !strings.Contains(out, "could not be read") {
			t.Errorf("summary:\n%s", out)
		}
	})
}

// The exec backend appends nft's stderr after the JSON on stdout. The JSON is
// still read (the fallback would fork one `nft -j list set` per set, and on
// exec those reads fail on the same warning).
func TestReadTableSummary_TrailingStderrKeepsTheJSONPath(t *testing.T) {
	be := &fakeBE{
		tableJSON: `{"nftables":[{"table":{"family":"inet","name":"cfm"}},` +
			`{"set":{"name":"block_v4","type":"ipv4_addr","elem":["198.51.100.1","198.51.100.2"]}},` +
			`{"rule":{"chain":"input"}}]}` + "\nWarning: table ip filter is managed by iptables-nft, do not touch!\n",
		textErr: errors.New("the text dump must not be read"),
		elemErr: map[string]error{"block_v4": errors.New("the per-set read must not happen")},
	}
	st := readTableSummary(be)
	if !st.RulesPresent || st.ReadError != "" || rowOf(t, st, "block_v4").Hosts != 2 {
		t.Fatalf("got %+v", st)
	}
}

// nftlib listed the sets over netlink, so a text dump that fails (it can time
// out on a loaded node) leaves only the rule count unknown.
func TestReadTableSummary_NftlibTextFailsKeepsSets(t *testing.T) {
	be := nftlibShape()
	be.text, be.textErr = "", errors.New("signal: killed")
	st := readTableSummary(be)
	if !st.TablePresent || st.RulesErr == "" || st.ReadError != "" || st.Totals.Overall != 8 {
		t.Fatalf("got %+v", st)
	}
	if !st.incomplete() {
		t.Error("a summary without its rule count must not be cached")
	}
	out := captureSummary(t, st)
	if !strings.Contains(out, "rules could not be read") || strings.Contains(out, "no rules found") || strings.Contains(out, "UNKNOWN") {
		t.Errorf("summary:\n%s", out)
	}
}

func TestCountChainRules_CommentsAndQuotedBraces(t *testing.T) {
	txt := "table inet cfm {\n" +
		"\tchain input {\n\t\tcomment \"managed by cfm\"\n\t\ttype filter hook input priority 0; policy accept;\n" +
		"\t\tiif \"x}\" accept comment \"odd } brace\"\n\t}\n" +
		"\tchain output {\n\t\tlog prefix \"{ cfm \" accept\n\t}\n}\n"
	if got := countChainRules(txt); got != 2 {
		t.Fatalf("countChainRules = %d, want 2 (one rule per chain)", got)
	}
}
