package firewall

import (
	"os"
	"strings"
	"testing"
)

const outputChainWithDrops = `table inet cfm {
	chain output { # handle 3
		type filter hook output priority filter; policy accept;
		ct state established,related accept # handle 40
		ct state invalid drop # handle 41
		ct state new tcp dport @tcp_out_ports accept # handle 42
		ct state new udp dport @udp_out_ports accept # handle 43
		ct state new tcp dport 0-65535 drop # handle 44
		ct state new udp dport 0-65535 drop # handle 45
	}
}
`

// Missing (every node upgraded from a release without it): one insert, at the
// head, and nothing deleted.
func TestOutputLoopbackScript_InsertsWhenMissing(t *testing.T) {
	got := OutputLoopbackScript("inet", "cfm", outputChainWithDrops)
	if got != `insert rule inet cfm output oif "lo" accept` {
		t.Fatalf("got %q", got)
	}
}

// Present as nft prints it: nothing to write, so no apply stacks copies.
func TestOutputLoopbackScript_NothingWhenPresent(t *testing.T) {
	listing := strings.Replace(outputChainWithDrops,
		"\t\tct state established,related accept # handle 40",
		"\t\toif \"lo\" accept # handle 39\n\t\tct state established,related accept # handle 40", 1)
	if got := OutputLoopbackScript("inet", "cfm", listing); got != "" {
		t.Fatalf("want no script, got %q", got)
	}
}

// Copies left by an apply that read the chain wrong are removed, the top-most
// one kept.
func TestOutputLoopbackScript_RemovesDuplicates(t *testing.T) {
	listing := strings.Replace(outputChainWithDrops,
		"\t\tct state established,related accept # handle 40",
		"\t\toif \"lo\" accept # handle 39\n\t\toif \"lo\" accept # handle 46\n\t\tct state established,related accept # handle 40\n\t\toif \"lo\" accept # handle 47", 1)
	got := OutputLoopbackScript("inet", "cfm", listing)
	want := "delete rule inet cfm output handle 46\ndelete rule inet cfm output handle 47"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

// Both engines' ApplyPortsPolicy must ensure the loopback accept, and before
// they write the catch-all NEW drops of the output chain. The helper is tested
// above; this pins that it stays wired in.
func TestApplyPortsPolicy_EnsuresOutputLoopbackBeforeDrops(t *testing.T) {
	for _, f := range []string{"nft/ports.go", "nftlib/ports_nftlib.go"} {
		b, err := os.ReadFile(f) // #nosec G304 -- fixed repo path
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		start := strings.Index(src, ") ApplyPortsPolicy(")
		if start < 0 {
			t.Fatalf("%s: ApplyPortsPolicy not found", f)
		}
		body := src[start:]
		call := strings.Index(body, "b.ensureOutputLoopbackAccept()")
		drop := strings.Index(body, `addRule("output", `+"`ct state new tcp dport 0-65535 drop`")
		if drop < 0 {
			drop = strings.Index(body, `addRule("output", "ct state new tcp dport 0-65535 drop")`)
		}
		if call < 0 || drop < 0 || call > drop {
			t.Errorf("%s: ensureOutputLoopbackAccept must be called in ApplyPortsPolicy before the output drops (call=%d drop=%d)", f, call, drop)
		}
	}
}
