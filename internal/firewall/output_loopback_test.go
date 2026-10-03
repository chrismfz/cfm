package firewall

import (
	"errors"
	"fmt"
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

// An unread chain is skipped: planned from an empty listing it would read as
// "missing" and stack a copy on every apply whose read times out.
func TestEnsureOutputLoopback_SkipsUnreadChain(t *testing.T) {
	var logged []string
	EnsureOutputLoopback("inet", "cfm",
		func() (string, error) { return "", errors.New("timed out") },
		func(s string) error { t.Fatalf("wrote %q for an unread chain", s); return nil },
		func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) })
	if len(logged) != 1 || !strings.Contains(logged[0], "timed out") {
		t.Fatalf("want the read error logged once, got %q", logged)
	}
}

// A failed write is logged, not returned: the caller must go on and write the
// rest of the egress policy.
func TestEnsureOutputLoopback_WriteFailureIsLogged(t *testing.T) {
	var wrote string
	var logged []string
	EnsureOutputLoopback("inet", "cfm",
		func() (string, error) { return outputChainWithDrops, nil },
		func(s string) error { wrote = s; return errors.New("nft: busy") },
		func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) })
	if wrote != `insert rule inet cfm output oif "lo" accept` {
		t.Fatalf("wrote %q", wrote)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "nft: busy") {
		t.Fatalf("want the write error logged once, got %q", logged)
	}
}

// Present: nothing written, nothing logged.
func TestEnsureOutputLoopback_NoopWhenPresent(t *testing.T) {
	listing := strings.Replace(outputChainWithDrops,
		"\t\tct state established,related accept # handle 40",
		"\t\toif \"lo\" accept # handle 39\n\t\tct state established,related accept # handle 40", 1)
	EnsureOutputLoopback("inet", "cfm",
		func() (string, error) { return listing, nil },
		func(s string) error { t.Fatalf("wrote %q although the rule is present", s); return nil },
		func(f string, a ...any) { t.Fatalf("logged %q", fmt.Sprintf(f, a...)) })
}

// Both engines' ApplyPortsPolicy must ensure the loopback accept right after
// the output chain exists: before the port sets are (re)loaded, so a stricter
// TCP_OUT never takes effect without it, and before any step that can return
// early. The helper is tested above; this pins that it stays wired in there.
func TestApplyPortsPolicy_EnsuresOutputLoopbackFirst(t *testing.T) {
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
		chain := strings.Index(body, "type filter hook output priority 0")
		call := strings.Index(body, "firewall.EnsureOutputLoopback(")
		sets := strings.Index(body, "[]string{setTCPIn, setUDPIn, setTCPOut, setUDPOut}")
		if chain < 0 || call < 0 || sets < 0 || !(chain < call && call < sets) {
			t.Errorf("%s: EnsureOutputLoopback must run after the output chain is ensured and before the port sets are loaded (chain=%d call=%d sets=%d)", f, chain, call, sets)
		}
	}
}
