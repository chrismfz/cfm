//go:build linux

package nft

import (
	"strings"
	"testing"
	"time"

	"cfm/internal/config"
	"cfm/internal/firewall"
)

// ApplyPortsPolicy's two chain reads (`nft -a list chain inet cfm
// input|output`) are the costly runs on EL8: nft 1.0.4 loads every set
// element before any `list chain` (4-12 s idle on earth, mars and virgo,
// 2026-11-22), and the runner's 10 s default, which also covers the wait for
// one of the four nft slots, timed the apply out under load. These tests pin
// the deadline both reads and the transaction get
// (firewall.PortsPolicyChainReadTimeout), that a timed-out read stays an
// error and writes nothing, and that the output chain is not read at all when
// the cheap `list chains inet` says it does not exist.

const portsInputListing = `table inet cfm {
	chain input { # handle 1
		type filter hook input priority filter; policy accept;
	}
}
`

const portsChainsInputOnly = `table inet cfm {
	chain input {
		type filter hook input priority filter; policy accept;
	}
}
`

const portsChainsWithOutput = `table inet cfm {
	chain input {
		type filter hook input priority filter; policy accept;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`

func portsCfg() *config.PortsConfig {
	return &config.PortsConfig{TCPIn: []config.PortRange{{From: 22, To: 22}, {From: 443, To: 443}}}
}

func withPortsReadTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := firewall.PortsPolicyChainReadTimeout
	firewall.PortsPolicyChainReadTimeout = d
	t.Cleanup(func() { firewall.PortsPolicyChainReadTimeout = old })
}

func countLines(log, line string) int {
	n := 0
	for _, ln := range strings.Split(log, "\n") {
		if ln == line {
			n++
		}
	}
	return n
}

func TestPortsPolicyChainReadTimeout_FitsEL8(t *testing.T) {
	if firewall.PortsPolicyChainReadTimeout < firewall.BaseInputReadTimeout {
		t.Errorf("PortsPolicyChainReadTimeout = %v, below EnsureBase's %v: EL8's 4-12 s `list chain` plus the slot wait",
			firewall.PortsPolicyChainReadTimeout, firewall.BaseInputReadTimeout)
	}
	if firewall.PortsPolicyChainReadTimeout <= defaultNFTCommandTimeout {
		t.Errorf("PortsPolicyChainReadTimeout = %v, not above the runner's %v default", firewall.PortsPolicyChainReadTimeout, defaultNFTCommandTimeout)
	}
}

func TestApplyPortsPolicy_SkipsAnAbsentOutputChain(t *testing.T) {
	log := fakeNFTOpts(t, fakeOpts{chains: "ok", chainsListing: portsChainsInputOnly, inputListing: portsInputListing})
	if err := New().ApplyPortsPolicy(portsCfg()); err != nil {
		t.Fatalf("ApplyPortsPolicy: %v", err)
	}
	got := readFile(t, log)
	if strings.Contains(got, "ARGS -a list chain inet cfm output") {
		t.Errorf("read the output chain `list chains inet` says is absent (a 4-12 s EL8 listing for nothing):\n%s", got)
	}
	if n := countLines(got, "ARGS -a list chain inet cfm input"); n != 1 {
		t.Errorf("input chain read %d times, want 1:\n%s", n, got)
	}
	if !strings.Contains(got, "add chain inet cfm output { type filter hook output priority 0; policy accept; }") {
		t.Errorf("the absent output chain was not planned as fresh:\n%s", got)
	}
}

func TestApplyPortsPolicy_ReadsAListedOutputChain(t *testing.T) {
	log := fakeNFTOpts(t, fakeOpts{chains: "ok", chainsListing: portsChainsWithOutput, inputListing: portsInputListing})
	if err := New().ApplyPortsPolicy(portsCfg()); err != nil {
		t.Fatalf("ApplyPortsPolicy: %v", err)
	}
	if n := countLines(readFile(t, log), "ARGS -a list chain inet cfm output"); n != 1 {
		t.Errorf("output chain read %d times, want 1", n)
	}
}

func TestApplyPortsPolicy_UnreadableChainListReadsTheOutputChain(t *testing.T) {
	log := fakeNFTOpts(t, fakeOpts{chains: "fail", inputListing: portsInputListing})
	if err := New().ApplyPortsPolicy(portsCfg()); err != nil {
		t.Fatalf("ApplyPortsPolicy: %v", err)
	}
	if n := countLines(readFile(t, log), "ARGS -a list chain inet cfm output"); n != 1 {
		t.Errorf("output chain read %d times with `list chains inet` failing, want 1", n)
	}
}

// The chain read runs under PortsPolicyChainReadTimeout, not the runner's
// default: shortened here, a hung read fails in well under the default.
// And it fails: the apply plans nothing from an unread chain.
func TestApplyPortsPolicy_ChainReadDeadlineIsAnError(t *testing.T) {
	withPortsReadTimeout(t, 300*time.Millisecond)
	log := fakeNFTOpts(t, fakeOpts{chains: "ok", chainsListing: portsChainsWithOutput, inputHang: true})
	start := time.Now()
	err := New().ApplyPortsPolicy(portsCfg())
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("the hung input read took %v: not bounded by PortsPolicyChainReadTimeout", took)
	}
	if err == nil || !strings.Contains(err.Error(), "input chain") {
		t.Fatalf("err = %v, want the input-chain read error", err)
	}
	got := readFile(t, log)
	if strings.Contains(got, "ARGS -f") {
		t.Errorf("wrote after a timed-out read:\n%s", got)
	}
}

func TestApplyPortsPolicy_TransactionDeadline(t *testing.T) {
	withPortsReadTimeout(t, 300*time.Millisecond)
	log := fakeNFTOpts(t, fakeOpts{chains: "ok", chainsListing: portsChainsWithOutput, inputListing: portsInputListing, scriptHang: true})
	start := time.Now()
	err := New().ApplyPortsPolicy(portsCfg())
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("two hung transactions took %v: not bounded by PortsPolicyChainReadTimeout", took)
	}
	if err == nil {
		t.Fatal("a hung transaction reported success")
	}
	if n := strings.Count(readFile(t, log), "ARGS -f -"); n != 2 {
		t.Errorf("%d transactions, want 2 (one retry)", n)
	}
}
