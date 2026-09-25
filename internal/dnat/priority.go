package dnat

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	"cfm/internal/config"
)

// _cfgDir holds the live CFM config directory (e.g. "/etc/cfm"). It lets the
// one-shot `cfm dnat` CLI resolve NFT_DNAT_PRIORITY from cfm.conf the same way
// the daemon does. The CLI builds an UNCONFIGURED backend (nft.New()/nftlib.New()
// carry no *config.Config — only the daemon populates it, via ApplyFloodRules),
// so without this the CLI could never see the operator's configured priority and
// always fell back to the -99 default. Set once by cmd/cfm/main.go during
// dispatch; empty when unset.
var _cfgDir atomic.Value // string

// SetConfigDir records the live CFM config directory. Called by cmd/cfm/main.go
// once during `cfm dnat` dispatch, mirroring SetAPIBase.
func SetConfigDir(dir string) { _cfgDir.Store(strings.TrimSpace(dir)) }

func configDir() string {
	if v := _cfgDir.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// ConfiguredWebDNATPriority returns the DNAT prerouting priority the daemon would
// apply from cfm.conf's NFT_DNAT_PRIORITY, or NFTDNATPriority (-99) when the key
// is unset/absent/unreadable. This is the CLI's source of truth for the
// `cfm dnat on` default so it matches the running daemon — which reads the same
// key via b.cfg.NFT.DNATPriority — instead of always defaulting to -99.
//
// cfm.conf is a FILE, never exported to the CLI process environment, so the old
// env-var read (getenvInt("NFT_DNAT_PRIORITY", …)) could not observe it. An
// explicit --priority flag still overrides this (it is the flag's default).
func ConfiguredWebDNATPriority() int {
	p, _ := configuredWebDNATPriority()
	return p
}

// configuredWebDNATPriority is ConfiguredWebDNATPriority plus whether cfm.conf
// was actually read (false: no config dir, unreadable or unparsable file, so
// the value is only the -99 fallback, not the operator's).
func configuredWebDNATPriority() (int, bool) {
	dir := configDir()
	if dir == "" {
		return NFTDNATPriority, false
	}
	f, err := os.Open(filepath.Join(dir, "cfm.conf"))
	if err != nil {
		return NFTDNATPriority, false
	}
	defer f.Close()
	cfg, err := config.ParseCFMConf(f)
	if err != nil || cfg == nil {
		return NFTDNATPriority, false
	}
	// ParseCFMConf runs SetDefaults()+Validate() internally, which map an
	// absent/zero NFT_DNAT_PRIORITY to -99 and clamp any present value to
	// [-300,300] — so cfg.NFT.DNATPriority is already the exact value the daemon
	// would use, never 0. The ==0 guard is belt-and-suspenders against a future
	// change to that normalization.
	if cfg.NFT.DNATPriority == 0 {
		return NFTDNATPriority, true
	}
	return cfg.NFT.DNATPriority, true
}

// clampNFTPriority bounds a priority to nftables' accepted range, matching the
// backend's own clamp (nft/dnat.go, nftlib/challenge.go) so the CLI never
// reports a value the backend would silently adjust before installing.
func clampNFTPriority(p int) int {
	if p < -300 {
		return -300
	}
	if p > 300 {
		return 300
	}
	return p
}

// nftBaseChainPriorityAnchors maps nftables' symbolic base-chain priority names
// to their numeric values. `nft list` renders a numeric priority symbolically
// when it matches a well-known anchor (a -99 NAT prerouting chain prints as
// "dstnat + 1", -100 as "dstnat", -101 as "dstnat - 1"), so the status report
// must translate the symbol back to a number to show the ACTUAL installed value.
// These are nft's standard base-chain priority names (std_prios): raw, mangle,
// dstnat, filter, security, srcnat. (conntrack/-200 is a hook priority but not an
// nft-displayed name, so it is intentionally absent.)
var nftBaseChainPriorityAnchors = map[string]int{
	"raw":      -300,
	"mangle":   -150,
	"dstnat":   -100,
	"filter":   0,
	"security": 50,
	"srcnat":   100,
}

// parseDNATChainPriority extracts the numeric prerouting base-chain priority from
// `nft list table` output, understanding both a raw integer ("priority -101;")
// and nft's symbolic anchor±offset form ("priority dstnat + 1;"). Returns
// ok=false when no prerouting priority line is present (empty/absent table) or
// the anchor is unrecognised, so callers can fall back to the configured value.
func parseDNATChainPriority(show string) (int, bool) {
	for _, line := range strings.Split(show, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "hook prerouting") {
			continue
		}
		i := strings.Index(line, "priority ")
		if i < 0 {
			continue
		}
		expr := line[i+len("priority "):]
		if j := strings.IndexByte(expr, ';'); j >= 0 {
			expr = expr[:j]
		}
		return evalNFTPriority(strings.TrimSpace(expr))
	}
	return 0, false
}

// evalNFTPriority evaluates a single nft priority expression: a plain integer,
// a bare anchor name, or "anchor + N" / "anchor - N".
func evalNFTPriority(expr string) (int, bool) {
	fields := strings.Fields(expr)
	switch len(fields) {
	case 1:
		if n, err := strconv.Atoi(fields[0]); err == nil {
			return n, true
		}
		if base, ok := nftBaseChainPriorityAnchors[fields[0]]; ok {
			return base, true
		}
	case 3:
		base, ok := nftBaseChainPriorityAnchors[fields[0]]
		if !ok {
			return 0, false
		}
		off, err := strconv.Atoi(fields[2])
		if err != nil {
			return 0, false
		}
		switch fields[1] {
		case "+":
			return base + off, true
		case "-":
			return base - off, true
		}
	}
	return 0, false
}
