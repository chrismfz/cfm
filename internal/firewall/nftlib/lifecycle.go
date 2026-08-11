//go:build linux

package nftlib

import (
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"syscall"
	"time"

	"cfm/internal/logging"
	"github.com/google/nftables"
)

// EnsureBase creates all core CFM-owned tables, chains, and sets using netlink.
// The local set handle cache is invalidated so the next nftlib operation
// re-fetches handles from the kernel.
func (b *Backend) EnsureBase() (err error) {
	start := time.Now()
	b.logPhase("EnsureBase", "start", 0, nil, "")
	// Split the timing so the self-test can tell contention (lock_wait) from
	// netlink-connection degradation (nl_work) from the nft CLI part (cli_work).
	var lockWait, nlWork, cliWork time.Duration
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.recordEnsureBase(lockWait, nlWork, cliWork, err)
		extra := fmt.Sprintf("lock_wait=%s nl_work=%s cli_work=%s",
			lockWait.Round(time.Millisecond), nlWork.Round(time.Millisecond), cliWork.Round(time.Millisecond))
		b.logPhase("EnsureBase", st, time.Since(start), err, extra)
	}()
	// Baseline lock_wait immediately before Lock (not from `start`) so it measures
	// ONLY mutex acquisition — otherwise the pre-lock logPhase/log write latency
	// would be misattributed to contention, which is exactly the signal this tool
	// exists to read cleanly.
	lockStart := time.Now()
	b.mu.Lock()
	lockWait = time.Since(lockStart)
	nlStart := time.Now()

	table := &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}
	b.conn.AddTable(table)

	prio := -50
	if b.cfg != nil && b.cfg.NFT.InputPriority != 0 {
		prio = b.cfg.NFT.InputPriority
	}
	// Defence-in-depth: nftables.ChainPriority is int32. prio is operator
	// config so this should never trip in practice, but a wildly out-of-
	// range value would silently wrap on conversion, producing a
	// surprising chain ordering rather than an error. Clamp at the
	// boundary so the misconfiguration is bounded to a sane priority.
	// (CodeQL #711, 2026-05-09 triage.)
	if prio > math.MaxInt32 {
		prio = math.MaxInt32
	} else if prio < math.MinInt32 {
		prio = math.MinInt32
	}
	inputPrio := nftables.ChainPriority(prio)

	acceptPolicy := nftables.ChainPolicyAccept

	b.conn.AddChain(&nftables.Chain{
		Table:    table,
		Name:     "input",
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: &inputPrio,
		Policy:   &acceptPolicy,
	})
	b.conn.AddChain(&nftables.Chain{Table: table, Name: "flood"})
	dstNatPrio := *nftables.ChainPriorityNATDest
	b.conn.AddChain(&nftables.Chain{
		Table:    table,
		Name:     "prerouting",
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: &dstNatPrio,
		Policy:   &acceptPolicy,
	})

	for _, spec := range []struct {
		name       string
		keyType    nftables.SetDatatype
		hasTimeout bool
		interval   bool
	}{
		{name: setAllowV4, keyType: nftables.TypeIPAddr, hasTimeout: true},
		{name: setAllowV6, keyType: nftables.TypeIP6Addr, hasTimeout: true},
		{name: setBlockV4, keyType: nftables.TypeIPAddr, hasTimeout: true},
		{name: setBlockV6, keyType: nftables.TypeIP6Addr, hasTimeout: true},
		{name: setAllowV4Net, keyType: nftables.TypeIPAddr, hasTimeout: true, interval: true},
		{name: setAllowV6Net, keyType: nftables.TypeIP6Addr, hasTimeout: true, interval: true},
		{name: setBlockV4Net, keyType: nftables.TypeIPAddr, hasTimeout: true, interval: true},
		{name: setBlockV6Net, keyType: nftables.TypeIP6Addr, hasTimeout: true, interval: true},
		{name: setIgnoreV4, keyType: nftables.TypeIPAddr, hasTimeout: true},
		{name: setIgnoreV6, keyType: nftables.TypeIP6Addr, hasTimeout: true},
		{name: setIgnoreV4Net, keyType: nftables.TypeIPAddr, hasTimeout: true, interval: true},
		{name: setIgnoreV6Net, keyType: nftables.TypeIP6Addr, hasTimeout: true, interval: true},
		{name: setChalV4, keyType: nftables.TypeIPAddr, hasTimeout: true},
		{name: setChalV6, keyType: nftables.TypeIP6Addr, hasTimeout: true},

		// self (loopback + local IPs) — interval set for CIDR entries
		{name: "self_v4", keyType: nftables.TypeIPAddr, hasTimeout: true, interval: true},
		{name: "self_v6", keyType: nftables.TypeIP6Addr, hasTimeout: true, interval: true},
		// dyn allow (DynDNS)
		{name: "allow_dyn_v4", keyType: nftables.TypeIPAddr, hasTimeout: true},
		{name: "allow_dyn_v6", keyType: nftables.TypeIP6Addr, hasTimeout: true},
		// debug API (restricted to debug port only)
		{name: "debug_api_v4", keyType: nftables.TypeIPAddr},
		{name: "debug_api_v6", keyType: nftables.TypeIP6Addr},
		// external allow/block unions (populated by feeds)
		{name: "allow_ext_v4_hosts", keyType: nftables.TypeIPAddr, hasTimeout: true},
		{name: "allow_ext_v6_hosts", keyType: nftables.TypeIP6Addr, hasTimeout: true},
		{name: "allow_ext_v4_nets", keyType: nftables.TypeIPAddr, hasTimeout: true, interval: true},
		{name: "allow_ext_v6_nets", keyType: nftables.TypeIP6Addr, hasTimeout: true, interval: true},
		{name: "block_ext_v4_hosts", keyType: nftables.TypeIPAddr, hasTimeout: true},
		{name: "block_ext_v6_hosts", keyType: nftables.TypeIP6Addr, hasTimeout: true},
		{name: "block_ext_v4_nets", keyType: nftables.TypeIPAddr, hasTimeout: true, interval: true},
		{name: "block_ext_v6_nets", keyType: nftables.TypeIP6Addr, hasTimeout: true, interval: true},
		// throttling sets
		{name: "th_syn_v4", keyType: nftables.TypeIPAddr, hasTimeout: true},
		{name: "th_syn_v6", keyType: nftables.TypeIP6Addr, hasTimeout: true},
		{name: "th_pps_v4", keyType: nftables.TypeIPAddr, hasTimeout: true},
		{name: "th_pps_v6", keyType: nftables.TypeIP6Addr, hasTimeout: true},
		{name: "th_pf_tcp_v4", keyType: nftables.TypeIPAddr, hasTimeout: true},
		{name: "th_pf_tcp_v6", keyType: nftables.TypeIP6Addr, hasTimeout: true},
		{name: "th_pf_udp_v4", keyType: nftables.TypeIPAddr, hasTimeout: true},
		{name: "th_pf_udp_v6", keyType: nftables.TypeIP6Addr, hasTimeout: true},
		{name: "throttled_v4", keyType: nftables.TypeIPAddr, hasTimeout: true},
		{name: "throttled_v6", keyType: nftables.TypeIP6Addr, hasTimeout: true},
	} {
		b.conn.AddSet(&nftables.Set{
			Table:      table,
			Name:       spec.name,
			KeyType:    spec.keyType,
			HasTimeout: spec.hasTimeout,
			Interval:   spec.interval,
		}, nil)
	}

	if err := b.conn.Flush(); err != nil {
		if isAlreadyExists(err) {
			// preserve idempotency for repeated EnsureBase calls
		} else {
			nlWork = time.Since(nlStart)
			b.mu.Unlock()
			return fmt.Errorf("nftlib: ensure base: %w", err)
		}
	}

	b.invalidateCache()

	nlWork = time.Since(nlStart)
	b.mu.Unlock()

	cliStart := time.Now()
	// Populate self_v4 / self_v6 with loopback + local interface IPs.
	b.refreshSelfSets()

	// Install base input chain rules (idempotent).
	b.applyBaseInputRules()
	cliWork = time.Since(cliStart)

	return nil
}

func (b *Backend) refreshSelfSets() {
	_ = b.nftExec("flush set inet cfm self_v4")
	_ = b.nftExec("flush set inet cfm self_v6")
	_ = b.nftExec("add element inet cfm self_v4 { 127.0.0.0/8 }")
	_ = b.nftExec("add element inet cfm self_v6 { ::1 }")
	_ = b.nftExec("add element inet cfm self_v6 { fe80::/10 }")

	b.selfResolver.Refresh()
	for _, s := range b.selfResolver.LocalIPs() {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			_ = b.nftExec("add element inet cfm self_v4 { " + s + " }")
		} else {
			_ = b.nftExec("add element inet cfm self_v6 { " + s + " }")
		}
	}
}

// applyBaseInputRules installs all permanent set-matching rules in the input chain.
// Each rule is added only if it is not already present (idempotent).
func (b *Backend) applyBaseInputRules() {
	addRule := func(expr string) {
		if !b.ruleExistsCLI("input", expr) {
			_ = b.nftExec("add rule inet cfm input " + expr)
		}
	}
	insertRule := func(expr string) {
		if !b.ruleExistsCLI("input", expr) {
			_ = b.nftExec("insert rule inet cfm input position 0 " + expr)
		}
	}

	// Early rules inserted at position 0 in reverse order so the final
	// top-down order matches the nft backend's EnsureBase:
	//   1 iif lo accept
	//   2 ip saddr @self_v4 accept
	//   3 ip6 saddr @self_v6 accept
	//   4-13 allow sets (manual, dyn, ext, nets)
	//   14-21 block sets (manual, ext, nets)
	//   (optional) ICMP → jump flood

	icmpEnabled := b.cfg != nil && b.cfg.Hardening.ICMPRate > 0

	early := []string{
		`iif "lo" accept`,
		`ip saddr @self_v4 accept`,
		`ip6 saddr @self_v6 accept`,
		`ip saddr @allow_v4 accept`,
		`ip6 saddr @allow_v6 accept`,
		`ip saddr @allow_dyn_v4 accept`,
		`ip6 saddr @allow_dyn_v6 accept`,
		`ip saddr @allow_ext_v4_hosts accept`,
		`ip6 saddr @allow_ext_v6_hosts accept`,
		`ip saddr @allow_ext_v4_nets accept`,
		`ip6 saddr @allow_ext_v6_nets accept`,
		`ip saddr @allow_v4_nets accept`,
		`ip6 saddr @allow_v6_nets accept`,
		`ip saddr @block_v4 drop`,
		`ip6 saddr @block_v6 drop`,
		`ip saddr @block_ext_v4_hosts drop`,
		`ip6 saddr @block_ext_v6_hosts drop`,
		`ip saddr @block_ext_v4_nets drop`,
		`ip6 saddr @block_ext_v6_nets drop`,
		`ip saddr @block_v4_nets drop`,
		`ip6 saddr @block_v6_nets drop`,
	}
	if icmpEnabled {
		early = append(early,
			`ip protocol icmp icmp type echo-request jump flood`,
			`ip6 nexthdr ipv6-icmp icmpv6 type echo-request jump flood`,
		)
	}

	// Insert in reverse so the first item ends up at the top.
	for i := len(early) - 1; i >= 0; i-- {
		insertRule(early[i])
	}

	// Established/related drops for blocked sets (before the general est/rel accept).
	addRule(`ct state established,related ip saddr @block_v4 drop`)
	addRule(`ct state established,related ip6 saddr @block_v6 drop`)
	addRule(`ct state established,related ip saddr @block_ext_v4_hosts drop`)
	addRule(`ct state established,related ip saddr @block_ext_v4_nets drop`)
	addRule(`ct state established,related ip6 saddr @block_ext_v6_hosts drop`)
	addRule(`ct state established,related ip6 saddr @block_ext_v6_nets drop`)
	addRule(`ct state established,related ip saddr @block_v4_nets drop`)
	addRule(`ct state established,related ip6 saddr @block_v6_nets drop`)
	addRule(`ct state established,related accept`)

	// Duplicate allow/block rules appended (nft backend adds them both early and late).
	addRule(`ip saddr @allow_v4 accept`)
	addRule(`ip6 saddr @allow_v6 accept`)
	addRule(`ip saddr @allow_dyn_v4 accept`)
	addRule(`ip6 saddr @allow_dyn_v6 accept`)
	addRule(`ip saddr @allow_ext_v4_hosts accept`)
	addRule(`ip6 saddr @allow_ext_v6_hosts accept`)
	addRule(`ip saddr @allow_ext_v4_nets accept`)
	addRule(`ip6 saddr @allow_ext_v6_nets accept`)
	addRule(`ip saddr @block_v4 drop`)
	addRule(`ip6 saddr @block_v6 drop`)
	addRule(`ip saddr @block_ext_v4_hosts drop`)
	addRule(`ip6 saddr @block_ext_v6_hosts drop`)
	addRule(`ip saddr @block_ext_v4_nets drop`)
	addRule(`ip6 saddr @block_ext_v6_nets drop`)
	addRule(`ip saddr @block_v4_nets drop`)
	addRule(`ip6 saddr @block_v6_nets drop`)

	// jump flood at the end of the base layer (before ports policy rules).
	if !b.ruleExistsCLI("input", "jump flood") {
		_ = b.nftExec("add rule inet cfm input jump flood")
	}
}

// DropEverything removes all CFM-owned firewall state.
func (b *Backend) DropEverything() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	table, err := b.lookupTable()
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("nftlib: drop everything: %w", err)
	}

	b.conn.DelTable(table)
	err = b.conn.Flush()
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("nftlib: drop everything: %w", err)
	}
	b.invalidateCache()
	return nil
}

// ResetTable rebuilds CFM table state via native lifecycle operations only.
//
// It emits explicit timing instrumentation so delegated-vs-native migration
// comparisons can be tracked in production logs.
func (b *Backend) ResetTable() error {
	start := time.Now()

	dropStart := time.Now()
	if err := b.DropEverything(); err != nil {
		return fmt.Errorf("nftlib: reset table (drop): %w", err)
	}
	dropDur := time.Since(dropStart)

	ensureStart := time.Now()
	if err := b.EnsureBase(); err != nil {
		return fmt.Errorf("nftlib: reset table (ensure): %w", err)
	}
	ensureDur := time.Since(ensureStart)

	logging.Logf("[nftlib] reset table timing: drop=%s ensure=%s total=%s", dropDur, ensureDur, time.Since(start))
	return nil
}

// EnsureSetDynamic creates a named dynamic set if it does not exist.
// The cache entry for that set is cleared so the next lookup re-fetches it.
func (b *Backend) EnsureSetDynamic(name string, v6 bool, isNet bool) error {
	keyType, interval := setShape(v6, isNet)
	table := &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.conn.AddSet(&nftables.Set{
		Table:      table,
		Name:       name,
		KeyType:    keyType,
		HasTimeout: true,
		Interval:   interval,
	}, nil)
	err := b.conn.Flush()
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("nftlib: ensure dynamic set %q: %w", name, err)
	}
	delete(b.namedSets, name)
	return nil
}

// DeleteSetIfExists removes a named set, ignoring not-found errors.
func (b *Backend) DeleteSetIfExists(name string) error {
	table := &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.conn.DelSet(&nftables.Set{Table: table, Name: name})
	if err := b.conn.Flush(); err != nil && !isNotFound(err) {
		return fmt.Errorf("nftlib: delete set %q: %w", name, err)
	}
	delete(b.namedSets, name)
	return nil
}

func setShape(v6 bool, isNet bool) (nftables.SetDatatype, bool) {
	if v6 {
		return nftables.TypeIP6Addr, isNet
	}
	return nftables.TypeIPAddr, isNet
}

// FlushSet resets a named set by deleting and recreating it.
//
// The delete and recreate are intentionally split into separate Flush() calls
// to keep transaction boundaries explicit: first commit set removal, then commit
// empty set creation. Missing table/set conditions are treated as no-ops.
// b.mu is held for each transaction individually so the conn queue stays coherent.
func (b *Backend) FlushSet(family, table, set string) error {
	if !strings.EqualFold(family, "inet") || table != cfmTableName {
		return fmt.Errorf("nftlib: unsupported set path %s %s %s", family, table, set)
	}

	// Transaction 1: look up and delete the existing set.
	b.mu.Lock()
	ns, err := b.lookupSet(set)
	if err != nil {
		b.mu.Unlock()
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("nftlib: flush set %s %s %s: %w", family, table, set, err)
	}
	b.conn.DelSet(ns)
	if err := b.conn.Flush(); err != nil {
		if isNotFound(err) {
			b.invalidateCache()
			b.mu.Unlock()
			return nil
		}
		b.mu.Unlock()
		return fmt.Errorf("nftlib: flush set %s %s %s (delete): %w", family, table, set, err)
	}
	delete(b.namedSets, set)
	b.mu.Unlock()

	// Transaction 2: recreate the set with the original schema.
	recreated := &nftables.Set{
		Table:      &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet},
		Name:       ns.Name,
		KeyType:    ns.KeyType,
		HasTimeout: ns.HasTimeout,
		Interval:   ns.Interval,
	}
	b.mu.Lock()
	b.conn.AddSet(recreated, nil)
	if err := b.conn.Flush(); err != nil {
		if isNotFound(err) {
			b.invalidateCache()
			b.mu.Unlock()
			return nil
		}
		if isAlreadyExists(err) {
			delete(b.namedSets, set)
			b.mu.Unlock()
			return nil
		}
		b.mu.Unlock()
		return fmt.Errorf("nftlib: flush set %s %s %s (recreate): %w", family, table, set, err)
	}
	delete(b.namedSets, set)
	b.mu.Unlock()
	return nil
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENODEV) || errors.Is(err, syscall.ESRCH) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no such") || strings.Contains(s, "not found")
}

func isAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EEXIST) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "file exists") || strings.Contains(s, "already exists")
}
