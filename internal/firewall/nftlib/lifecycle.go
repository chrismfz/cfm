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

	"cfm/internal/firewall/feedutil"
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
	// slow kernel round-trips (nl_work) from the nft CLI part (cli_work).
	var lockWait, nlWork, cliWork time.Duration
	var rulesErr error // base input rules left incomplete; not fatal, but recorded
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		recErr := err
		if recErr == nil {
			recErr = rulesErr
		}
		b.recordEnsureBase(lockWait, nlWork, cliWork, recErr)
		extra := fmt.Sprintf("lock_wait=%s nl_work=%s cli_work=%s",
			lockWait.Round(time.Millisecond), nlWork.Round(time.Millisecond), cliWork.Round(time.Millisecond))
		if rulesErr != nil {
			extra += fmt.Sprintf(" base_rules_err=%q", rulesErr.Error())
		}
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

	// Keep an existing input chain as it is, as the nft backend does.
	// Re-declaring a base chain with another priority fails the whole batch
	// (EOPNOTSUPP), so every later EnsureBase — and every DNATOn, which calls
	// it — would fail. The priority differs whenever this process has no
	// config (a one-shot `cfm dnat on`, which builds its backend without one)
	// or NFT_INPUT_PRIORITY changed after the chain was created.
	cur := b.existingInputChain()
	newChain := cur == nil
	if cur == nil {
		b.conn.AddChain(&nftables.Chain{
			Table:    table,
			Name:     "input",
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookInput,
			Priority: &inputPrio,
			Policy:   &acceptPolicy,
		})
	} else if b.cfg != nil && cur.Priority != nil && *cur.Priority != inputPrio {
		logging.Logf("[nftlib] WARNING: input chain priority is %d, config wants %d; keeping the existing chain (NFT_INPUT_PRIORITY applies only when the chain is created)",
			*cur.Priority, inputPrio)
	}
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

	// Legacy cleanup (runs each EnsureBase; no-op once clean): earlier
	// versions created the retired per-IP challenge-DNAT sets unconditionally.
	// Drop them if still present so upgraded nodes shed the stale (empty)
	// sets; tolerant when absent, and a hypothetical node with rules still
	// referencing them just keeps them (delete fails EBUSY, ignored) until
	// the next full table reset.
	_ = b.DeleteSetIfExists("challenge_v4")
	_ = b.DeleteSetIfExists("challenge_v6")

	// Populate self_v4 / self_v6 with loopback + local interface IPs (netlink;
	// each write is recorded with the feed writes).
	b.refreshSelfSets()

	// Install base input chain rules (idempotent).
	cliStart := time.Now()
	rulesErr = b.applyBaseInputRules(newChain)
	cliWork = time.Since(cliStart)

	return nil
}

// existingInputChain returns inet cfm's input chain, or nil when it doesn't
// exist or the chain list can't be read (EnsureBase then declares it, as it
// always did). Only chains are listed: never the input chain's rules, which
// google/nftables can't decode (see panel_dnat_accepts.go). Must be called
// with b.mu held.
func (b *Backend) existingInputChain() *nftables.Chain {
	chains, err := b.conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return nil
	}
	for _, ch := range chains {
		if ch.Table != nil && ch.Table.Name == cfmTableName && ch.Name == "input" {
			return ch
		}
	}
	return nil
}

// refreshSelfSets loads self_v4/self_v6 over netlink. They used to take one
// nft process per statement — two flushes, the static ranges, one add per
// local address — and on a node with large feed sets each nft process costs
// over a second (the CLI loads the whole ruleset, set elements included).
func (b *Backend) refreshSelfSets() {
	b.selfResolver.Refresh()
	v4, v6 := selfSetElems(b.selfResolver.LocalIPs())
	_ = b.ReplaceSetFlushAdd("self_v4", v4, nil) // logs its own failure
	_ = b.ReplaceSetFlushAdd("self_v6", v6, nil)
}

// selfSetElems is what self_v4/self_v6 hold: loopback, link-local and each
// local address, as CIDRs with overlaps merged. The sets are interval sets,
// which refuse overlapping elements, and a local link-local address lies
// inside fe80::/10.
func selfSetElems(local []string) (v4, v6 []string) {
	v4 = []string{"127.0.0.0/8"}
	v6 = []string{"::1/128", "fe80::/10"}
	for _, s := range local {
		ip := net.ParseIP(s)
		switch {
		case ip == nil:
		case ip.To4() != nil:
			v4 = append(v4, ip.To4().String()+"/32")
		default:
			v6 = append(v6, ip.String()+"/128")
		}
	}
	return feedutil.NormalizeCIDRsV4(v4), feedutil.NormalizeCIDRsV6(v6)
}

// applyBaseInputRules installs all permanent set-matching rules in the input chain.
// Each rule is added only if it is not already present (idempotent): one read
// of the chain, then the missing rules in one nft run (baseRulesScript).
// newChain says the chain was created by this EnsureBase, so it holds no rules
// yet. The error says the rules may be incomplete; they are best effort.
func (b *Backend) applyBaseInputRules(newChain bool) error {
	var ins, adds []string
	insertRule := func(expr string) { ins = append(ins, expr) }
	addRule := func(expr string) { adds = append(adds, expr) }

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
	addRule("jump flood")

	// Rules are only ever added, so an unread chain must not be taken for an
	// empty one — that would add every rule a second time — unless this
	// EnsureBase just created it: then it is empty, and leaving it so would
	// leave the node without its allow/block rules.
	chain, err := b.chainTextCLI("input")
	if err != nil && !newChain {
		err = fmt.Errorf("can't read the input chain, left as is: %w", err)
		logging.Logf("[nftlib] base input rules: %v", err)
		return err
	}
	stmts := baseRulesScript(chain, ins, adds)
	if len(stmts) == 0 {
		return nil
	}
	err = b.nftExec(strings.Join(stmts, "\n"))
	if err == nil {
		return nil
	}
	// Best effort, as before: a statement nft refuses mustn't keep the others
	// out. Re-read first — the run may have committed before failing (e.g.
	// killed at its timeout), and running the statements again would
	// duplicate them.
	runErr := fmt.Errorf("one nft run of %d statements failed: %s", len(stmts), errTail(err, 300))
	chain, err = b.chainTextCLI("input")
	if err != nil {
		err = fmt.Errorf("%v; can't re-read the input chain, left as is: %w", runErr, err)
		logging.Logf("[nftlib] base input rules: %v", err)
		return err
	}
	stmts = baseRulesScript(chain, ins, adds)
	logging.Logf("[nftlib] base input rules: %v; applying %d one by one", runErr, len(stmts))
	failed := 0
	for _, st := range stmts {
		if b.nftExec(st) != nil {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%v; %d of %d single statements failed too", runErr, failed, len(stmts))
	}
	return nil
}

// errTail is the end of err's message, where nft's own reason is (nftExec
// quotes the whole script before it), cut to at most n bytes.
func errTail(err error, n int) string {
	s := err.Error()
	if len(s) > n {
		s = "…" + s[len(s)-n:]
	}
	return s
}

// baseRulesScript returns the statements that install the rules the input
// chain (as `nft list chain` prints it) lacks: ins inserted at the top in the
// order given (each lands above the previous one), adds appended. A rule
// counts as present when the chain text contains it, the rules queued before
// it included — the same check the one-nft-process-per-rule version made
// against the chain as it grew.
func baseRulesScript(chain string, ins, adds []string) []string {
	norm := func(s string) string { return " " + strings.Join(strings.Fields(s), " ") + " " }
	have := norm(chain)
	missing := func(expr string) bool {
		if strings.Contains(have, norm(expr)) {
			return false
		}
		have += norm(expr)
		return true
	}
	var stmts []string
	for _, e := range ins {
		if missing(e) {
			stmts = append(stmts, "insert rule inet cfm input position 0 "+e)
		}
	}
	for _, e := range adds {
		if missing(e) {
			stmts = append(stmts, "add rule inet cfm input "+e)
		}
	}
	return stmts
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
	delete(b.appliedHash, name) // set is gone → its applied-content hash is stale
	return nil
}

func setShape(v6 bool, isNet bool) (nftables.SetDatatype, bool) {
	if v6 {
		return nftables.TypeIP6Addr, isNet
	}
	return nftables.TypeIPAddr, isNet
}

// FlushSet empties a named set in place. It used to delete and recreate the
// set, which the kernel refuses (EBUSY) for any set a rule references — and
// the sets `cfm flush` empties, block_v4/block_v6, always are. A missing
// table or set is a no-op.
func (b *Backend) FlushSet(family, table, set string) error {
	if !strings.EqualFold(family, "inet") || table != cfmTableName {
		return fmt.Errorf("nftlib: unsupported set path %s %s %s", family, table, set)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	ns, err := b.lookupSet(set)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("nftlib: flush set %s %s %s: %w", family, table, set, err)
	}
	b.conn.FlushSet(ns)
	if err := b.conn.Flush(); err != nil {
		if isNotFound(err) {
			b.invalidateCache()
			return nil
		}
		return fmt.Errorf("nftlib: flush set %s %s %s: %w", family, table, set, err)
	}
	delete(b.appliedHash, set) // set was just emptied → drop its applied-content hash
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
