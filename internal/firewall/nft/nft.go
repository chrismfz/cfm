//go:build linux

package nft

import (
	"bufio"
	"bytes"
	cfgpkg "cfm/internal/config"
	enrichpkg "cfm/internal/enrich"
	"cfm/internal/firewall"
	"cfm/internal/firewall/autoblock"
	"cfm/internal/firewall/feedutil"
	"cfm/internal/firewall/selfip"
	"cfm/internal/firewall/setprobe"
	"cfm/internal/logging"
	"cfm/internal/reporting"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// selfIPsLuaPath is the edge's snapshot of this server's own IPs (the Lua
// local-origin bypass reads it). A var, not a const, so a test binary can point
// it at a temp dir: EnsureBase refreshes it, and a test driving EnsureBase
// through a fake runner otherwise rewrote the LIVE file with test data.
var selfIPsLuaPath = "/var/lib/cfm/lua/cfm_self_ips.lua"

const (
	tableName = "cfm"
	family    = "inet"

	// Retired per-IP challenge DNAT set names — referenced only by the
	// one-shot legacy cleanup in EnsureBase.
	challengeV4 = "challenge_v4"
	challengeV6 = "challenge_v6"

	// manual
	setV4   = "block_v4"
	setV6   = "block_v6"
	allowV4 = "allow_v4"
	allowV6 = "allow_v6"
	// NEW: manual nets
	allowV4Nets = "allow_v4_nets"
	allowV6Nets = "allow_v6_nets"
	blockV4Nets = "block_v4_nets"
	blockV6Nets = "block_v6_nets"

	allowDynV4 = "allow_dyn_v4"
	allowDynV6 = "allow_dyn_v6"

	// Debug server: resolved API IPs (strictly for the debug port rules)
	debugAPIV4 = firewall.SetDebugAPIV4
	debugAPIV6 = firewall.SetDebugAPIV6

	// external (SPLIT: hosts vs nets)
	allowExtV4Hosts = "allow_ext_v4_hosts" // type ipv4_addr; flags timeout
	allowExtV6Hosts = "allow_ext_v6_hosts" // type ipv6_addr; flags timeout
	allowExtV4Nets  = "allow_ext_v4_nets"  // type ipv4_addr; flags timeout,interval
	allowExtV6Nets  = "allow_ext_v6_nets"  // type ipv6_addr; flags timeout,interval

	blockExtV4Hosts = "block_ext_v4_hosts"
	blockExtV6Hosts = "block_ext_v6_hosts"
	blockExtV4Nets  = "block_ext_v4_nets"
	blockExtV6Nets  = "block_ext_v6_nets"
)

type setDesc struct {
	name   string // π.χ. block_ext_v4_nets_dshield
	family string // "ip" ή "ip6"
	action string // "ALLOW" ή "BLOCK"
	scope  string // "hosts" ή "nets"
	feed   string // π.χ. "dshield", "myallow" (κενό για manual)
}

type extFeedData struct {
	H4  []string
	N4  []string
	H6  []string
	N6  []string
	TTL *time.Duration // optional; used only if you decide to honor per-feed TTLs in unions later
}

var debugEnv = os.Getenv("CFM_DEBUG") == "1"

type Backend struct {
	last map[string]uint64 // last seen packets per counter (for delta logging)
	cfg  *cfgpkg.Config

	enr      *enrichpkg.Enricher
	reporter reporting.Reporter
	cfgDir   string // resolve config dir

	pfSets   []string            // th_pf_<port>_<proto>_v4/v6
	clSets   []string            // th_connlimit_<port>_<proto>_v4/v6
	feedKeys map[string]struct{} // π.χ. {"dshield":{}, "abuseipdb":{}}

	// external feed element caches (so RebuildExternalUnions NEVER needs `nft -j list set`)
	extFeedMu sync.RWMutex
	extAllow  map[string]extFeedData // key -> elems
	extBlock  map[string]extFeedData // key -> elems

	// appliedHash is the content hash of the last successful ReplaceSetFlushAdd
	// of a PERMANENT set (the feed unions), so an unchanged hourly apply skips
	// the rewrite. Only a hint: the skip also asks the kernel for one of the
	// elements, so a set another process emptied or recreated is rewritten.
	appliedMu   sync.Mutex
	appliedHash map[string]uint64

	// cache of external ALLOW set names (per-feed), to avoid expensive table scans on every check
	extMu           sync.RWMutex
	extAllowCacheAt time.Time
	extAllowV4Hosts []string
	extAllowV4Nets  []string
	extAllowV6Hosts []string
	extAllowV6Nets  []string

	selfResolver *selfip.Resolver

	floodDumpMu      sync.Mutex
	floodDumpRunning bool
	lastFloodHash    uint64
	lastFloodRebuild time.Time
	// portscanSkipLogged throttles the "skipped this tick" line of
	// loadPortScannerOnce (guarded by abMu, which that function holds).
	portscanSkipLogged time.Time

	portScanMu      sync.Mutex
	portScanRunning bool

	// autoblock evaluator and per-IP debounce maps (moved from package-level vars).
	// abMu serialises ab, its Reasons and the debounce maps: the flood dump
	// (throttle) and the port scanner run in separate goroutines, started
	// together every tick, and both drive the one Evaluator — which is not
	// goroutine-safe — so they could write its maps at once ("concurrent map
	// writes" is fatal).
	abMu            sync.Mutex
	ab              *autoblock.Evaluator
	lastAutoBlockAt map[string]time.Time
	lastIgnoredAt   map[string]time.Time

	apiCacheMu         sync.Mutex
	apiCacheHost       string
	apiCacheV4         []string
	apiCacheV6         []string
	apiCacheResolvedAt time.Time
}

var _ firewall.Backend = (*Backend)(nil)
var _ firewall.DNATPriorityReporter = (*Backend)(nil)

// GetEnricher returns the enrichment engine (if enabled).
func (b *Backend) GetEnricher() *enrichpkg.Enricher {
	return b.enr
}

func (b *Backend) SetReporter(r reporting.Reporter) { b.reporter = r }

//func New() *Backend { return &Backend{} }

func New() *Backend {
	return &Backend{
		last:                 make(map[string]uint64),
		feedKeys:             make(map[string]struct{}),
		extAllow:             make(map[string]extFeedData),
		extBlock:             make(map[string]extFeedData),
		selfResolver:         selfip.New(),
		ab:                   autoblock.New(),
		lastAutoBlockAt:      make(map[string]time.Time),
		lastIgnoredAt:        make(map[string]time.Time),
	}
}

// cleanupLegacyChallengeDNAT sheds any state left behind by the retired
// per-IP challenge DNAT (challenge_v4/v6 sets, the challenge_guard chain's
// rules). Runs on every EnsureBase; after the first pass the existence probes
// miss and it is a cheap no-op. Tolerant of a missing table (fresh install).
func (b *Backend) cleanupLegacyChallengeDNAT() {
	if b == nil {
		return
	}
	if b.setExists(challengeV4) {
		_ = b.nftCmd(fmt.Sprintf(`flush set %s %s %s`, family, tableName, challengeV4))
		_ = b.nftCmd(fmt.Sprintf(`delete set %s %s %s`, family, tableName, challengeV4))
	}
	if b.setExists(challengeV6) {
		_ = b.nftCmd(fmt.Sprintf(`flush set %s %s %s`, family, tableName, challengeV6))
		_ = b.nftCmd(fmt.Sprintf(`delete set %s %s %s`, family, tableName, challengeV6))
	}
	if b.chainExists("challenge_guard") {
		_ = b.nftCmd(fmt.Sprintf(`flush chain %s %s challenge_guard`, family, tableName))
	}
}

func (b *Backend) logPhase(phase, status string, duration time.Duration, err error, extra string) {
	msg := fmt.Sprintf("[firewall] engine=nft phase=%s status=%s duration=%s", phase, status, duration)
	if err != nil {
		msg += fmt.Sprintf(" error=%q", err.Error())
	} else {
		msg += ` error=""`
	}
	if extra != "" {
		msg += " " + extra
	}
	logging.Logf("%s", msg)
}

// ReportBlock decides (based on config + source) whether to notify the API and then calls reporter.
// source: "detector" | "autoblock" | "manual"
// mode:   "ttl" | "permanent" | "dryrun"
func (b *Backend) ReportBlock(ip, comment, source, mode string, ttlSeconds int) error {
	if b == nil || b.reporter == nil || !firewall.ShouldReportBlock(b.cfg, source) {
		return nil
	}
	return b.reporter.ReportBlock(ip, comment, source, mode, ttlSeconds)
}

// ReportLenient forwards a lenient (per-server) block record. Honours the same
// global per-source report switches as ReportBlock; the lenient vs blacklist
// choice only selects the destination list once reporting is enabled.
func (b *Backend) ReportLenient(ip, comment, source, mode string, ttlSeconds int) error {
	if b == nil || b.reporter == nil || !firewall.ShouldReportBlock(b.cfg, source) {
		return nil
	}
	return b.reporter.ReportLenient(ip, comment, source, mode, ttlSeconds)
}

func (b *Backend) registerFeedKey(k string) {
	if b.feedKeys == nil {
		b.feedKeys = map[string]struct{}{}
	}
	b.feedKeys[k] = struct{}{}
}
func (b *Backend) unregisterFeedKey(k string) {
	if b.feedKeys == nil {
		return
	}
	delete(b.feedKeys, k)
}

func (b *Backend) cacheExternalFeed(isAllow bool, key string, h4, n4, h6, n6 []string, ttl *time.Duration) {
	b.extFeedMu.Lock()
	defer b.extFeedMu.Unlock()

	if b.extAllow == nil {
		b.extAllow = map[string]extFeedData{}
	}
	if b.extBlock == nil {
		b.extBlock = map[string]extFeedData{}
	}

	fd := extFeedData{H4: h4, N4: n4, H6: h6, N6: n6, TTL: ttl}
	if isAllow {
		b.extAllow[key] = fd
	} else {
		b.extBlock[key] = fd
	}
}

func (b *Backend) dropExternalFeedCache(key string) {
	b.extFeedMu.Lock()
	defer b.extFeedMu.Unlock()
	if b.extAllow != nil {
		delete(b.extAllow, key)
	}
	if b.extBlock != nil {
		delete(b.extBlock, key)
	}
}

func (b *Backend) registerPfSet(name string) {
	for _, s := range b.pfSets {
		if s == name {
			return
		}
	}
	b.pfSets = append(b.pfSets, name)
}
func (b *Backend) registerClSet(name string) {
	for _, s := range b.clSets {
		if s == name {
			return
		}
	}
	b.clSets = append(b.clSets, name)
}

// Προαιρετικός helper: ενεργοποιεί enrichment αν βρεθούν mmdb σε dirs
func (b *Backend) EnableEnrichment(dirs ...string) {
	if b == nil || b.enr != nil {
		return
	}
	if e, _ := enrichpkg.New(dirs...); e != nil {
		b.enr = e
	}
}

// (προαιρετικά) Setter αν θέλεις να το περνάς “έτοιμο”
func (b *Backend) SetEnricher(e *enrichpkg.Enricher) { b.enr = e }

func (b *Backend) SetConfigDir(dir string) { b.cfgDir = strings.TrimSpace(dir) }

// ---------- ensure base ----------

func (b *Backend) ensureSetWithFlags(name, typ, flags string) error {
	// Be robust/idempotent: try to create the set and ignore "already exists".
	// We've seen cases where setExists() can be misleading under concurrent
	// applies/resets; failing here later breaks rule insertion at @set.
	expr := fmt.Sprintf(`add set %s %s %s { type %s; flags %s; }`, family, tableName, name, typ, flags)
	out, err := b.nftOut(expr)
	if err == nil {
		return nil
	}
	// Common idempotent errors from nft when the set already exists.
	if strings.Contains(out, "File exists") || strings.Contains(out, "already exists") {
		return nil
	}
	// Fallback to old check as a last resort.
	if b.setExists(name) {
		return nil
	}
	return err
}

func (b *Backend) ensureSet(name, typ string) error {
	return b.ensureSetWithFlags(name, typ, "timeout")
}

// icmpFloodJumps send echo-requests through the flood chain when ICMP rate
// limiting is on.
var icmpFloodJumps = []string{
	`ip protocol icmp icmp type echo-request jump flood`,
	`ip6 nexthdr ipv6-icmp icmpv6 type echo-request jump flood`,
}

// inputChainReadTimeout bounds EnsureBase's read of the input chain's rules
// (~4 s idle on an EL8 node with large sets).
var inputChainReadTimeout = 30 * time.Second

// dedupeTimeout bounds the one-transaction delete of duplicate base rules:
// the runner's default plus 1 s per 1000 handles (mars held ~7,400).
func dedupeTimeout(n int) time.Duration {
	return defaultNFTCommandTimeout + time.Duration(n/1000)*time.Second
}

// baseEarlyRules is the top of the input chain, top-down: loopback, self,
// every allow set, every unconditional block set, then (ICMP rate limiting
// on) the ICMP jumps to flood.
func baseEarlyRules(icmpJumps bool) []string {
	early := []string{
		// 1) loopback
		`iif lo accept`,

		// 2) self IPs
		`ip saddr @self_v4 accept`,
		`ip6 saddr @self_v6 accept`,

		// 3) ALLOW sets (manual + dyn + external + nets)
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

		// 4) UNCONDITIONAL BLOCKS (must be above ICMP/conntrack/ports)
		`ip saddr @block_v4 drop`,
		`ip6 saddr @block_v6 drop`,
		`ip saddr @block_ext_v4_hosts drop`,
		`ip6 saddr @block_ext_v6_hosts drop`,
		`ip saddr @block_ext_v4_nets drop`,
		`ip6 saddr @block_ext_v6_nets drop`,
		`ip saddr @block_v4_nets drop`,
		`ip6 saddr @block_v6_nets drop`,
		`ip6 saddr @block_v6_clients drop`,
	}
	// 5) ICMP → flood (below unconditional drops)
	if icmpJumps {
		early = append(early, icmpFloodJumps...)
	}
	return early
}

// baseLateRules are appended after the early group, in this order (a rule
// the early group already holds reads present and is not added again).
var baseLateRules = []string{
	// Established/related from IPs already in a block set
	`ct state established,related ip saddr @block_v4 drop`,
	`ct state established,related ip6 saddr @block_v6 drop`,
	// External feeds — hosts & nets
	`ct state established,related ip saddr @block_ext_v4_hosts drop`,
	`ct state established,related ip saddr @block_ext_v4_nets drop`,
	`ct state established,related ip6 saddr @block_ext_v6_hosts drop`,
	`ct state established,related ip6 saddr @block_ext_v6_nets drop`,
	// Manual/aggregate nets
	`ct state established,related ip saddr @block_v4_nets drop`,
	`ct state established,related ip6 saddr @block_v6_nets drop`,
	`ct state established,related ip6 saddr @block_v6_clients drop`,
	// The general established/related accept, after the drops
	baseEstablishedAccept,
	// 1) manual allow
	`ip saddr @allow_v4 accept`,
	`ip6 saddr @allow_v6 accept`,
	// 2) dyn allow
	`ip saddr @allow_dyn_v4 accept`,
	`ip6 saddr @allow_dyn_v6 accept`,
	// 3) external allow (hosts, then nets)
	`ip saddr @allow_ext_v4_hosts accept`,
	`ip6 saddr @allow_ext_v6_hosts accept`,
	`ip saddr @allow_ext_v4_nets accept`,
	`ip6 saddr @allow_ext_v6_nets accept`,
	// 4) manual block
	`ip saddr @block_v4 drop`,
	`ip6 saddr @block_v6 drop`,
	// 5) external block (hosts, then nets)
	`ip saddr @block_ext_v4_hosts drop`,
	`ip6 saddr @block_ext_v6_hosts drop`,
	`ip saddr @block_ext_v4_nets drop`,
	`ip6 saddr @block_ext_v6_nets drop`,
	// manual block nets
	`ip saddr @block_v4_nets drop`,
	`ip6 saddr @block_v6_nets drop`,
}

// baseEstablishedAccept is also the ports policy's ruleEstablished, which it
// positions itself: never deduplicated here.
const baseEstablishedAccept = `ct state established,related accept`

// baseDedupeExprs is every base rule EnsureBase writes, each once, but the
// established accept: the ICMP jumps always (a copy left from when ICMP rate
// limiting was on is still a copy) and `jump flood`.
func baseDedupeExprs(early, late []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, group := range [][]string{early, icmpFloodJumps, late, {"jump flood"}} {
		for _, e := range group {
			if e == baseEstablishedAccept || seen[e] {
				continue
			}
			seen[e] = true
			out = append(out, e)
		}
	}
	return out
}

func (b *Backend) EnsureBase() (err error) {
	start := time.Now()
	b.logPhase("EnsureBase", "start", 0, nil, "")
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("EnsureBase", st, time.Since(start), err, "")
	}()
	// 1) Ensure table. `add table` is idempotent and costs one cheap nft run;
	// the existence probe it replaced (`list tables`) made nft load every set
	// element in the table first (~2 s with a large feed or TTL-ban set).
	if err := b.nftCmd(fmt.Sprintf("add table %s %s", family, tableName)); err != nil {
		return err
	}

	// desired priority (default -50; override από cfg)
	prio := -50
	if b.cfg != nil && b.cfg.NFT.InputPriority != 0 {
		prio = b.cfg.NFT.InputPriority
	}

	// 2) Ensure chains (input με σωστό priority, flood χωρίς hook)
	// One cheap read answers which chains exist and the input chain's hook
	// line (see chainExists); `nft list chain` costs 4-12 s apiece on EL8.
	chains, chainsOK := cfmChains()
	// A chain is NEW only when this run saw it absent: then the rule read
	// below may find it empty and every base rule is written. When the
	// listing could not be read the chains are declared anyway (`add chain`
	// is idempotent, so a cold boot still gets them), but the read guard
	// stays on: adding rules blind is how mars came to hold 268 copies.
	needCreate := chainsOK && !hasCFMChain(chains, "input")
	if chainsOK && !needCreate {
		if p, ok := hookPriority(chains["input"]); !ok || p != prio {
			// Do NOT silently destroy the input chain on a priority
			// mismatch — that leaves the server unprotected during recreate.
			// Log the discrepancy and leave the existing chain intact.
			// To migrate the priority deliberately, run: cfm reset && cfm daemon
			logging.Logf("[nft] WARNING: input chain priority mismatch (want %d, chain has %q). "+
				"Run 'cfm reset' to apply the new priority. Keeping existing chain.", prio, chains["input"])
		}
	}

	if needCreate || !chainsOK {
		if err := b.nftCmd(fmt.Sprintf(
			`add chain %s %s input { type filter hook input priority %d; policy accept; }`,
			family, tableName, prio,
		)); err != nil {
			if needCreate {
				return err
			}
			// Unlisted, the chain may exist with another priority, which nft
			// refuses to redeclare: keep it, as the mismatch check does.
			logging.Logf("[nft] EnsureBase: declaring the input chain blind failed (kept as is): %v", firstLine(err.Error()))
		}
	}
	if !chainsOK || !hasCFMChain(chains, "flood") {
		if err := b.nftCmd(fmt.Sprintf(`add chain %s %s flood`, family, tableName)); err != nil && chainsOK {
			return err
		}
	}

	// 3) Ensure sets (manual/dyn/external + throttling)
	// manual allow/block
	if err := b.ensureSet(allowV4, "ipv4_addr"); err != nil {
		return err
	}
	if err := b.ensureSet(allowV6, "ipv6_addr"); err != nil {
		return err
	}
	if err := b.ensureSet(setV4, "ipv4_addr"); err != nil {
		return err
	}
	if err := b.ensureSet(setV6, "ipv6_addr"); err != nil {
		return err
	}
	// NEW: manual nets (for CIDR)
	if err := b.ensureSetWithFlags(allowV4Nets, "ipv4_addr", "timeout,interval"); err != nil {
		return err
	}
	if err := b.ensureSetWithFlags(allowV6Nets, "ipv6_addr", "timeout,interval"); err != nil {
		return err
	}
	if err := b.ensureSetWithFlags(blockV4Nets, "ipv4_addr", "timeout,interval"); err != nil {
		return err
	}
	if err := b.ensureSetWithFlags(blockV6Nets, "ipv6_addr", "timeout,interval"); err != nil {
		return err
	}
	// The automatic IPv6 client /64 bans (firewall/client_block.go): their
	// own set, so they never collide with the operator's CIDRs above.
	if err := b.ensureSetWithFlags(firewall.BlockV6Clients, "ipv6_addr", "timeout,interval"); err != nil {
		return err
	}

	// NEW: ignore (manual) hosts + nets
	if err := b.ensureSetWithFlags("ignore_v4", "ipv4_addr", "timeout"); err != nil {
		return err
	}
	if err := b.ensureSetWithFlags("ignore_v6", "ipv6_addr", "timeout"); err != nil {
		return err
	}
	if err := b.ensureSetWithFlags("ignore_v4_nets", "ipv4_addr", "timeout,interval"); err != nil {
		return err
	}
	if err := b.ensureSetWithFlags("ignore_v6_nets", "ipv6_addr", "timeout,interval"); err != nil {
		return err
	}

	// local and server-IPs
	if err := b.ensureSetWithFlags("self_v4", "ipv4_addr", "timeout,interval"); err != nil {
		return err
	}
	if err := b.ensureSetWithFlags("self_v6", "ipv6_addr", "timeout,interval"); err != nil {
		return err
	}
	// quickly load our self-IPs
	b.refreshSelfSets()

	// dyn allow
	if err := b.ensureSet(allowDynV4, "ipv4_addr"); err != nil {
		return err
	}
	if err := b.ensureSet(allowDynV6, "ipv6_addr"); err != nil {
		return err
	}
	// debug-only API sets (hosts)
	if err := b.ensureSet(debugAPIV4, "ipv4_addr"); err != nil {
		return err
	}
	if err := b.ensureSet(debugAPIV6, "ipv6_addr"); err != nil {
		return err
	}
	// external allow (hosts/nets)
	if err := b.ensureSetWithFlags(allowExtV4Hosts, "ipv4_addr", "timeout"); err != nil {
		return err
	}
	if err := b.ensureSetWithFlags(allowExtV6Hosts, "ipv6_addr", "timeout"); err != nil {
		return err
	}
	if err := b.ensureSetWithFlags(allowExtV4Nets, "ipv4_addr", "timeout,interval"); err != nil {
		return err
	}
	if err := b.ensureSetWithFlags(allowExtV6Nets, "ipv6_addr", "timeout,interval"); err != nil {
		return err
	}
	// external block (hosts/nets)
	if err := b.ensureSetWithFlags(blockExtV4Hosts, "ipv4_addr", "timeout"); err != nil {
		return err
	}
	if err := b.ensureSetWithFlags(blockExtV6Hosts, "ipv6_addr", "timeout"); err != nil {
		return err
	}
	if err := b.ensureSetWithFlags(blockExtV4Nets, "ipv4_addr", "timeout,interval"); err != nil {
		return err
	}
	if err := b.ensureSetWithFlags(blockExtV6Nets, "ipv6_addr", "timeout,interval"); err != nil {
		return err
	}
	// throttling sets (per-reason και aggregate)
	_ = b.ensureSetWithFlags("th_syn_v4", "ipv4_addr", "timeout")
	_ = b.ensureSetWithFlags("th_syn_v6", "ipv6_addr", "timeout")
	_ = b.ensureSetWithFlags("th_pps_v4", "ipv4_addr", "timeout")
	_ = b.ensureSetWithFlags("th_pps_v6", "ipv6_addr", "timeout")
	_ = b.ensureSetWithFlags("th_pf_tcp_v4", "ipv4_addr", "timeout")
	_ = b.ensureSetWithFlags("th_pf_tcp_v6", "ipv6_addr", "timeout")
	_ = b.ensureSetWithFlags("th_pf_udp_v4", "ipv4_addr", "timeout")
	_ = b.ensureSetWithFlags("th_pf_udp_v6", "ipv6_addr", "timeout")
	_ = b.ensureSetWithFlags("throttled_v4", "ipv4_addr", "timeout")
	_ = b.ensureSetWithFlags("throttled_v6", "ipv6_addr", "timeout")

	// Shed retired per-IP challenge-DNAT state (sets/chain left behind by
	// pre-edge-unification versions); no-op once clean.
	b.cleanupLegacyChallengeDNAT()

	// 4) Base allow/deny rules (idempotent, σταθερή σειρά)
	// NOTE: querying `nft list chain ...` repeatedly can become very expensive on
	// large installations. Cache the input chain snapshot once and keep it updated
	// as we add/insert rules during this EnsureBase run.
	// This read is the one EnsureBase cannot make cheap: on EL8's nft 1.0.4 any
	// `list chain` loads every set element (~4 s on mars, idle), so it gets a
	// deadline of its own. If it fails, the rules are NOT taken for absent:
	// an unread chain used to read as empty, so every base rule was added
	// again, and the per-tick re-runs left ~268 copies of each on mars (141
	// on earth and virgo). A chain this run just created is empty for sure.
	readCtx, readCancel := context.WithTimeout(context.Background(), inputChainReadTimeout)
	resInput, readErr := runNFTCommand(readCtx, "-a", "list", "chain", family, tableName, "input")
	readCancel()
	if readErr != nil && !needCreate {
		logging.Logf("[nft] EnsureBase: cannot read the input chain (%v); its base rules are left as they are, unchecked (adding them blind would duplicate every one)", firstLine(readErr.Error()))
		return nil
	}
	inputRules := firewall.ParseChainRules(resInput.Stdout)
	ruleInInput := inputRules.Present
	recordRuleInInput := inputRules.Add

	// The early group, top-down (inserted in reverse below), and the late
	// group, appended in order. Each base rule is wanted exactly once.
	early := baseEarlyRules(b.cfg != nil && b.cfg.Hardening.ICMPRate > 0)
	late := baseLateRules

	// Drop the copies earlier versions piled up, keeping the top-most of each
	// (the one the base order wants): the old presence check never recognised
	// `iif lo accept` (nft prints `iif "lo" accept`), and an unread chain added
	// every rule again (above). One transaction: a packet sees all the copies
	// or one, never none. `ct state established,related accept` is left to the
	// ports policy, which positions its own copy (firewall.PortsPolicyScript).
	if dups := inputRules.DuplicateHandles(baseDedupeExprs(early, late)...); len(dups) > 0 {
		var sb strings.Builder
		for _, h := range dups {
			fmt.Fprintf(&sb, "delete rule %s %s input handle %s\n", family, tableName, h)
		}
		ctx, cancel := context.WithTimeout(context.Background(), dedupeTimeout(len(dups)))
		err := b.nftExprCtx(ctx, strings.TrimSpace(sb.String()))
		cancel()
		if err != nil {
			logging.Logf("[nft] EnsureBase: removing %d duplicate base rules failed: %v", len(dups), firstLine(err.Error()))
		} else {
			logging.Logf("[nft] EnsureBase: removed %d duplicate base rules", len(dups))
			inputRules.Forget(dups)
		}
	}

	// A rule written after the rest (firewall.BaseRuleAnchors) goes right
	// after its anchor on a chain that already holds it: an insert at 0
	// would put it above the self / allow accepts, an append below the ports
	// policy's accepts.
	place := func(expr, otherwise string) string {
		if h := inputRules.AnchorHandle(expr); h != "" {
			return fmt.Sprintf(`add rule %s %s input position %s %s`, family, tableName, h, expr)
		}
		return otherwise
	}
	addRule := func(expr string) error {
		if ruleInInput(expr) {
			return nil
		}
		if err := b.nftCmd(place(expr, fmt.Sprintf(`add rule %s %s input %s`, family, tableName, expr))); err != nil {
			return err
		}
		recordRuleInInput(expr)
		return nil
	}

	// --- EARLY RULES (insert in reverse so final order is top-down) ---

	// helper stays the same
	addEarly := func(expr string) {
		if ruleInInput(expr) {
			return
		}
		if err := b.nftCmd(place(expr, fmt.Sprintf(`insert rule %s %s input position 0 %s`, family, tableName, expr))); err == nil {
			recordRuleInInput(expr)
		}
	}

	// Insert in reverse so first item ends up highest in chain
	for i := len(early) - 1; i >= 0; i-- {
		addEarly(early[i])
	}

	for _, expr := range late {
		if err := addRule(expr); err != nil {
			return err
		}
	}

	// 6) jump flood στο τέλος του base layer. The presence check matches it as a
	// whole rule, not inside the ICMP jumps above (which, as a substring, kept
	// it out whenever ICMP rate limiting was on and the chain was new).
	if !ruleInInput("jump flood") {
		if err := b.nftCmd(fmt.Sprintf(`add rule %s %s input jump flood`, family, tableName)); err != nil {
			return err
		}
		recordRuleInInput("jump flood")
	}

	//moved to ports.go
	// if err := addRule(`ct state invalid drop`); err != nil { return err }

	return nil
}

// refreshAPISets resolves cfg.API.URL (hostname in API_URL), populating debug_api_v4 / debug_api_v6.
// No-op if URL is empty, invalid, or resolution fails. Best-effort.
// Notes: We don’t add these sets to the global “ALLOW” early rules, so the API doesn’t get blanket access to other services.
// Only the debug port rules (below) will consult these sets.
const apiDNSCacheTTL = 5 * time.Minute

func (b *Backend) refreshAPISets() {
	if b.cfg == nil || strings.TrimSpace(b.cfg.API.URL) == "" {
		_ = b.nftExpr("flush set inet cfm " + debugAPIV4 + ";")
		_ = b.nftExpr("flush set inet cfm " + debugAPIV6 + ";")
		return
	}
	u := strings.TrimSpace(b.cfg.API.URL)
	host := u
	if strings.Contains(u, "://") {
		if parsed, err := url.Parse(u); err == nil && parsed != nil {
			host = parsed.Hostname()
		}
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return
	}

	// Issue 5: only re-resolve DNS every 5 minutes, or when the host changes.
	b.apiCacheMu.Lock()
	cacheValid := host == b.apiCacheHost &&
		time.Since(b.apiCacheResolvedAt) < apiDNSCacheTTL
	v4s := b.apiCacheV4
	v6s := b.apiCacheV6
	b.apiCacheMu.Unlock()

	if !cacheValid {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			// Keep stale cache on transient DNS failure — don't flush the sets.
			return
		}
		var newV4, newV6 []string
		for _, ip := range ips {
			if v := ip.To4(); v != nil {
				newV4 = append(newV4, v.String())
			} else {
				newV6 = append(newV6, ip.String())
			}
		}
		b.apiCacheMu.Lock()
		b.apiCacheHost = host
		b.apiCacheV4 = newV4
		b.apiCacheV6 = newV6
		b.apiCacheResolvedAt = time.Now()
		v4s = newV4
		v6s = newV6
		b.apiCacheMu.Unlock()
	}

	// Only rewrite the sets when we have a fresh resolve (cacheValid == false)
	// or on first call. Avoids redundant nft writes every 20s tick.
	if cacheValid {
		return
	}

	_ = b.nftExpr("flush set inet cfm " + debugAPIV4 + ";")
	_ = b.nftExpr("flush set inet cfm " + debugAPIV6 + ";")
	for _, ip := range v4s {
		_ = b.nftExpr("add element inet cfm " + debugAPIV4 + " { " + ip + " };")
	}
	for _, ip := range v6s {
		_ = b.nftExpr("add element inet cfm " + debugAPIV6 + " { " + ip + " };")
	}
}

// -------- block (manual) --------

// AddBlock replaces whatever block the address has (the manual path; the
// automatic one is firewall.ExtendBlock). It holds hostBatchMu like the
// batches: unserialised, its delete + add could land between a batch's read
// and write, and the batch's replace would then cut a permanent ban to its TTL.
func (b *Backend) AddBlock(ip net.IP, _ string, ttl *time.Duration) error {
	if ip == nil {
		return errors.New("nil ip")
	}
	hostBatchMu.Lock()
	defer hostBatchMu.Unlock()
	set := setV4
	if ip.To4() == nil {
		set = setV6
	}
	elem := ip.String()

	_ = b.removeBlockLocked(ip)

	ttlStr := ""
	if ttl != nil && *ttl > 0 {
		ttlStr = humanTimeout(*ttl) // 90s / 5m / 1h
	}

	out, err := b.nftAddElementArgv(set, elem, ttlStr)
	if err == nil {
		return nil
	}
	if strings.Contains(out, "already exists") || strings.Contains(out, "File exists") {
		_ = b.removeBlockLocked(ip)
		if out2, err2 := b.nftAddElementArgv(set, elem, ttlStr); err2 == nil {
			return nil
		} else {
			return fmt.Errorf("nft add element (retry) failed: %v: %s", err2, out2)
		}
	}
	return fmt.Errorf("nft add element failed: %v: %s", err, out)
}

func (b *Backend) RemoveBlock(ip net.IP) error {
	if ip == nil {
		return errors.New("nil ip")
	}
	hostBatchMu.Lock()
	defer hostBatchMu.Unlock()
	return b.removeBlockLocked(ip)
}

// CreateBlock blocks ip for ttl only if no block holds it: one exclusive
// `create element`. exists reports a block already there, left as it is
// (its length unknown). firewall.ExtendBlock's fallback when the set can't
// be read: unlike AddBlock it never shortens a ban.
func (b *Backend) CreateBlock(ip net.IP, ttl time.Duration) (exists bool, err error) {
	if ip == nil || ip.IsUnspecified() || ttl <= 0 {
		return false, fmt.Errorf("not blockable: %v for %s", ip, ttl)
	}
	// humanTimeout prints anything under a second as "0s", which nft takes
	// as no timeout: a permanent ban. One second, as SplitBlockEntries does.
	if ttl < time.Second {
		ttl = time.Second
	}
	set := setV4
	if ip.To4() == nil {
		set = setV6
	}
	hostBatchMu.Lock()
	defer hostBatchMu.Unlock()
	res, err := runNFTCommand(context.Background(), "create", "element", family, tableName, set,
		"{ "+ip.String()+" timeout "+humanTimeout(ttl)+" }")
	if err == nil {
		return false, nil
	}
	if out := res.Stdout + res.Stderr; strings.Contains(out, "File exists") || strings.Contains(out, "already exists") {
		return true, nil
	}
	return false, &nftBatchError{msg: nftFirstError(res.Stdout+res.Stderr, err), err: err}
}

// removeBlockLocked is RemoveBlock under hostBatchMu.
func (b *Backend) removeBlockLocked(ip net.IP) error {
	set := setV4
	elem := ip.String()
	if ip.To4() == nil {
		set = setV6
	}
	cmd := fmt.Sprintf(`delete element %s %s %s { %s }`, family, tableName, set, elem)
	out, err := b.nftOut(cmd)
	if err != nil && !missingElement(out) {
		return fmt.Errorf("nft: %v: %s", err, out)
	}
	return nil
}

func (b *Backend) ListBlocks() ([]firewall.BlockedEntry, error) {
	var outAll []firewall.BlockedEntry
	sets := []struct {
		name string
		v6   bool
	}{{setV4, false}, {setV6, true}}
	for _, s := range sets {
		if ents, ok := b.listSetJSON_robust(s.name); ok {
			outAll = append(outAll, ents...)
			continue
		}
		if ents, ok := b.listSetText(s.name, s.v6); ok {
			outAll = append(outAll, ents...)
		}
	}
	return outAll, nil
}

// -------- allow (manual) --------

func (b *Backend) AddAllow(ip net.IP, ttl *time.Duration) error {
	if ip == nil {
		return errors.New("nil ip")
	}
	set := allowV4
	if ip.To4() == nil {
		set = allowV6
	}
	elem := ip.String()

	_ = b.RemoveAllow(ip)

	ttlStr := ""
	if ttl != nil && *ttl > 0 {
		ttlStr = humanTimeout(*ttl)
	}
	out, err := b.nftAddElementArgv(set, elem, ttlStr)
	if err == nil {
		return nil
	}
	if strings.Contains(out, "already exists") || strings.Contains(out, "File exists") {
		_ = b.RemoveAllow(ip)
		if out2, err2 := b.nftAddElementArgv(set, elem, ttlStr); err2 == nil {
			return nil
		} else {
			return fmt.Errorf("nft add allow (retry) failed: %v: %s", err2, out2)
		}
	}
	return fmt.Errorf("nft add allow failed: %v: %s", err, out)
}

// -------- ignore (manual) --------
func (b *Backend) AddIgnore(ip net.IP, ttl *time.Duration) error {
	if ip == nil {
		return errors.New("nil ip")
	}
	set := "ignore_v4"
	if ip.To4() == nil {
		set = "ignore_v6"
	}
	_ = b.RemoveIgnore(ip)
	ttlStr := ""
	if ttl != nil && *ttl > 0 {
		ttlStr = humanTimeout(*ttl)
	}
	out, err := b.nftAddElementArgv(set, ip.String(), ttlStr)
	if err == nil {
		return nil
	}
	if strings.Contains(out, "already exists") || strings.Contains(out, "File exists") {
		_ = b.RemoveIgnore(ip)
		if _, err2 := b.nftAddElementArgv(set, ip.String(), ttlStr); err2 == nil {
			return nil
		}
	}
	return fmt.Errorf("nft add ignore failed: %v: %s", err, out)
}
func (b *Backend) RemoveIgnore(ip net.IP) error {
	if ip == nil {
		return errors.New("nil ip")
	}
	set := "ignore_v4"
	if ip.To4() == nil {
		set = "ignore_v6"
	}
	cmd := fmt.Sprintf(`delete element %s %s %s { %s }`, family, tableName, set, ip.String())
	out, err := b.nftOut(cmd)
	if err != nil && !missingElement(out) {
		return fmt.Errorf("nft: %v: %s", err, out)
	}
	return nil
}
func (b *Backend) AddIgnoreNet(cidr string, ttl *time.Duration) error {
	canon, v6, err := canonCIDR(cidr)
	if err != nil {
		return err
	}
	set := "ignore_v4_nets"
	if v6 {
		set = "ignore_v6_nets"
	}
	_ = b.RemoveIgnoreNet(canon)
	ttlStr := ""
	if ttl != nil && *ttl > 0 {
		ttlStr = humanTimeout(*ttl)
	}
	if out, err := b.nftAddElementArgv(set, canon, ttlStr); err != nil && !strings.Contains(out, "already exists") {
		return fmt.Errorf("nft add ignore net failed: %v: %s", err, out)
	}
	return nil
}
func (b *Backend) RemoveIgnoreNet(cidr string) error {
	canon, v6, err := canonCIDR(cidr)
	if err != nil {
		return err
	}
	set := "ignore_v4_nets"
	if v6 {
		set = "ignore_v6_nets"
	}
	cmd := fmt.Sprintf(`delete element %s %s %s { %s }`, family, tableName, set, canon)
	out, err2 := b.nftOut(cmd)
	if err2 != nil && !missingElement(out) {
		return fmt.Errorf("nft: %v: %s", err2, out)
	}
	return nil
}

func (b *Backend) RemoveAllow(ip net.IP) error {
	if ip == nil {
		return errors.New("nil ip")
	}
	set := allowV4
	elem := ip.String()
	if ip.To4() == nil {
		set = allowV6
	}
	cmd := fmt.Sprintf(`delete element %s %s %s { %s }`, family, tableName, set, elem)
	out, err := b.nftOut(cmd)
	if err != nil && !missingElement(out) {
		return fmt.Errorf("nft: %v: %s", err, out)
	}
	return nil
}

// missingElement reports nft's output for a delete of an element the set
// does not hold, which every Remove* takes as done: "No such file or
// directory" for a host set, "Could not delete element", and "element does
// not exist" for an interval set (nft 1.0.4 on EL8 and 1.0.9 on EL9 alike,
// checked 2026-11-19: before it was matched, every remove of a CIDR the set
// did not hold failed).
func missingElement(out string) bool {
	return strings.Contains(out, "No such file or directory") ||
		strings.Contains(out, "Could not delete element") ||
		strings.Contains(out, "element does not exist")
}

// -------- manual nets (CIDR) --------

func canonCIDR(s string) (cidr string, v6 bool, err error) {
	ip, nw, e := net.ParseCIDR(strings.TrimSpace(s))
	if e != nil || ip == nil || nw == nil {
		return "", false, fmt.Errorf("invalid cidr: %s", s)
	}
	// canonical string "ip/mask"
	nw.IP = ip.Mask(nw.Mask)
	return nw.String(), ip.To4() == nil, nil
}

func (b *Backend) AddBlockNet(cidr string, ttl *time.Duration) error {
	canon, v6, err := canonCIDR(cidr)
	if err != nil {
		return err
	}
	set := blockV4Nets
	if v6 {
		set = blockV6Nets
	}
	ttlStr := ""
	if ttl != nil && *ttl > 0 {
		ttlStr = humanTimeout(*ttl)
	}
	// best-effort: first delete, then add
	_ = b.RemoveBlockNet(canon)
	if out, err := b.nftAddElementArgv(set, canon, ttlStr); err != nil {
		if !strings.Contains(out, "already exists") {
			return fmt.Errorf("nft add element failed: %v: %s", err, out)
		}
	}
	return nil
}

func (b *Backend) RemoveBlockNet(cidr string) error {
	canon, v6, err := canonCIDR(cidr)
	if err != nil {
		return err
	}
	set := blockV4Nets
	if v6 {
		set = blockV6Nets
	}
	cmd := fmt.Sprintf(`delete element %s %s %s { %s }`, family, tableName, set, canon)
	out, err2 := b.nftOut(cmd)
	if err2 != nil && !missingElement(out) {
		return fmt.Errorf("nft: %v: %s", err2, out)
	}
	return nil
}

func (b *Backend) AddAllowNet(cidr string, ttl *time.Duration) error {
	canon, v6, err := canonCIDR(cidr)
	if err != nil {
		return err
	}
	set := allowV4Nets
	if v6 {
		set = allowV6Nets
	}
	ttlStr := ""
	if ttl != nil && *ttl > 0 {
		ttlStr = humanTimeout(*ttl)
	}
	_ = b.RemoveAllowNet(canon)
	if out, err := b.nftAddElementArgv(set, canon, ttlStr); err != nil {
		if !strings.Contains(out, "already exists") {
			return fmt.Errorf("nft add element failed: %v: %s", err, out)
		}
	}
	return nil
}

func (b *Backend) RemoveAllowNet(cidr string) error {
	canon, v6, err := canonCIDR(cidr)
	if err != nil {
		return err
	}
	set := allowV4Nets
	if v6 {
		set = allowV6Nets
	}
	cmd := fmt.Sprintf(`delete element %s %s %s { %s }`, family, tableName, set, canon)
	out, err2 := b.nftOut(cmd)
	if err2 != nil && !missingElement(out) {
		return fmt.Errorf("nft: %v: %s", err2, out)
	}
	return nil
}

func (b *Backend) ListAllows() ([]firewall.BlockedEntry, error) {
	var outAll []firewall.BlockedEntry
	sets := []struct {
		name string
		v6   bool
	}{{allowV4, false}, {allowV6, true}}
	for _, s := range sets {
		if ents, ok := b.listSetJSON_robust(s.name); ok {
			outAll = append(outAll, ents...)
			continue
		}
		if ents, ok := b.listSetText(s.name, s.v6); ok {
			outAll = append(outAll, ents...)
		}
	}
	return outAll, nil
}

// -------- listing helpers (JSON + text fallback) --------

func (b *Backend) listSetJSON_robust(setName string) ([]firewall.BlockedEntry, bool) {
	res, err := runNFTCommand(context.Background(), "-j", "list", "set", family, tableName, setName)
	raw := []byte(res.Stdout + res.Stderr)
	if err != nil {
		return nil, false
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, false
	}
	nftables, _ := root["nftables"].([]any)
	if len(nftables) == 0 {
		return nil, false
	}

	var out []firewall.BlockedEntry
	parseSeconds := func(m map[string]any, key string) int {
		if m == nil {
			return 0
		}
		switch v := m[key].(type) {
		case float64:
			if v > 0 {
				return int(v)
			}
		case int:
			if v > 0 {
				return v
			}
		case string:
			s := strings.TrimSpace(v)
			if strings.HasSuffix(s, "s") {
				if n, err := strconv.Atoi(strings.TrimSuffix(s, "s")); err == nil && n > 0 {
					return n
				}
			} else if n, err := strconv.Atoi(s); err == nil && n > 0 {
				return n
			}
		}
		return 0
	}

	for _, item := range nftables {
		m, _ := item.(map[string]any)
		setObj, _ := m["set"].(map[string]any)
		if setObj == nil {
			continue
		}
		arr, _ := setObj["elem"].([]any)
		if len(arr) == 0 {
			arr, _ = setObj["elements"].([]any)
		}
		if len(arr) == 0 {
			continue
		}
		for _, e := range arr {
			switch v := e.(type) {
			case string:
				if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
					out = append(out, firewall.BlockedEntry{IP: ip})
				}
			case map[string]any:
				var elemIP string
				var seconds int
				if inner, ok := v["elem"].(map[string]any); ok {
					// host entry
					elemIP = toStr(inner["val"])
					if s := parseSeconds(inner, "expires"); s > 0 {
						seconds = s
					} else {
						seconds = parseSeconds(inner, "timeout")
					}
				} else {
					// older/other formats
					elemIP = toStr(v["elem"])
					if s := parseSeconds(v, "expires"); s > 0 {
						seconds = s
					} else {
						seconds = parseSeconds(v, "timeout")
					}
				}
				ip := net.ParseIP(strings.TrimSpace(elemIP))
				if ip == nil {
					continue
				}
				var exp *time.Time
				if seconds > 0 {
					t := time.Now().Add(time.Duration(seconds) * time.Second)
					exp = &t
				}
				out = append(out, firewall.BlockedEntry{IP: ip, Expires: exp})
			}
		}
	}
	return out, len(out) > 0
}

func toStr(x any) string {
	switch t := x.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprintf("%v", t)
	}
}

func (b *Backend) listSetText(setName string, v6 bool) ([]firewall.BlockedEntry, bool) {
	res, err := runNFTCommand(context.Background(), "list", "set", family, tableName, setName)
	raw := []byte(res.Stdout + res.Stderr)
	if err != nil {
		return nil, false
	}
	s := string(raw)
	start := strings.Index(s, "elements = {")
	if start == -1 {
		return nil, false
	}
	end := strings.Index(s[start:], "}")
	if end == -1 {
		return nil, false
	}
	inner := s[start+len("elements = {") : start+end]
	toks := strings.Split(inner, ",")
	var out []firewall.BlockedEntry
	reV4 := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reV6 := regexp.MustCompile(`\b[0-9a-fA-F:]+::?[0-9a-fA-F:]*\b`)

	for _, t := range toks {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		var ipStr string
		if v6 {
			ipStr = reV6.FindString(t)
		} else {
			ipStr = reV4.FindString(t)
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		var exp *time.Time
		if i := strings.Index(t, "timeout "); i != -1 {
			part := strings.TrimSpace(t[i+len("timeout "):])
			if j := strings.Index(part, "s"); j != -1 {
				if n, err := strconv.Atoi(strings.TrimSpace(part[:j])); err == nil && n > 0 {
					tt := time.Now().Add(time.Duration(n) * time.Second)
					exp = &tt
				}
			}
		}
		out = append(out, firewall.BlockedEntry{IP: ip, Expires: exp})
	}
	return out, len(out) > 0
}

// -------- shell helpers --------

// tableState is what a probe of table inet cfm found. Unknown is its own
// answer: a probe that timed out (the nft runs share four slots, and the wait
// for one counts against the deadline) or failed says nothing about the
// table, and must not start a repair (see the repair callers).
type tableState int

const (
	tableUnknown tableState = iota
	tablePresent
	tableAbsent
)

// tableProbeTimeout bounds each probe run, the wait for an nft slot included.
var tableProbeTimeout = 5 * time.Second

// probeTable asks nft whether table inet cfm exists. It reads `nft list chains
// inet`, which prints each inet table's header (`table inet cfm {`) with only
// its chains, in ~5 ms. `list tables`, which gives the same answer, makes nft
// load every set element of every table first (~2 s per call on a node with
// large feed / TTL-ban sets), and its 5 s deadline, slot wait included, ran
// out on loaded nodes: the timeout read as "no table", and the per-tick
// portscan load re-ran EnsureBase every minute or two all day. `list tables`
// now only answers when the cheap listing fails for a reason other than its
// deadline (an nft that refuses it), with a deadline of its own.
func (b *Backend) probeTable() tableState {
	if st, timedOut := probeTableWith("list", "chains", family); st != tableUnknown || timedOut {
		return st
	}
	st, _ := probeTableWith("list", "tables")
	return st
}

// probeTableWith runs one listing under its own deadline: present / absent
// from the listing, unknown (and whether the deadline ran out) on any error.
func probeTableWith(args ...string) (tableState, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), tableProbeTimeout)
	defer cancel()
	res, err := runNFTCommand(ctx, args...)
	if err != nil {
		return tableUnknown, ctx.Err() != nil
	}
	if listingHasCFMTable(res.Stdout) {
		return tablePresent, false
	}
	return tableAbsent, false
}

// tableExists reports whether nft says table inet cfm exists: false for both
// absent and unknown (the CLI's "not present" gate). A caller that would
// REPAIR on false (EnsureBase, a flush, a delete) asks probeTable instead and
// acts only on tableAbsent.
func (b *Backend) tableExists() bool {
	return b.probeTable() == tablePresent
}

// listingHasCFMTable finds the `table inet cfm` header line in an nft
// listing (`list tables` prints it bare, `list chains` with " {").
func listingHasCFMTable(out string) bool {
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		ln = strings.TrimSpace(strings.TrimSuffix(ln, "{"))
		if ln == "table "+family+" "+tableName {
			return true
		}
	}
	return false
}

func TableExistsCFM() bool {
	var b Backend
	return b.tableExists()
}

// chainExists reports whether table inet cfm has the chain. It reads `nft
// list chains inet` (3-10 ms on every fleet node): `nft list chain inet cfm
// <chain>`, which it used, makes nft 1.0.4 (EL8) load every set element first
// (4-12 s per call on mars, even for a chain that does not exist), and its 5 s
// deadline then read a present chain as missing. The old listing answers only
// when the cheap one fails.
func (b *Backend) chainExists(chain string) bool {
	if chains, ok := cfmChains(); ok {
		_, has := chains[chain]
		return has
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := runNFTCommand(ctx, "list", "chain", family, tableName, chain)
	return err == nil
}

// cfmChains reads table inet cfm's chains from `nft list chains inet`: each
// chain's name, mapped to its hook line ("type filter hook input priority
// -50; policy accept;"), or "" for a regular chain. ok is false when the
// listing could not be read; a table that is absent reads as no chains.
func cfmChains() (map[string]string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), tableProbeTimeout)
	defer cancel()
	res, err := runNFTCommand(ctx, "list", "chains", family)
	if err != nil {
		return nil, false
	}
	return parseCFMChains(res.Stdout), true
}

// parseCFMChains is cfmChains' parser: the chains inside the `table inet cfm
// {` block only (another table may have a chain of the same name).
func parseCFMChains(out string) map[string]string {
	chains := map[string]string{}
	inTable, chain := false, ""
	for _, ln := range strings.Split(out, "\n") {
		t := ln
		if i := strings.Index(t, " # "); i >= 0 && !strings.Contains(t[:i], `"`) {
			t = t[:i] // `-a` prints "chain input { # handle 1"
		}
		t = strings.TrimSpace(t)
		switch {
		case strings.HasPrefix(t, "table "):
			inTable = strings.TrimSpace(strings.TrimSuffix(t, "{")) == "table "+family+" "+tableName
			chain = ""
		case !inTable:
		case strings.HasPrefix(t, "chain ") && strings.HasSuffix(t, "{"):
			chain = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(t, "chain "), "{"))
			chains[chain] = ""
		case t == "}":
			if chain != "" {
				chain = ""
			} else {
				inTable = false
			}
		case chain != "" && strings.Contains(t, " hook "):
			chains[chain] = t
		}
	}
	return chains
}

func hasCFMChain(chains map[string]string, name string) bool {
	_, ok := chains[name]
	return ok
}

// hookPriorities are the names nft prints for the filter-family hook
// priorities, in place of their numbers.
var hookPriorities = map[string]int{"raw": -300, "mangle": -150, "dstnat": -100, "filter": 0, "security": 50, "srcnat": 100}

// hookPriority reads the priority of a hook line as a number. nft prints it
// as a number (-50), a name (filter) or a name with an offset (filter + 10,
// filter - 5); ok is false when there is none it can read.
func hookPriority(hook string) (int, bool) {
	i := strings.Index(hook, "priority ")
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(strings.TrimSpace(strings.SplitN(hook[i+len("priority "):], ";", 2)[0]))
	if len(f) == 0 {
		return 0, false
	}
	base, err := strconv.Atoi(f[0])
	if err != nil {
		n, ok := hookPriorities[f[0]]
		if !ok {
			return 0, false
		}
		base = n
	}
	if len(f) == 1 {
		return base, true
	}
	if len(f) == 3 && (f[1] == "+" || f[1] == "-") {
		off, err := strconv.Atoi(f[2])
		if err != nil {
			return 0, false
		}
		if f[1] == "-" {
			off = -off
		}
		return base + off, true
	}
	return 0, false
}

func (b *Backend) ruleExists(chain, needle string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := runNFTCommand(ctx, "list", "chain", family, tableName, chain)
	out := []byte(res.Stdout + res.Stderr)
	if err != nil {
		return false
	}

	normalize := func(s string) string {
		s = strings.ReplaceAll(s, "\r", "")
		s = strings.ReplaceAll(s, "\t", " ")
		// collapse all runs of whitespace into a single space
		return strings.Join(strings.Fields(s), " ")
	}

	s := normalize(string(out))
	n := normalize(needle)

	return strings.Contains(s, " "+n+" ")
}

// -t terse - don't print the contents ffs//
func (b *Backend) setExists(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := runNFTCommand(ctx, "-t", "list", "set", family, tableName, name)
	return err == nil
}

func (b *Backend) nftCmd(expr string) error {
	_, err := b.nftOut(expr)
	return err
}
func (b *Backend) nftOut(expr string) (string, error) {
	expr = strings.TrimSpace(expr)
	// nftOut runs `nft -f -` (script mode). A leading-dash token is a CLI flag
	// (e.g. `-a`, `-n`, `-t`), which is a syntax error inside a script and makes
	// the whole command fail — silently, if the caller discards the error. That
	// is exactly how scoped DNAT accepts once landed after the default drop.
	// Reject it at runtime (covers dynamically-built args the source-scan guard
	// can't see); use runNFTCommand / ListChainText for flagged listings.
	if strings.HasPrefix(expr, "-") {
		return "", fmt.Errorf("nftOut: %q starts with a CLI flag but nftOut runs `nft -f -` (script mode); use runNFTCommand/ListChainText for flagged listings", expr)
	}
	if !strings.HasSuffix(expr, ";") {
		expr += ";"
	}
	if debugEnv {
		fmt.Fprintln(os.Stderr, "[nft] expr:", expr)
	}
	res, err := runNFTCommandInput(context.Background(), expr+"\n", "-f", "-")
	out := []byte(res.Stdout + res.Stderr)
	if debugEnv {
		fmt.Fprintln(os.Stderr, "[nft] rc:", err)
		if len(out) > 0 {
			fmt.Fprintln(os.Stderr, "[nft] out:", string(out))
		}
	}
	return string(out), err
}

// argv-mode add element (όπως στο shell)
func (b *Backend) nftAddElementArgv(set, ip, ttl string) (string, error) {
	args := []string{"add", "element", family, tableName, set, "{", ip}
	if ttl != "" {
		args = append(args, "timeout", ttl)
	}
	args = append(args, "}")
	if debugEnv {
		fmt.Fprintln(os.Stderr, "[nft argv] cmd:", "nft", strings.Join(args, " "))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := runNFTCommand(ctx, args...)
	out := []byte(res.Stdout + res.Stderr)
	if debugEnv {
		fmt.Fprintln(os.Stderr, "[nft argv] rc:", err)
		if len(out) > 0 {
			fmt.Fprintln(os.Stderr, "[nft argv] out:", string(out))
		}
	}
	return string(out), err
}

// 90s/5m/1h/1d
// humanTimeout renders d as a single nftables-parseable time unit (Ns/Nm/Nh/Nd)
// for use INSIDE rule/set syntax — it is functional, not display. Keep it
// single-unit and whole-seconds. Do NOT fold it into a display formatter
// (healthcli.formatShortDuration, webdetector.shortDur): those print forms nft
// does not parse. (nft itself accepts multi-unit "1m30s"; a rule matched by
// its printed text must use firewall.NFTDuration, which writes exactly what
// nft prints.) Pinned by TestHumanTimeout_EmitsSingleUnitNftSyntax.
func humanTimeout(d time.Duration) string {
	sec := int(d.Seconds())
	if sec <= 0 {
		return "0s"
	}
	if sec%86400 == 0 {
		return fmt.Sprintf("%dd", sec/86400)
	}
	if sec%3600 == 0 {
		return fmt.Sprintf("%dh", sec/3600)
	}
	if sec%60 == 0 {
		return fmt.Sprintf("%dm", sec/60)
	}
	return fmt.Sprintf("%ds", sec)
}

// ---------- external sets apply (flush + bulk add) ----------

// replaceChunk is how many elements go into one `add element` statement of a
// replace script. The statements all run in ONE nft transaction; the chunk
// only keeps each line a sane length.
const replaceChunk = 1500

// ReplaceSetFlushAdd replaces a set's content with elems (IPs or CIDRs).
// ttl==nil => no per-element timeout. *_nets sets are de-overlapped first
// (shared keying with nftlib).
//
// The flush and every add are ONE `nft -f` transaction, so the kernel swaps
// the old content for the new at commit and a packet sees one or the other,
// never an empty or half-filled set. It used to run the flush as its own nft
// run and then the adds in batches of 1500, each its own run: the feed unions
// the base rules drop on (block_ext_v4_hosts, …) were empty and then partly
// filled for the whole refill, ~4.5 s for a 1M-address set, on every hourly
// apply of every feed. nft sizes its socket buffer to the batch (it uses
// SO_SNDBUFFORCE as root), so even millions of elements fit; inside an
// unprivileged user namespace it is capped at wmem_max and a large batch
// fails with "Message too long". Then nothing changed, and the old chunked
// write runs instead, logged: the set gets the new content, with the old gap.
// So does a run killed by its deadline (replaceTimeout; a loaded host): each
// batch of the chunked write is a short run of its own, and a set that never
// fits the deadline would otherwise never take new content. Any other failure (an element nft or the kernel rejects) also changed
// nothing, and the set KEEPS its old content: the chunked write would flush it
// and stop at the bad batch, leaving every address after it unblocked.
//
// A PERMANENT set whose content is unchanged since the last successful write
// is not rewritten, as nftlib does, as long as the kernel still holds one of
// its elements: an emptied or recreated set (`cfm reset` / `cfm disable` from
// the CLI, another process this backend cannot see) is written again. A TTL
// set is always rewritten: its elements expire, so the same input does not
// mean the kernel still holds them, and the rewrite is what renews them.
func (b *Backend) ReplaceSetFlushAdd(setName string, elems []string, ttl *time.Duration) error {
	elems = cleanElems(feedutil.NormalizeNetsForSet(setName, elems))

	ttlStr := ""
	if ttl != nil && *ttl > 0 {
		ttlStr = humanTimeout(*ttl)
	}
	permanent := ttl == nil
	var h uint64
	if permanent {
		h = feedutil.HashElems(elems)
		if b.appliedMatches(setName, h) && (len(elems) == 0 || b.setHoldsElem(setName, elems[0])) {
			return nil
		}
	}
	b.forgetApplied(setName)

	ctx, cancel := context.WithTimeout(context.Background(), replaceTimeout(len(elems)))
	err := b.nftExprCtx(ctx, replaceSetScript(setName, elems, ttlStr))
	cancel()
	if err != nil {
		if !batchedWriteMayFix(err) {
			logging.Logf("[nft] replace set %s elems=%d failed, the set keeps its old content: %v",
				setName, len(elems), firstLine(err.Error()))
			return fmt.Errorf("replace %s: %w", setName, err)
		}
		logging.Logf("[nft] replace set %s elems=%d: too large or too slow for one transaction (%v); writing it in batches, with the set briefly partial",
			setName, len(elems), firstLine(err.Error()))
		err = b.replaceSetChunked(setName, elems, ttlStr)
	}
	if err == nil && permanent {
		b.recordApplied(setName, h)
	}
	return err
}

// batchedWriteMayFix reports whether a failed replace failed for its size,
// not its content: nft printed "Message too long" (EMSGSIZE, the batch does
// not fit its socket buffer), or the run hit its deadline. Only then is the
// batched write a fix rather than a way to empty the set (a rejected element
// fails fast, at parse or in the kernel).
func batchedWriteMayFix(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "Message too long") || strings.Contains(msg, "timed_out=true")
}

// replaceTimeout bounds the one-transaction replace: the runner's default 10 s
// plus 1 s per 25 000 elements. One run now carries what used to be hundreds
// (a million addresses commit in ~3 s on an idle host).
func replaceTimeout(n int) time.Duration {
	return defaultNFTCommandTimeout + time.Duration(n/25_000)*time.Second
}

// replaceSetScript is the one-transaction replace: flush, then the elements in
// `add element` statements of replaceChunk each.
func replaceSetScript(setName string, elems []string, ttlStr string) string {
	var sb strings.Builder
	sb.Grow(64 + len(elems)*24)
	fmt.Fprintf(&sb, "flush set %s %s %s\n", family, tableName, setName)
	for i := 0; i < len(elems); i += replaceChunk {
		writeAddElement(&sb, setName, elems[i:min(i+replaceChunk, len(elems))], ttlStr)
		sb.WriteString("\n")
	}
	return sb.String()
}

// replaceSetChunked is the fallback: the flush and each batch of adds are
// separate nft runs (the set is empty, then partial, until the last one).
func (b *Backend) replaceSetChunked(setName string, elems []string, ttlStr string) error {
	if err := b.nftExpr(fmt.Sprintf(`flush set %s %s %s;`, family, tableName, setName)); err != nil {
		return fmt.Errorf("flush %s: %w", setName, err)
	}
	return b.nftAddElementsExpr(setName, elems, ttlStr, replaceChunk)
}

// setHoldsElem asks the kernel whether set holds elem (one netlink lookup,
// setprobe; `nft get element` would load the whole set first). Any error —
// an old kernel that cannot answer, no netlink — reads as "no": the caller
// then rewrites, which is always safe.
func (b *Backend) setHoldsElem(setName, elem string) bool {
	ok, err := setprobe.Holds(setName, elem)
	return err == nil && ok
}

func (b *Backend) appliedMatches(setName string, h uint64) bool {
	b.appliedMu.Lock()
	defer b.appliedMu.Unlock()
	prev, ok := b.appliedHash[setName]
	return ok && prev == h
}

func (b *Backend) recordApplied(setName string, h uint64) {
	b.appliedMu.Lock()
	defer b.appliedMu.Unlock()
	if b.appliedHash == nil {
		b.appliedHash = make(map[string]uint64)
	}
	b.appliedHash[setName] = h
}

// forgetApplied drops a set's applied-content hash ("" = every set), so its
// next ReplaceSetFlushAdd writes. Called wherever this backend empties or
// deletes sets.
func (b *Backend) forgetApplied(setName string) {
	b.appliedMu.Lock()
	defer b.appliedMu.Unlock()
	if setName == "" {
		b.appliedHash = nil
		return
	}
	delete(b.appliedHash, setName)
}

// cleanElems trims the elements and drops empty ones (into a new slice).
func cleanElems(elems []string) []string {
	out := elems[:0:0]
	for _, e := range elems {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// writeAddElement writes one `add element … { e1, e2 }` statement (no
// trailing newline). Empty elements are skipped.
func writeAddElement(sb *strings.Builder, setName string, chunk []string, ttlStr string) {
	sb.WriteString("add element ")
	sb.WriteString(family)
	sb.WriteString(" ")
	sb.WriteString(tableName)
	sb.WriteString(" ")
	sb.WriteString(setName)
	sb.WriteString(" { ")
	first := true
	for _, e := range chunk {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !first {
			sb.WriteString(", ")
		}
		sb.WriteString(e)
		if ttlStr != "" {
			sb.WriteString(" timeout ")
			sb.WriteString(ttlStr)
		}
		first = false
	}
	sb.WriteString(" };")
}

// add element ... { ... } σε batches, μέσω nft -f - (expr); each batch is its
// own nft run (no flush: AddElementsBulk and the replace fallback).
func (b *Backend) nftAddElementsExpr(setName string, elems []string, ttlStr string, batchSize int) error {
	if len(elems) == 0 {
		return nil
	}
	if batchSize <= 0 {
		batchSize = 1000
	}
	for i := 0; i < len(elems); i += batchSize {
		var sb strings.Builder
		writeAddElement(&sb, setName, elems[i:min(i+batchSize, len(elems))], ttlStr)
		if err := b.nftExpr(sb.String()); err != nil {
			return fmt.Errorf("batch add to %s failed: %w", setName, err)
		}
	}
	return nil
}

// AddElementsBulk: add elems to set in batches (no flush).
// ttl==nil => no timeout. Safe/fast for large PERM loads.
// NOTE: If elems already exist in the set, nft will error for that batch.
// Use your seen-maps (or prefill them) to avoid duplicates.
func (b *Backend) AddElementsBulk(setName string, elems []string, ttl *time.Duration) error {
	ttlStr := ""
	if ttl != nil && *ttl > 0 {
		ttlStr = humanTimeout(*ttl)
	}
	return b.nftAddElementsExpr(setName, elems, ttlStr, 1500)
}

// expr runner
func (b *Backend) nftExpr(expr string) error {
	return b.nftExprCtx(context.Background(), expr)
}

// nftExprCtx is nftExpr under ctx (no deadline = the runner's default).
func (b *Backend) nftExprCtx(ctx context.Context, expr string) error {
	if debugEnv {
		fmt.Fprintln(os.Stderr, "[nft expr]:", expr)
	}
	res, err := runNFTCommandInput(ctx, expr+"\n", "-f", "-")
	out := []byte(res.Stdout + res.Stderr)
	if debugEnv {
		fmt.Fprintln(os.Stderr, "[nft] rc:", err)
		if len(out) > 0 {
			fmt.Fprintln(os.Stderr, "[nft] out:", string(out))
		}
	}
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(out))
	}
	return nil
}

// Sanitizer για feed names: lower, [a-z0-9_], κόψιμο μήκους, prefix αν αρχίζει με digit
func SanitizeFeedName(s string) string {
	s = strings.ToLower(s)
	b := make([]rune, 0, len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b = append(b, r)
		} else {
			b = append(b, '_')
		}
	}
	out := strings.Trim(bulkUnderscores(string(b)), "_")
	if out == "" {
		out = "feed"
	}
	if out[0] >= '0' && out[0] <= '9' {
		out = "f_" + out
	}
	if len(out) > 40 { // αυθαίρετο όριο για καθαρότητα ονόματος
		out = out[:40]
	}
	return out
}
func bulkUnderscores(s string) string {
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	return s
}

// Δημιουργεί δυναμικό set με flags ανάλογα με hosts/nets και v4/v6
func (b *Backend) EnsureSetDynamic(name string, v6 bool, isNet bool) error {
	typ := "ipv4_addr"
	if v6 {
		typ = "ipv6_addr"
	}
	flags := "timeout"
	if isNet {
		flags = "timeout,interval"
	}
	return b.ensureSetWithFlags(name, typ, flags)
}

// --- WHICH IP support --------------------------------------------------------
// --- inside package nft (internal/firewall/nft/nft.go) ---

type setMeta struct {
	Name  string
	Type  string   // ipv4_addr | ipv6_addr
	Flags []string // e.g. ["timeout","interval"]
}

// DropFeedSets διαγράφει όλα τα per-feed sets (hosts/nets, v4/v6, allow/block)
func (b *Backend) DropFeedSets(feedName string) {
	suff := SanitizeFeedName(feedName)
	sets := []string{
		"allow_ext_v4_hosts_" + suff,
		"allow_ext_v4_nets_" + suff,
		"allow_ext_v6_hosts_" + suff,
		"allow_ext_v6_nets_" + suff,
		"block_ext_v4_hosts_" + suff,
		"block_ext_v4_nets_" + suff,
		"block_ext_v6_hosts_" + suff,
		"block_ext_v6_nets_" + suff,
	}
	for _, s := range sets {
		// αγνόησε σφάλματα αν δεν υπάρχουν ή είναι δεσμευμένα
		_, _ = runNFTCommand(context.Background(), "flush", "set", "inet", tableName, s)
		_, _ = runNFTCommand(context.Background(), "delete", "set", "inet", tableName, s)
		b.forgetApplied(s)
	}

	b.unregisterFeedKey(suff)
	b.dropExternalFeedCache(suff)

	_ = b.RebuildExternalUnions()
}

// DropEverything: delete whole table inet cfm
func (b *Backend) DropEverything() error {
	b.forgetApplied("")
	// Only a definite absence skips the delete: on an unknown probe, try, and
	// let nft's own error answer (a "nothing to do" success must not hide a
	// table that is still loaded).
	if b.probeTable() == tableAbsent {
		return nil
	}
	// best-effort flush first (μην αποτύχει delete λόγω refs)
	_, _ = runNFTCommand(context.Background(), "flush", "table", family, tableName)
	return b.nftCmd(fmt.Sprintf("delete table %s %s", family, tableName))
}

// ResetTable: flush whole table (rules + sets content), κρατώντας το table
func (b *Backend) ResetTable() error {
	b.forgetApplied("")
	if b.probeTable() == tableAbsent { // unknown: try, as DropEverything does
		return nil
	}
	return b.nftCmd(fmt.Sprintf("flush table %s %s", family, tableName))
}

func (b *Backend) ResetCFMTable() error {
	b.forgetApplied("")
	// Σβήσε το table αν υπάρχει (αγνόησε error αν δεν υπάρχει)
	_ = b.nftCmd(fmt.Sprintf("delete table %s %s", family, tableName))
	// Ξαναφτιάξ’ το άδειο
	return b.nftCmd(fmt.Sprintf("add table %s %s", family, tableName))
}

// refreshSelfSets loads self_v4/self_v6 (loopback, link-local, every local
// address). It used to run one nft process per statement (two flushes, the
// three static ranges, one add per local address) on every EnsureBase. Now it
// reads both sets (`-j list set <one>`: 3-10 ms on every fleet node), writes
// nothing when they already hold the wanted content (every restart of a node
// whose addresses did not change), and otherwise replaces both in ONE
// transaction, so a packet never sees a flushed, half-filled self set. If nft
// refuses that write, writeSelfSetFallback retries each set on its own, then
// with loopback and link-local only; a write that ran out of time is not
// retried (a retry waits for the same busy nft slots).
func (b *Backend) refreshSelfSets() {
	b.selfResolver.Refresh()
	v4, v6 := firewall.SelfSetElems(b.selfResolver.LocalIPs())
	if !b.setHolds("self_v4", v4) || !b.setHolds("self_v6", v6) {
		script := replaceSetScript("self_v4", v4, "") + replaceSetScript("self_v6", v6, "")
		if err := b.nftExpr(script); err != nil {
			if nftTimedOut(err) {
				logging.Logf("[nft] self sets write timed out, they keep their old content: %v", firstLine(err.Error()))
			} else {
				logging.Logf("[nft] self sets write failed: %v; retrying each set on its own", firstLine(err.Error()))
				b.writeSelfSetFallback()
			}
		}
	}
	b.writeSelfIPsLua()
}

// writeSelfSetFallback runs after the one-transaction write was refused: one
// element nft rejects fails the whole script, and after a reboot the sets
// start empty, so without this not even loopback would be accepted early.
// Each set is written on its own; a set that still refuses gets the static
// ranges alone (loopback, link-local), which the old per-statement run always
// landed. Every step is a single transaction, so a set is never left flushed.
func (b *Backend) writeSelfSetFallback() {
	v4, v6 := firewall.SelfSetElems(b.selfResolver.LocalIPs())
	s4, s6 := firewall.SelfSetElems(nil)
	for _, w := range []struct {
		name         string
		full, static []string
	}{{"self_v4", v4, s4}, {"self_v6", v6, s6}} {
		if b.setHolds(w.name, w.full) {
			continue
		}
		err := b.nftExpr(replaceSetScript(w.name, w.full, ""))
		if err == nil {
			continue
		}
		logging.Logf("[nft] %s write failed: %v; writing loopback and link-local only", w.name, firstLine(err.Error()))
		if b.setHolds(w.name, w.static) {
			continue
		}
		if err := b.nftExpr(replaceSetScript(w.name, w.static, "")); err != nil {
			logging.Logf("[nft] %s static write failed, it keeps its old content: %v", w.name, firstLine(err.Error()))
		}
	}
}

// nftTimedOut reports whether an nft run failed on its deadline (the slot
// wait included), not because nft refused the script.
func nftTimedOut(err error) bool {
	return err != nil && (errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timed_out=true"))
}

// setHolds reports whether the kernel's set holds exactly want. A failed read,
// or an element it cannot read, is "no": the caller writes the set again
// rather than trust an unknown.
func (b *Backend) setHolds(setName string, want []string) bool {
	have, err := listSetElemsStrict(setName)
	if err != nil {
		return false
	}
	return firewall.SameSetElems(have, want)
}

func (b *Backend) writeSelfIPsLua() {
	dir := filepath.Dir(selfIPsLuaPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		logging.Logf("[nft] self-ip lua mkdir failed path=%s err=%v", filepath.Dir(selfIPsLuaPath), err)
		return
	}

	keys := b.selfResolver.LocalIPs()
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteString("-- generated by cfm (nft.refreshSelfSets); do not edit\n")
	buf.WriteString("return {\n")
	buf.WriteString(fmt.Sprintf("  generated_at = %q,\n", time.Now().UTC().Format(time.RFC3339Nano)))
	buf.WriteString("  ips = {\n")
	for _, ip := range keys {
		buf.WriteString(fmt.Sprintf("    [%q] = true,\n", ip))
	}
	buf.WriteString("  },\n")
	buf.WriteString("}\n")

	tmp := selfIPsLuaPath + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o640); err != nil {
		logging.Logf("[nft] self-ip lua write failed path=%s err=%v", tmp, err)
		return
	}
	if err := os.Chmod(tmp, 0o640); err != nil {
		logging.Logf("[nft] self-ip lua chmod failed path=%s err=%v", tmp, err)
	}
	b.ensureCFMGroupRead(tmp)
	if err := os.Rename(tmp, selfIPsLuaPath); err != nil {
		_ = os.Remove(tmp)
		logging.Logf("[nft] self-ip lua rename failed from=%s to=%s err=%v", tmp, selfIPsLuaPath, err)
		return
	}
	if err := os.Chmod(selfIPsLuaPath, 0o640); err != nil {
		logging.Logf("[nft] self-ip lua chmod failed path=%s err=%v", selfIPsLuaPath, err)
	}
	b.ensureCFMGroupRead(selfIPsLuaPath)
	b.ensureCFMGroupRead(dir)
}

func (b *Backend) ensureCFMGroupRead(path string) {
	g, err := user.LookupGroup("cfm")
	if err != nil || g == nil {
		return
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return
	}
	_ = os.Chown(path, -1, gid)
}

func (b *Backend) isSelfIPString(s string) bool {
	return b.selfResolver.Contains(s)
}

// HasElem returns true if elem is in setName without dumping the set.
func (b *Backend) HasElem(setName, elem string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := []string{"get", "element", family, tableName, setName, "{", elem, "}"}
	res, err := runNFTCommand(ctx, args...)
	out := []byte(res.Stdout + res.Stderr)
	if err == nil {
		return true, nil // found
	}
	s := string(out)
	// "Could not get element", "not found", etc. = not present (not an error for us)
	if strings.Contains(s, "Could not get element") || strings.Contains(s, "not found") {
		return false, nil
	}
	if strings.Contains(s, "No such file or directory") {
		// set missing -> treat as not present; caller may decide what to do
		return false, nil
	}
	return false, fmt.Errorf("nft get element %s{%s}: %v: %s", setName, elem, err, s)
}

// //// helpers caching allow lists for ignore feature /////
// listSetsByPrefixes returns set names that start with any of the given prefixes.
func (b *Backend) listSetsByPrefixes(prefixes ...string) ([]string, error) {
	res, err := runNFTCommand(context.Background(), "-t", "-n", "list", "table", string(family), tableName)
	out := []byte(res.Stdout + res.Stderr)
	if err != nil {
		return nil, fmt.Errorf("nft list table: %v: %s", err, string(out))
	}
	var names []string
	pfx := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p != "" {
			pfx = append(pfx, p)
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "set ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[1]
		for _, p := range pfx {
			if strings.HasPrefix(name, p) {
				names = append(names, name)
				break
			}
		}
	}
	return names, nil
}

// refreshExtAllowCache reloads per-feed allow set names with a small TTL.
func (b *Backend) refreshExtAllowCache() {
	b.extMu.RLock()
	if time.Since(b.extAllowCacheAt) < 300*time.Second {
		b.extMu.RUnlock()
		return
	}
	b.extMu.RUnlock()

	// discover per-feed allow sets
	v4h, _ := b.listSetsByPrefixes("allow_ext_v4_hosts_")
	v4n, _ := b.listSetsByPrefixes("allow_ext_v4_nets_")
	v6h, _ := b.listSetsByPrefixes("allow_ext_v6_hosts_")
	v6n, _ := b.listSetsByPrefixes("allow_ext_v6_nets_")

	b.extMu.Lock()
	defer b.extMu.Unlock()
	if time.Since(b.extAllowCacheAt) < 300*time.Second {
		return
	}
	b.extAllowV4Hosts = v4h
	b.extAllowV4Nets = v4n
	b.extAllowV6Hosts = v6h
	b.extAllowV6Nets = v6n
	b.extAllowCacheAt = time.Now()
}

func (b *Backend) getExtAllowSets(fam int) (hosts []string, nets []string) {
	b.refreshExtAllowCache()
	b.extMu.RLock()
	defer b.extMu.RUnlock()
	if fam == 6 {
		return append([]string(nil), b.extAllowV6Hosts...), append([]string(nil), b.extAllowV6Nets...)
	}
	return append([]string(nil), b.extAllowV4Hosts...), append([]string(nil), b.extAllowV4Nets...)
}

// -------- challenge (source IP redirect) --------

func (b *Backend) ListTableJSON(fam, table string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := runNFTCommand(ctx, "-j", "list", "table", fam, table)
	out := []byte(res.Stdout + res.Stderr)
	if err != nil {
		return nil, fmt.Errorf("nft list table %s %s: %v: %s", fam, table, err, string(out))
	}
	return out, nil
}

// ListSetsJSON lists the sets of every table of the family WITHOUT their
// elements: `nft -j -t list sets <family>`. Each set carries its "table"; a
// caller keeps its own table's. A caller that only wants the sets' names and
// key types reads this, not ListTableJSON: with a fleet feed in the table
// (MYBLOCK, ~215k addresses on virgo) the full dump ran past its 5 s deadline
// and `cfm search` reported the nft source as unreadable. Measured with 1M
// addresses in a feed set and its union: `list sets` 5 ms, `list table` 32 s
// even with -t, which still loads every element. It ends at ctx's deadline,
// or after 15 s.
func (b *Backend) ListSetsJSON(ctx context.Context, fam string) ([]byte, error) {
	return nftListJSONContext(ctx, "-j", "-t", "list", "sets", fam)
}

// ListSetJSONContext is ListSetJSON ending at ctx's deadline (or after 15 s:
// a fleet feed's set is several MB of JSON). Its error carries nft's stderr,
// never the partial stdout of a dump cut short.
func (b *Backend) ListSetJSONContext(ctx context.Context, fam, table, set string) ([]byte, error) {
	return nftListJSONContext(ctx, "-j", "list", "set", fam, table, set)
}

func nftListJSONContext(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	res, err := runNFTCommand(ctx, args...)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, fmt.Errorf("nft %s: %w", strings.Join(args, " "), cerr)
		}
		return nil, fmt.Errorf("nft %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(res.Stderr))
	}
	return []byte(res.Stdout), nil
}

func (b *Backend) ListSetJSON(fam, table, set string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := runNFTCommand(ctx, "-j", "list", "set", fam, table, set)
	out := []byte(res.Stdout + res.Stderr)
	if err != nil {
		return nil, fmt.Errorf("nft list set %s %s %s: %v: %s", fam, table, set, err, string(out))
	}
	return out, nil
}

func (b *Backend) ListTableTextNoDNS(fam, table string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := runNFTCommand(ctx, "-t", "-n", "list", "table", fam, table)
	out := []byte(res.Stdout + res.Stderr)
	if err != nil {
		return "", fmt.Errorf("nft list table %s %s: %v: %s", fam, table, err, string(out))
	}
	return string(out), nil
}

func (b *Backend) ListChainText(fam, table, chain string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := runNFTCommand(ctx, "-a", "list", "chain", fam, table, chain)
	out := []byte(res.Stdout + res.Stderr)
	if err != nil {
		return "", fmt.Errorf("nft list chain %s %s %s: %v: %s", fam, table, chain, err, string(out))
	}
	return string(out), nil
}

func (b *Backend) FlushSet(fam, table, set string) error {
	b.forgetApplied(set)
	res, err := runNFTCommand(context.Background(), "-n", "flush", "set", fam, table, set)
	out := []byte(res.Stdout + res.Stderr)
	if err != nil {
		return fmt.Errorf("nft flush set %s %s %s: %v: %s", fam, table, set, err, string(out))
	}
	return nil
}
