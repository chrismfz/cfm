//go:build linux

package nft

import (
	"bufio"
	"bytes"
	cfgpkg "cfm/internal/config"
	enrichpkg "cfm/internal/enrich"
	"cfm/internal/firewall"
	"cfm/internal/logging"
	"cfm/internal/reporting"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tableName      = "cfm"
	family         = "inet"
	selfIPsLuaPath = "/var/lib/cfm/lua/cfm_self_ips.lua"

	//web challenge nets
	challengeV4       = "challenge_v4"
	challengeV6       = "challenge_v6"
	challengeNatChain = "prerouting"

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
	debugAPIV4 = "debug_api_v4"
	debugAPIV6 = "debug_api_v6"

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

	// Optional logger used by the challenge server so nft can log rule installs
	// into the same cfm.challenges.log stream.
	challengeLogf func(format string, args ...any)

	// When false (OpenResty mode), do NOT create challenge_v4/challenge_v6 sets.
	// Also remove them if they already exist.
	challengeDNATEnabled bool

	pfSets   []string            // th_pf_<port>_<proto>_v4/v6
	clSets   []string            // th_connlimit_<port>_<proto>_v4/v6
	feedKeys map[string]struct{} // π.χ. {"dshield":{}, "abuseipdb":{}}

	// external feed element caches (so RebuildExternalUnions NEVER needs `nft -j list set`)
	extFeedMu sync.RWMutex
	extAllow  map[string]extFeedData // key -> elems
	extBlock  map[string]extFeedData // key -> elems

	// cache of external ALLOW set names (per-feed), to avoid expensive table scans on every check
	extMu           sync.RWMutex
	extAllowCacheAt time.Time
	extAllowV4Hosts []string
	extAllowV4Nets  []string
	extAllowV6Hosts []string
	extAllowV6Nets  []string

	selfIPsMu    sync.RWMutex
	selfIPs      map[string]struct{}
	selfInitOnce sync.Once

	floodDumpMu      sync.Mutex
	floodDumpRunning bool
	lastFloodHash    uint64
	lastFloodRebuild time.Time

	portScanMu      sync.Mutex
	portScanRunning bool

	apiCacheMu         sync.Mutex
	apiCacheHost       string
	apiCacheV4         []string
	apiCacheV6         []string
	apiCacheResolvedAt time.Time
}

var _ firewall.Backend = (*Backend)(nil)

// GetEnricher returns the enrichment engine (if enabled).
func (b *Backend) GetEnricher() *enrichpkg.Enricher {
	return b.enr
}

func (b *Backend) SetReporter(r reporting.Reporter) { b.reporter = r }

// SetChallengeLogger allows the challenge server to pass its log function so nft
// can emit per-rule debug lines into cfm.challenges.log.
func (b *Backend) SetChallengeLogger(f func(format string, args ...any)) {
	b.challengeLogf = f
}

func (b *Backend) chlogf(format string, args ...any) {
	if b != nil && b.challengeLogf != nil {
		b.challengeLogf(format, args...)
	}
}

//func New() *Backend { return &Backend{} }

func New() *Backend {
	return &Backend{
		last:                 make(map[string]uint64),
		feedKeys:             make(map[string]struct{}),
		extAllow:             make(map[string]extFeedData),
		extBlock:             make(map[string]extFeedData),
		selfIPs:              make(map[string]struct{}),
		challengeDNATEnabled: true,
	}
}

func (b *Backend) SetChallengeRedirectEnabled(enabled bool) {
	if b == nil {
		return
	}
	b.challengeDNATEnabled = enabled
	if !enabled {
		_ = b.CleanupChallengeRedirect()
	}
}

func (b *Backend) CleanupChallengeRedirect() error {
	if b == nil {
		return nil
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
	return nil
}

func (b *Backend) SetChallengeDNATEnabled(enabled bool) {
	b.SetChallengeRedirectEnabled(enabled)
}

func (b *Backend) CleanupChallengeDNAT() error {
	return b.CleanupChallengeRedirect()
}

// ReportBlock decides (based on config + source) whether to notify the API and then calls reporter.
// source: "detector" | "autoblock" | "manual"
// mode:   "ttl" | "permanent" | "dryrun"
func (b *Backend) ReportBlock(ip, comment, source, mode string, ttlSeconds int) error {
	if b == nil || b.reporter == nil || b.cfg == nil {
		return nil
	}
	switch source {
	case "detector":
		// Allow if DETECTORS_SEND_TO_API enabled, OR fall back to AUTOBLOCK_SEND_TO_API.
		if !(b.cfg.API.DetectorsSend || b.cfg.API.AutoBlockSend) {
			return nil
		}
	case "autoblock":
		if !b.cfg.API.AutoBlockSend {
			return nil
		}
	case "manual":
		if !b.cfg.API.ManualBlockSend {
			return nil
		}
	default:
		// Unknown source → be conservative (no report)
		return nil
	}
	return b.reporter.ReportBlock(ip, comment, source, mode, ttlSeconds)
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

func (b *Backend) EnsureBase() error {
	// 1) Ensure table
	if !b.tableExists() {
		if err := b.nftCmd(fmt.Sprintf("add table %s %s", family, tableName)); err != nil {
			return err
		}
	}

	// desired priority (default -50; override από cfg)
	prio := -50
	if b.cfg != nil && b.cfg.NFT.InputPriority != 0 {
		prio = b.cfg.NFT.InputPriority
	}

	// 2) Ensure chains (input με σωστό priority, flood χωρίς hook)
	needCreate := false
	if !b.chainExists("input") {
		needCreate = true
	} else {

		ctx5, cancel5 := context.WithTimeout(context.Background(), 5*time.Second)
		out, _ := exec.CommandContext(ctx5, "nft", "list", "chain", family, tableName, "input").CombinedOutput()
		cancel5()
		s := string(out)
		want := fmt.Sprintf("priority %d", prio)
		same := strings.Contains(s, want) || (prio == 0 && strings.Contains(s, "priority filter"))
		if !same {
			// Do NOT silently destroy the input chain on a priority
			// mismatch — that leaves the server unprotected during recreate.
			// Log the discrepancy and leave the existing chain intact.
			// To migrate the priority deliberately, run: cfm reset && cfm daemon
			logging.Logf("[nft] WARNING: input chain priority mismatch (want %d). "+
				"Run 'cfm reset' to apply the new priority. Keeping existing chain.", prio)
			// needCreate stays false — we proceed with the existing chain as-is.
		}
	}

	if needCreate {
		if err := b.nftCmd(fmt.Sprintf(
			`add chain %s %s input { type filter hook input priority %d; policy accept; }`,
			family, tableName, prio,
		)); err != nil {
			return err
		}
	}
	if !b.chainExists("flood") {
		if err := b.nftCmd(fmt.Sprintf(`add chain %s %s flood`, family, tableName)); err != nil {
			return err
		}
	}

	// 2b) Ensure NAT prerouting chain for challenge redirects
	if !b.chainExists(challengeNatChain) {
		if err := b.nftCmd(fmt.Sprintf(
			`add chain %s %s %s { type nat hook prerouting priority dstnat; policy accept; }`,
			family, tableName, challengeNatChain,
		)); err != nil {
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

	// Challenge sets (source IPs that should be redirected to challenge ports)
	// Challenge sets (dynamic DNAT mode only)
	if b.challengeDNATEnabled {
		if err := b.ensureSetWithFlags(challengeV4, "ipv4_addr", "timeout"); err != nil {
			return err
		}
		if err := b.ensureSetWithFlags(challengeV6, "ipv6_addr", "timeout"); err != nil {
			return err
		}
	} else {
		_ = b.CleanupChallengeRedirect()
	}

	// 4) Base allow/deny rules (idempotent, σταθερή σειρά)
	// NOTE: querying `nft list chain ...` repeatedly can become very expensive on
	// large installations. Cache the input chain snapshot once and keep it updated
	// as we add/insert rules during this EnsureBase run.
	inputChainRaw, _ := exec.Command("nft", "list", "chain", family, tableName, "input").CombinedOutput()
	normalizeRule := func(s string) string {
		s = strings.ReplaceAll(s, "\r", "")
		s = strings.ReplaceAll(s, "\t", " ")
		return " " + strings.Join(strings.Fields(s), " ") + " "
	}
	inputChainNorm := normalizeRule(string(inputChainRaw))
	ruleInInput := func(expr string) bool {
		return strings.Contains(inputChainNorm, normalizeRule(expr))
	}
	recordRuleInInput := func(expr string) {
		inputChainNorm += normalizeRule(expr)
	}

	addRule := func(expr string) error {
		if ruleInInput(expr) {
			return nil
		}
		if err := b.nftCmd(fmt.Sprintf(`add rule %s %s input %s`, family, tableName, expr)); err != nil {
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
		if err := b.nftCmd(fmt.Sprintf(`insert rule %s %s input position 0 %s`, family, tableName, expr)); err == nil {
			recordRuleInInput(expr)
		}
	}

	// Build desired top-down order:
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
	}

	// 5) ICMP → flood (below unconditional drops)
	if b.cfg != nil && b.cfg.Hardening.ICMPRate > 0 {
		early = append(early,
			`ip protocol icmp icmp type echo-request jump flood`,
			`ip6 nexthdr ipv6-icmp icmpv6 type echo-request jump flood`,
		)
	}

	// Insert in reverse so first item ends up highest in chain
	for i := len(early) - 1; i >= 0; i-- {
		addEarly(early[i])
	}

	// Κόψε established/related από IPs που είναι ήδη σε block sets
	if err := addRule(`ct state established,related ip saddr @block_v4 drop`); err != nil {
		return err
	}
	if err := addRule(`ct state established,related ip6 saddr @block_v6 drop`); err != nil {
		return err
	}

	// External feeds — hosts & nets
	if err := addRule(`ct state established,related ip saddr @block_ext_v4_hosts drop`); err != nil {
		return err
	}
	if err := addRule(`ct state established,related ip saddr @block_ext_v4_nets drop`); err != nil {
		return err
	}
	if err := addRule(`ct state established,related ip6 saddr @block_ext_v6_hosts drop`); err != nil {
		return err
	}
	if err := addRule(`ct state established,related ip6 saddr @block_ext_v6_nets drop`); err != nil {
		return err
	}

	// Manual/aggregate nets (αν τα έχεις)
	if err := addRule(`ct state established,related ip saddr @block_v4_nets drop`); err != nil {
		return err
	}
	if err := addRule(`ct state established,related ip6 saddr @block_v6_nets drop`); err != nil {
		return err
	}

	// Τώρα το γενικό established/related accept (μετά τα drops)
	if err := addRule(`ct state established,related accept`); err != nil {
		return err
	}

	// Rules continue //

	// 1) manual allow
	if err := addRule(`ip saddr @allow_v4 accept`); err != nil {
		return err
	}
	if err := addRule(`ip6 saddr @allow_v6 accept`); err != nil {
		return err
	}
	// 2) dyn allow
	if err := addRule(`ip saddr @allow_dyn_v4 accept`); err != nil {
		return err
	}
	if err := addRule(`ip6 saddr @allow_dyn_v6 accept`); err != nil {
		return err
	}
	// 3) external allow (hosts, then nets)
	if err := addRule(`ip saddr @allow_ext_v4_hosts accept`); err != nil {
		return err
	}
	if err := addRule(`ip6 saddr @allow_ext_v6_hosts accept`); err != nil {
		return err
	}
	if err := addRule(`ip saddr @allow_ext_v4_nets accept`); err != nil {
		return err
	}
	if err := addRule(`ip6 saddr @allow_ext_v6_nets accept`); err != nil {
		return err
	}
	// 4) manual block
	if err := addRule(`ip saddr @block_v4 drop`); err != nil {
		return err
	}
	if err := addRule(`ip6 saddr @block_v6 drop`); err != nil {
		return err
	}
	// 5) external block (hosts, then nets)
	if err := addRule(`ip saddr @block_ext_v4_hosts drop`); err != nil {
		return err
	}
	if err := addRule(`ip6 saddr @block_ext_v6_hosts drop`); err != nil {
		return err
	}
	if err := addRule(`ip saddr @block_ext_v4_nets drop`); err != nil {
		return err
	}
	if err := addRule(`ip6 saddr @block_ext_v6_nets drop`); err != nil {
		return err
	}

	// NEW: manual block nets
	if err := addRule(`ip saddr @block_v4_nets drop`); err != nil {
		return err
	}
	if err := addRule(`ip6 saddr @block_v6_nets drop`); err != nil {
		return err
	}

	// 6) jump flood στο τέλος του base layer
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

func (b *Backend) AddBlock(ip net.IP, _ string, ttl *time.Duration) error {
	if ip == nil {
		return errors.New("nil ip")
	}
	set := setV4
	if ip.To4() == nil {
		set = setV6
	}
	elem := ip.String()

	_ = b.RemoveBlock(ip)

	ttlStr := ""
	if ttl != nil && *ttl > 0 {
		ttlStr = humanTimeout(*ttl) // 90s / 5m / 1h
	}

	out, err := b.nftAddElementArgv(set, elem, ttlStr)
	if err == nil {
		return nil
	}
	if strings.Contains(out, "already exists") || strings.Contains(out, "File exists") {
		_ = b.RemoveBlock(ip)
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
	set := setV4
	elem := ip.String()
	if ip.To4() == nil {
		set = setV6
	}
	cmd := fmt.Sprintf(`delete element %s %s %s { %s }`, family, tableName, set, elem)
	out, err := b.nftOut(cmd)
	if err != nil && !strings.Contains(out, "No such file or directory") && !strings.Contains(out, "Could not delete element") {
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
	if err != nil && !strings.Contains(out, "No such file or directory") && !strings.Contains(out, "Could not delete element") {
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
	if err2 != nil && !strings.Contains(out, "No such file or directory") && !strings.Contains(out, "Could not delete element") {
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
	if err != nil && !strings.Contains(out, "No such file or directory") && !strings.Contains(out, "Could not delete element") {
		return fmt.Errorf("nft: %v: %s", err, out)
	}
	return nil
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
	if err2 != nil && !strings.Contains(out, "No such file or directory") && !strings.Contains(out, "Could not delete element") {
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
	if err2 != nil && !strings.Contains(out, "No such file or directory") && !strings.Contains(out, "Could not delete element") {
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
	raw, err := exec.Command("nft", "-j", "list", "set", family, tableName, setName).CombinedOutput()
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
	raw, err := exec.Command("nft", "list", "set", family, tableName, setName).CombinedOutput()
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

func (b *Backend) tableExists() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", "list", "tables").Output()
	if err != nil {
		return false
	}
	for _, ln := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(ln) == "table inet cfm" {
			return true
		}
	}
	return false
}

func TableExistsCFM() bool {
	var b Backend
	return b.tableExists()
}

func (b *Backend) chainExists(chain string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := exec.CommandContext(ctx, "nft", "list", "chain", family, tableName, chain).CombinedOutput()
	return err == nil
}

func (b *Backend) ruleExists(chain, needle string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", "list", "chain", family, tableName, chain).CombinedOutput()
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
	_, err := exec.CommandContext(ctx, "nft", "-t", "list", "set", family, tableName, name).CombinedOutput()
	return err == nil
}

func (b *Backend) nftCmd(expr string) error {
	_, err := b.nftOut(expr)
	return err
}
func (b *Backend) nftOut(expr string) (string, error) {
	expr = strings.TrimSpace(expr)
	if !strings.HasSuffix(expr, ";") {
		expr += ";"
	}
	if debugEnv {
		fmt.Fprintln(os.Stderr, "[nft] expr:", expr)
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(expr + "\n")
	out, err := cmd.CombinedOutput()
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
	out, err := exec.CommandContext(ctx, "nft", args...).CombinedOutput()
	if debugEnv {
		fmt.Fprintln(os.Stderr, "[nft argv] rc:", err)
		if len(out) > 0 {
			fmt.Fprintln(os.Stderr, "[nft argv] out:", string(out))
		}
	}
	return string(out), err
}

// 90s/5m/1h/1d
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

// ReplaceSetFlushAdd: καθαρίζει το set και βάζει elems (IP ή CIDR) σε batches.
// Για _nets sets κάνει κανονικοποίηση CIDR (drop overlapping subnets).
// ttl==nil => χωρίς timeout per-element.
func (b *Backend) ReplaceSetFlushAdd(setName string, elems []string, ttl *time.Duration) error {
	// flush
	if err := b.nftExpr(fmt.Sprintf(`flush set %s %s %s;`, family, tableName, setName)); err != nil {
		return fmt.Errorf("flush %s: %w", setName, err)
	}

	// Αν είναι *nets set, καθάρισε επικαλύψεις

	if strings.Contains(setName, "_v4_nets") {
		elems = normalizeCIDRsV4(elems)
	}
	if strings.Contains(setName, "_v6_nets") {
		elems = normalizeCIDRsV6(elems)
	}

	ttlStr := ""
	if ttl != nil && *ttl > 0 {
		ttlStr = humanTimeout(*ttl)
	}

	return b.nftAddElementsExpr(setName, elems, ttlStr, 1500)
}

// add element ... { ... } σε batches, μέσω nft -f - (expr)
func (b *Backend) nftAddElementsExpr(setName string, elems []string, ttlStr string, batchSize int) error {
	if len(elems) == 0 {
		return nil
	}
	if batchSize <= 0 {
		batchSize = 1000
	}
	for i := 0; i < len(elems); i += batchSize {
		j := i + batchSize
		if j > len(elems) {
			j = len(elems)
		}
		chunk := elems[i:j]

		var sb strings.Builder
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
	if debugEnv {
		fmt.Fprintln(os.Stderr, "[nft expr]:", expr)
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(expr + "\n")
	out, err := cmd.CombinedOutput()
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

// ---------- CIDR normalization (drop overlaps) ----------

// IPv4
type v4range struct {
	start uint32
	end   uint32
	cidr  string
}

func ip4ToU32(ip net.IP) uint32 {
	ip4 := ip.To4()
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func cidrRangeV4(c *net.IPNet) (uint32, uint32) {
	network := c.IP.Mask(c.Mask).To4()
	start := ip4ToU32(network)
	ones, bits := c.Mask.Size()
	// host count = 2^(bits-ones)
	host := uint32(1)<<(uint(bits-ones)) - 1
	end := start + host
	return start, end
}

func normalizeCIDRsV4(in []string) []string {
	// parse + canonicalize + dedup
	seen := make(map[string]struct{})
	var arr []v4range
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || strings.IndexByte(s, '/') == -1 {
			continue
		}
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		// canonical cidr string
		canon := ipnet.IP.Mask(ipnet.Mask).String() + "/" + strconv.Itoa(maskOnes(ipnet.Mask))
		if _, ok := seen[canon]; ok {
			continue
		}
		seen[canon] = struct{}{}
		st, en := cidrRangeV4(ipnet)
		arr = append(arr, v4range{start: st, end: en, cidr: canon})
	}

	if len(arr) == 0 {
		return nil
	}

	// sort: start asc, end desc (ώστε ο υπερ-χώρος πρώτος)
	sortFunc := func(i, j int) bool {
		if arr[i].start == arr[j].start {
			return arr[i].end > arr[j].end
		}
		return arr[i].start < arr[j].start
	}
	// local sort to avoid extra import
	for i := 1; i < len(arr); i++ {
		for j := i; j > 0 && sortFunc(j, j-1); j-- {
			arr[j], arr[j-1] = arr[j-1], arr[j]
		}
	}

	out := make([]string, 0, len(arr))
	var coverEnd uint32 = 0
	for _, r := range arr {
		if len(out) == 0 {
			out = append(out, r.cidr)
			coverEnd = r.end
			continue
		}
		// αν ο τρέχων αρχίζει μέσα σε ήδη καλυμμένο διάστημα και τελειώνει πριν/ίσο με coverEnd => contained → drop
		if r.start <= coverEnd && r.end <= coverEnd {
			continue
		}
		// εκτός κάλυψης → keep
		if r.start > coverEnd {
			out = append(out, r.cidr)
			coverEnd = r.end
			continue
		}
		// Θεωρητικά partial overlap δεν πρέπει να υπάρξει με CIDR, παρ' όλα αυτά:
		if r.end > coverEnd {
			// επεκτείνει την κάλυψη (σπάνιο για CIDR) – κρατάμε το νέο για ασφάλεια
			out = append(out, r.cidr)
			coverEnd = r.end
		}
	}
	return out
}

func maskOnes(m net.IPMask) int {
	ones, _ := m.Size()
	return ones
}

// IPv6
type v6range struct {
	start *big.Int
	end   *big.Int
	cidr  string
}

func ip6ToBig(ip net.IP) *big.Int {
	ip = ip.To16()
	return new(big.Int).SetBytes(ip)
}

func cidrRangeV6(n *net.IPNet) (*big.Int, *big.Int) {
	base := ip6ToBig(n.IP.Mask(n.Mask))
	ones, bits := n.Mask.Size()
	rem := uint(bits - ones)
	hostCount := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), rem), big.NewInt(1))
	end := new(big.Int).Add(base, hostCount)
	return base, end
}

func normalizeCIDRsV6(in []string) []string {
	seen := make(map[string]struct{})
	var arr []v6range
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || strings.IndexByte(s, '/') == -1 {
			continue
		}
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		ipnet.IP = ipnet.IP.Mask(ipnet.Mask)
		canon := ipnet.String()
		if _, ok := seen[canon]; ok {
			continue
		}
		seen[canon] = struct{}{}
		st, en := cidrRangeV6(ipnet)
		arr = append(arr, v6range{start: st, end: en, cidr: canon})
	}
	if len(arr) == 0 {
		return nil
	}

	// sort: start asc, end desc
	less := func(a, b v6range) bool {
		c := a.start.Cmp(b.start)
		if c == 0 {
			return a.end.Cmp(b.end) > 0
		}
		return c < 0
	}
	for i := 1; i < len(arr); i++ {
		for j := i; j > 0 && less(arr[j], arr[j-1]); j-- {
			arr[j], arr[j-1] = arr[j-1], arr[j]
		}
	}

	out := make([]string, 0, len(arr))
	coverEnd := new(big.Int).SetUint64(0)
	for _, r := range arr {
		if len(out) == 0 {
			out = append(out, r.cidr)
			coverEnd = new(big.Int).Set(r.end)
			continue
		}
		if r.start.Cmp(coverEnd) <= 0 && r.end.Cmp(coverEnd) <= 0 {
			// contained
			continue
		}
		if r.start.Cmp(coverEnd) == 1 {
			// disjoint → keep
			out = append(out, r.cidr)
			coverEnd = new(big.Int).Set(r.end)
			continue
		}
		// unexpected partial: keep and extend cover
		if r.end.Cmp(coverEnd) == 1 {
			out = append(out, r.cidr)
			coverEnd = new(big.Int).Set(r.end)
		}
	}
	return out
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
		_ = exec.Command("nft", "flush", "set", "inet", tableName, s).Run()
		_ = exec.Command("nft", "delete", "set", "inet", tableName, s).Run()
	}

	b.unregisterFeedKey(suff)
	b.dropExternalFeedCache(suff)

	_ = b.RebuildExternalUnions()
}

// DropEverything: delete whole table inet cfm
func (b *Backend) DropEverything() error {
	if !b.tableExists() {
		return nil
	}
	// best-effort flush first (μην αποτύχει delete λόγω refs)
	_ = exec.Command("nft", "flush", "table", family, tableName).Run()
	return b.nftCmd(fmt.Sprintf("delete table %s %s", family, tableName))
}

// ResetTable: flush whole table (rules + sets content), κρατώντας το table
func (b *Backend) ResetTable() error {
	if !b.tableExists() {
		return nil
	}
	return b.nftCmd(fmt.Sprintf("flush table %s %s", family, tableName))
}

func (b *Backend) ResetCFMTable() error {
	// Σβήσε το table αν υπάρχει (αγνόησε error αν δεν υπάρχει)
	_ = b.nftCmd(fmt.Sprintf("delete table %s %s", family, tableName))
	// Ξαναφτιάξ’ το άδειο
	return b.nftCmd(fmt.Sprintf("add table %s %s", family, tableName))
}

func (b *Backend) refreshSelfSets() {
	// άδειασε τα sets
	_ = b.nftExpr("flush set inet cfm self_v4;")
	_ = b.nftExpr("flush set inet cfm self_v6;")
	// loopbacks πάντα μέσα
	_ = b.nftExpr("add element inet cfm self_v4 { 127.0.0.0/8 };")
	_ = b.nftExpr("add element inet cfm self_v6 { ::1 };")
	_ = b.nftExpr("add element inet cfm self_v6 { fe80::/10 };")

	// όλες οι τοπικές
	ifaces, _ := net.Interfaces()
	var v4s, v6s []string
	for _, ifc := range ifaces {
		if (ifc.Flags & net.FlagUp) == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil || ip == nil {
				continue
			}
			if ip.IsLoopback() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				v4s = append(v4s, v4.String())
			} else {
				v6s = append(v6s, ip.String())
			}
		}
	}
	// batch add
	cached := make(map[string]struct{}, len(v4s)+len(v6s))
	for _, ip := range v4s {
		_ = b.nftExpr(fmt.Sprintf("add element inet cfm self_v4 { %s };", ip))
		cached[ip] = struct{}{}
	}
	for _, ip := range v6s {
		_ = b.nftExpr(fmt.Sprintf("add element inet cfm self_v6 { %s };", ip))
		cached[ip] = struct{}{}
	}
	b.selfIPsMu.Lock()
	b.selfIPs = cached
	b.selfIPsMu.Unlock()
	b.writeSelfIPsLua(cached)
}

func (b *Backend) writeSelfIPsLua(cached map[string]struct{}) {
	dir := filepath.Dir(selfIPsLuaPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		logging.Logf("[nft] self-ip lua mkdir failed path=%s err=%v", filepath.Dir(selfIPsLuaPath), err)
		return
	}

	keys := make([]string, 0, len(cached))
	for ip := range cached {
		keys = append(keys, ip)
	}
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

// isSelfIPString: true αν είναι loopback ή υπάρχει στα self_v4/self_v6
func (b *Backend) isSelfIPString(s string) bool {
	b.selfInitOnce.Do(func() {
		b.refreshSelfSets()
	})
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	b.selfIPsMu.RLock()
	_, ok := b.selfIPs[ip.String()]
	b.selfIPsMu.RUnlock()
	return ok
}

// HasElem returns true if elem is in setName without dumping the set.
func (b *Backend) HasElem(setName, elem string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := []string{"get", "element", family, tableName, setName, "{", elem, "}"}
	out, err := exec.CommandContext(ctx, "nft", args...).CombinedOutput()
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
	out, err := exec.Command("nft", "-t", "-n", "list", "table", string(family), tableName).CombinedOutput()
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

// EnsureChallengeRedirect installs NAT redirect rules for IPs in challenge sets.
// httpListen / httpsListen are like "127.0.0.1:9098" or ":9098".
func (b *Backend) EnsureChallengeRedirect(httpListen, httpsListen string) error {
	httpHost, httpPort, okHTTP := parseListenHostPort(httpListen)
	httpsHost, httpsPort, okHTTPS := parseListenHostPort(httpsListen)
	if !okHTTP && !okHTTPS {
		// nothing to do
		return nil
	}

	if !b.challengeDNATEnabled {
		_ = b.CleanupChallengeRedirect()
		return nil
	}

	// Ensure base exists (chains/sets)
	if err := b.EnsureBase(); err != nil {
		return err
	}

	// Ensure challenge sets exist BEFORE any rule references @challenge_v4/@challenge_v6
	// (otherwise nft insert rule fails with "No such file or directory" at @challenge_v4)
	if err := b.ensureSet(challengeV4, "ipv4_addr"); err != nil {
		return err
	}
	if err := b.ensureSet(challengeV6, "ipv6_addr"); err != nil {
		return err
	}

	hasComment := func(chain, label string) bool {
		// Match by comment only so formatting differences can't cause duplicates.
		return b.ruleExists(chain, fmt.Sprintf(`comment "cfm_challenge_%s"`, label))
	}

	// Ensure dedicated guard chain + early jump (so it runs BEFORE established/related accept).
	// The jump rule must not reference any sets.
	if !b.chainExists("challenge_guard") {
		if err := b.nftCmd(fmt.Sprintf(`add chain %s %s challenge_guard`, family, tableName)); err != nil {
			return fmt.Errorf("nft add chain challenge_guard: %w", err)
		}
		b.chlogf("nft add chain challenge_guard")
	}
	if !b.ruleExists("input", "jump challenge_guard") {
		if err := b.nftCmd(fmt.Sprintf(`insert rule %s %s input position 0 jump challenge_guard`, family, tableName)); err != nil {
			return fmt.Errorf("nft insert jump challenge_guard failed: %w", err)
		}
		b.chlogf("nft insert jump challenge_guard at input pos0")
	}

	addGuardRule := func(label, expr string) error {
		if hasComment("challenge_guard", label) {
			return nil
		}
		expr = strings.TrimSpace(expr) + fmt.Sprintf(` comment "cfm_challenge_%s"`, label)
		if err := b.nftCmd(fmt.Sprintf(`add rule %s %s challenge_guard %s`, family, tableName, expr)); err != nil {
			return err
		}
		b.chlogf("nft add %s: %s", label, expr)
		return nil
	}

	addInputAccept := func(label, expr string) error {
		if hasComment("input", label) {
			return nil
		}
		expr = strings.TrimSpace(expr) + fmt.Sprintf(` comment "cfm_challenge_%s"`, label)
		// IMPORTANT: keep the jump-to-guard at position 0, so the guard chain runs FIRST.
		// Insert accepts right after it.
		if err := b.nftCmd(fmt.Sprintf(`insert rule %s %s input position 0 %s`, family, tableName, expr)); err != nil {
			return err
		}
		b.chlogf("nft insert %s (pos1): %s", label, expr)
		return nil
	}

	// NOTE: we no longer insert set-dependent enforcement rules directly into input (position juggling can be brittle).
	// Challenge enforcement rules live in the dedicated challenge_guard chain.

	addNatRule := func(label, expr string) error {
		if hasComment(challengeNatChain, label) {
			return nil
		}
		expr = strings.TrimSpace(expr) + fmt.Sprintf(` comment "cfm_challenge_%s"`, label)
		if err := b.nftCmd(fmt.Sprintf(`add rule %s %s %s %s`, family, tableName, challengeNatChain, expr)); err != nil {
			return err
		}
		b.chlogf("nft add %s: %s", label, expr)
		return nil
	}

	// HTTP :80 -> challenge httpPort
	if okHTTP && httpPort > 0 {

		// DNAT to loopback if server is bound to loopback
		if httpHost == "127.0.0.1" {
			if err := addNatRule("nat_v4_80", fmt.Sprintf(`ip saddr @%s tcp dport 80 dnat to 127.0.0.1:%d`, challengeV4, httpPort)); err != nil {
				return err
			}
			// allow challenged sources to reach loopback-dnatted listener
			if err := addInputAccept("accept_v4_http", fmt.Sprintf(`ip saddr @%s ip daddr 127.0.0.1 tcp dport %d accept`, challengeV4, httpPort)); err != nil {
				return err
			}
		} else {
			// fallback: keep old behavior if not loopback-bound
			if err := addNatRule("nat_v4_80", fmt.Sprintf(`ip saddr @%s tcp dport 80 redirect to :%d`, challengeV4, httpPort)); err != nil {
				return err
			}
			if err := addInputAccept("accept_v4_http", fmt.Sprintf(`ip saddr @%s tcp dport %d accept`, challengeV4, httpPort)); err != nil {
				return err
			}
		}

		if httpHost == "::1" || httpHost == "127.0.0.1" {
			if err := addNatRule("nat_v6_80", fmt.Sprintf(`ip6 saddr @%s tcp dport 80 dnat to [::1]:%d`, challengeV6, httpPort)); err != nil {
				return err
			}
			if err := addInputAccept("accept_v6_http", fmt.Sprintf(`ip6 saddr @%s ip6 daddr ::1 tcp dport %d accept`, challengeV6, httpPort)); err != nil {
				return err
			}
		} else {
			// fallback for v6
			if err := addNatRule("nat_v6_80", fmt.Sprintf(`ip6 saddr @%s tcp dport 80 redirect to :%d`, challengeV6, httpPort)); err != nil {
				return err
			}
			if err := addInputAccept("accept_v6_http", fmt.Sprintf(`ip6 saddr @%s tcp dport %d accept`, challengeV6, httpPort)); err != nil {
				return err
			}
		}

	}

	// HTTPS :443 -> challenge httpsPort
	if okHTTPS && httpsPort > 0 {

		if httpsHost == "127.0.0.1" {
			if err := addNatRule("nat_v4_443", fmt.Sprintf(`ip saddr @%s tcp dport 443 dnat to 127.0.0.1:%d`, challengeV4, httpsPort)); err != nil {
				return err
			}
			if err := addInputAccept("accept_v4_https", fmt.Sprintf(`ip saddr @%s ip daddr 127.0.0.1 tcp dport %d accept`, challengeV4, httpsPort)); err != nil {
				return err
			}
		} else {
			if err := addNatRule("nat_v4_443", fmt.Sprintf(`ip saddr @%s tcp dport 443 redirect to :%d`, challengeV4, httpsPort)); err != nil {
				return err
			}
			if err := addInputAccept("accept_v4_https", fmt.Sprintf(`ip saddr @%s tcp dport %d accept`, challengeV4, httpsPort)); err != nil {
				return err
			}
		}

		if httpsHost == "::1" || httpsHost == "127.0.0.1" {
			if err := addNatRule("nat_v6_443", fmt.Sprintf(`ip6 saddr @%s tcp dport 443 dnat to [::1]:%d`, challengeV6, httpsPort)); err != nil {
				return err
			}
			if err := addInputAccept("accept_v6_https", fmt.Sprintf(`ip6 saddr @%s ip6 daddr ::1 tcp dport %d accept`, challengeV6, httpsPort)); err != nil {
				return err
			}
		} else {
			if err := addNatRule("nat_v6_443", fmt.Sprintf(`ip6 saddr @%s tcp dport 443 redirect to :%d`, challengeV6, httpsPort)); err != nil {
				return err
			}
			if err := addInputAccept("accept_v6_https", fmt.Sprintf(`ip6 saddr @%s tcp dport %d accept`, challengeV6, httpsPort)); err != nil {
				return err
			}
		}

	}

	// Challenge port connlimit (protect the challenge listener itself):
	// If a challenged IP tries to open too many concurrent connections to the challenge ports,
	// drop NEW connections beyond the threshold.
	// This is per-source-IP, and state naturally disappears as conns close.
	// NOTE: this matches the post-DNAT destination ports (httpPort/httpsPort), not 80/443.
	const chalConnLimit = 16 // per-IP NEW connections/sec to challenge ports
	if okHTTP && httpPort > 0 {
		if err := addGuardRule("guard_v4_http_connlimit",
			fmt.Sprintf(
				`ip saddr @%s tcp dport %d ct state new `+
					`meter chal_cl_http_v4 size 65535 { ip saddr limit rate over %d/second } drop`,
				challengeV4, httpPort, chalConnLimit)); err != nil {
			return err
		}
		if err := addGuardRule("guard_v6_http_connlimit",
			fmt.Sprintf(
				`ip6 saddr @%s tcp dport %d ct state new `+
					`meter chal_cl_http_v6 size 65535 { ip6 saddr limit rate over %d/second } drop`,
				challengeV6, httpPort, chalConnLimit)); err != nil {
			return err
		}
	}
	if okHTTPS && httpsPort > 0 {
		if err := addGuardRule("guard_v4_https_connlimit",
			fmt.Sprintf(
				`ip saddr @%s tcp dport %d ct state new `+
					`meter chal_cl_https_v4 size 65535 { ip saddr limit rate over %d/second } drop`,
				challengeV4, httpsPort, chalConnLimit)); err != nil {
			return err
		}
		if err := addGuardRule("guard_v6_https_connlimit",
			fmt.Sprintf(
				`ip6 saddr @%s tcp dport %d ct state new `+
					`meter chal_cl_https_v6 size 65535 { ip6 saddr limit rate over %d/second } drop`,
				challengeV6, httpsPort, chalConnLimit)); err != nil {
			return err
		}
	}

	// QUIC/HTTP3 bypass fix:
	// Challenged IPs must not be able to keep browsing via UDP/443 (h3/quic).
	// Dropping UDP/443 forces browsers to fall back to TCP so DNAT redirect can work.
	if okHTTPS && httpsPort > 0 {
		if err := addGuardRule("guard_v4_quic_drop", fmt.Sprintf(`ip saddr @%s udp dport 443 drop`, challengeV4)); err != nil {
			return err
		}
		if err := addGuardRule("guard_v6_quic_drop", fmt.Sprintf(`ip6 saddr @%s udp dport 443 drop`, challengeV6)); err != nil {
			return err
		}
	}

	// Kill existing keepalive connections to real web ports for challenged IPs.
	// This forces clients to reconnect, so the next NEW connection hits the NAT redirect.
	if err := addGuardRule("guard_v4_reset", fmt.Sprintf(`ip saddr @%s tcp dport {80,443} ct state established,related reject with tcp reset`, challengeV4)); err != nil {
		return err
	}
	if err := addGuardRule("guard_v6_reset", fmt.Sprintf(`ip6 saddr @%s tcp dport {80,443} ct state established,related reject with tcp reset`, challengeV6)); err != nil {
		return err
	}

	return nil
}

func parseListenHostPort(addr string) (host string, port int, ok bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", 0, false
	}
	h, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		// handle ":9098" (SplitHostPort accepts it) or "9098" (not valid)
		if strings.Count(addr, ":") == 0 {
			return "", 0, false
		}
		return "", 0, false
	}

	host = strings.TrimSpace(h)
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 {
		return host, 0, false
	}
	return host, p, true
}

// -------- challenge (source IP redirect) --------

func (b *Backend) AddChallenge(ip net.IP, ttl *time.Duration) error {
	if ip == nil {
		return errors.New("nil ip")
	}
	set := challengeV4
	if ip.To4() == nil {
		set = challengeV6
	}
	elem := ip.String()

	_ = b.RemoveChallenge(ip)

	ttlStr := ""
	if ttl != nil && *ttl > 0 {
		ttlStr = humanTimeout(*ttl)
	}

	out, err := b.nftAddElementArgv(set, elem, ttlStr)
	if err == nil {
		return nil
	}
	if strings.Contains(out, "already exists") || strings.Contains(out, "File exists") {
		_ = b.RemoveChallenge(ip)
		if out2, err2 := b.nftAddElementArgv(set, elem, ttlStr); err2 == nil {
			return nil
		} else {
			return fmt.Errorf("nft add challenge (retry) failed: %v: %s", err2, out2)
		}
	}
	return fmt.Errorf("nft add challenge failed: %v: %s", err, out)
}

func (b *Backend) RemoveChallenge(ip net.IP) error {
	if ip == nil {
		return errors.New("nil ip")
	}
	set := challengeV4
	elem := ip.String()
	if ip.To4() == nil {
		set = challengeV6
	}
	cmd := fmt.Sprintf(`delete element %s %s %s { %s }`, family, tableName, set, elem)
	out, err := b.nftOut(cmd)
	if err != nil && !strings.Contains(out, "No such file or directory") && !strings.Contains(out, "Could not delete element") {
		return fmt.Errorf("nft: %v: %s", err, out)
	}
	return nil
}

// RemoveBlockBatch removes multiple IPs from their respective sets in a single
// nft process invocation. Falls back to sequential on partial failure.
func (b *Backend) RemoveBlockBatch(ips []net.IP) error {
	if len(ips) == 0 {
		return nil
	}

	// Group by set
	v4 := make([]string, 0)
	v6 := make([]string, 0)
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}

	// Try atomic batch first: one delete per set with all IPs in { }
	// This is one nft process, one kernel transaction.
	// Fails if ANY element is missing — in that case fall back to sequential.
	var sb strings.Builder
	if len(v4) > 0 {
		fmt.Fprintf(&sb, "delete element %s %s %s { %s };\n",
			family, tableName, setV4, strings.Join(v4, ", "))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&sb, "delete element %s %s %s { %s };\n",
			family, tableName, setV6, strings.Join(v6, ", "))
	}

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(sb.String())
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil // all done in one shot
	}

	// Batch failed (likely some IPs not in set) — fall back to sequential.
	// Still just ONE goroutine, ONE ip at a time: no fork storm.
	s := string(out)
	if strings.Contains(s, "No such file or directory") ||
		strings.Contains(s, "Could not delete element") ||
		strings.Contains(s, "Element not found") {
		for _, ip := range ips {
			_ = b.RemoveBlock(ip) // already ignores "not found"
		}
		return nil
	}

	return fmt.Errorf("nft batch delete failed: %v: %s", err, s)
}

func (b *Backend) ListTableJSON(fam, table string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", "-j", "list", "table", fam, table).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nft list table %s %s: %v: %s", fam, table, err, string(out))
	}
	return out, nil
}

func (b *Backend) ListSetJSON(fam, table, set string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", "-j", "list", "set", fam, table, set).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nft list set %s %s %s: %v: %s", fam, table, set, err, string(out))
	}
	return out, nil
}

func (b *Backend) ListTableTextNoDNS(fam, table string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", "-t", "-n", "list", "table", fam, table).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("nft list table %s %s: %v: %s", fam, table, err, string(out))
	}
	return string(out), nil
}

func (b *Backend) FlushSet(fam, table, set string) error {
	out, err := exec.Command("nft", "-n", "flush", "set", fam, table, set).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft flush set %s %s %s: %v: %s", fam, table, set, err, string(out))
	}
	return nil
}
