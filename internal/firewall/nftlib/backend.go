//go:build linux

// Package nftlib implements firewall.Backend using github.com/google/nftables
// (direct netlink, zero forks). All data-plane operations go through netlink;
// two diagnostic methods (ListTableTextNoDNS, ListChainText) run nft once for
// human-readable text output but are never on the hot path.
package nftlib

import (
	"fmt"
	"sync"
	"time"

	cfgpkg "cfm/internal/config"
	enrichpkg "cfm/internal/enrich"
	"cfm/internal/firewall"
	"cfm/internal/firewall/autoblock"
	"cfm/internal/firewall/selfip"
	"cfm/internal/reporting"

	"github.com/google/nftables"
)

// extFeedData mirrors nft.extFeedData — the in-memory element cache that
// lets RebuildExternalUnions avoid reading the kernel on every feed update.
type extFeedData struct {
	H4  []string
	N4  []string
	H6  []string
	N6  []string
	TTL *time.Duration
}

// Compile-time: nftlib.Backend must satisfy firewall.Backend.
// Build fails here — not at runtime — if any method is missing.
var _ firewall.Backend = (*Backend)(nil)

const (
	cfmTableName = "cfm"

	setBlockV4     = "block_v4"
	setBlockV6     = "block_v6"
	setAllowV4     = "allow_v4"
	setAllowV6     = "allow_v6"
	setBlockV4Net  = "block_v4_nets"
	setBlockV6Net  = "block_v6_nets"
	setAllowV4Net  = "allow_v4_nets"
	setAllowV6Net  = "allow_v6_nets"
	setIgnoreV4    = "ignore_v4"
	setIgnoreV6    = "ignore_v6"
	setIgnoreV4Net = "ignore_v4_nets"
	setIgnoreV6Net = "ignore_v6_nets"
)

// Backend implements firewall.Backend using github.com/google/nftables.
// All data-plane operations use netlink directly (zero forks, zero execs).
type Backend struct {
	conn *nftables.Conn
	mu   sync.Mutex

	// namedSets and table are lazy-populated on first use.
	// Call invalidateCache() after any structural change.
	namedSets map[string]*nftables.Set
	table     *nftables.Table

	// External feed element cache — avoids kernel reads on every feed update.
	extFeedMu sync.RWMutex
	extAllow  map[string]extFeedData // feedKey → data
	extBlock  map[string]extFeedData // feedKey → data
	feedKeys  map[string]struct{}    // active sanitized feed keys

	// appliedHash is the content hash of the last full-replace successfully
	// written to a PERMANENT (no-TTL) set, so ReplaceSetFlushAdd can skip
	// rewriting an unchanged set (e.g. a blocklist that didn't change this hour).
	// Guarded by b.mu (all set writes hold it) and DROPPED by invalidateCache on
	// any structural change, so a recreated/flushed set is always rewritten.
	appliedHash map[string]uint64

	// Wiring fields set by callers at startup.
	enr           *enrichpkg.Enricher
	reporter      reporting.Reporter
	challengeLogf func(format string, args ...any)
	cfgDir        string


	// cfg is stored in ApplyFloodRules so telemetry methods can read throttle
	// and portscan config without re-reading the config file on every tick.
	cfg *cfgpkg.Config

	// ab evaluates the sliding-window auto-block algorithm.
	ab *autoblock.Evaluator

	// last tracks previous flood counter packet counts for delta logging.
	last map[string]uint64

	// Overlap guards for telemetry goroutines.
	floodDumpMu      sync.Mutex
	floodDumpRunning bool
	portScanMu       sync.Mutex
	portScanRunning  bool

	// Per-IP debounce maps for auto-block actions.
	lastAutoBlockAt map[string]time.Time
	lastIgnoredAt   map[string]time.Time

	// selfResolver answers isSelfIP queries via net.Interfaces (no subprocess).
	selfResolver *selfip.Resolver

	// flood rebuild deduplication (same semantics as nft backend).
	lastFloodHash    uint64
	lastFloodRebuild time.Time

	// Self-test instrumentation (read-only diagnostics; see selftest.go). Guarded
	// by statMu — NEVER b.mu — so recording a measurement can't add contention to
	// the very path (EnsureBase / set writes) we are measuring.
	statMu     sync.Mutex
	ebBuf      [ensureBaseRingCap]ebSample // fixed ring of recent EnsureBase timings
	ebN        int                         // total EnsureBase calls (ring index = ebN % cap)
	feedWrites map[string]fwSample         // latest write per set name
}

// New opens a lasting netlink connection and returns a ready nftlib.Backend.
func New() (*Backend, error) {
	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, fmt.Errorf("nftlib: open netlink conn: %w", err)
	}
	return &Backend{
		conn:                     conn,
		namedSets:                make(map[string]*nftables.Set),
		extAllow:                 make(map[string]extFeedData),
		extBlock:                 make(map[string]extFeedData),
		feedKeys:                 make(map[string]struct{}),
		ab:                       autoblock.New(),
		last:                     make(map[string]uint64),
		lastAutoBlockAt:          make(map[string]time.Time),
		lastIgnoredAt:            make(map[string]time.Time),
		selfResolver:             selfip.New(),
		feedWrites:               make(map[string]fwSample),
		appliedHash:              make(map[string]uint64),
	}, nil
}

func (b *Backend) Capabilities() firewall.Capabilities {
	return firewall.Capabilities{
		PortsPolicyInboundRules: true,
		PortscanTrackingSets:    true,
		NewStateDropFallback:    true,
	}
}
