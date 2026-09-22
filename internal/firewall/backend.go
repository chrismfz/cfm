package firewall

import (
	"cfm/internal/blocklists"
	"cfm/internal/config"
	"cfm/internal/enrich"
	"cfm/internal/reporting"
	"context"
	"net"
	"time"
)

type BlockedEntry struct {
	IP      net.IP
	Expires *time.Time
	Comment string
}

// SetElementTimed pairs a set element (host IP or CIDR string) with its
// remaining TTL. Expires is zero when the element has no timeout.
type SetElementTimed struct {
	Elem    string
	Expires time.Duration
}

// Capabilities describes feature-level backend support that startup wiring can
// use to avoid engine-type hard gates.
type Capabilities struct {
	PortsPolicyInboundRules bool
	PortscanTrackingSets    bool
	NewStateDropFallback    bool
}

type CapabilityReporter interface {
	Capabilities() Capabilities
}

// Phase 2 backend operation ownership matrix (roadmap-aligned):
// - nftlib-owned operations:
//   - Lifecycle/list primitives: EnsureBase, ResetTable, List* + table/set dump helpers.
//   - Manual element writes: Add/Remove Block|Allow|Ignore (+ CIDR, batch variants).
//   - Set/bulk/feed lifecycle: EnsureSetDynamic, DeleteSetIfExists, ReplaceSetFlushAdd,
//     AddElementsBulk, FlushSet, HasElem/ListSetElementsRaw, ApplyFeed/RebuildExternalUnions/
//     PruneExternalFeeds/DropFeedSets/RemoveFeedByKey.
//   - Standards: use transaction-style commit boundaries for related mutations, fail closed on
//     partial updates, and return wrapped errors with op/family/table/set/attempt context.
//
// - nftcli-owned operations (hybrid until nftlib parity):
//   - Policy/rules programming: ApplyFloodRules, ApplyHardeningRules, ApplyPortsPolicy,
//     ApplyConnlimit, ApplyPortFlood, ApplySMTPBlock, ApplyOutboundObserve.
//   - Edge DNAT control: DNATStatus, DNATShow, DNATOn, DNATOff.
//   - Panel DNAT control: PanelDNATOn/Off/Status and scoped panel DNAT accepts.
//   - Protections: keep timeout + backpressure controls (central command runner, bounded
//     concurrency/serialization, and context cancellation propagation) on every subprocess path.
type Backend interface {
	// Lifecycle / wiring
	EnsureBase() error
	DropEverything() error
	ResetTable() error
	SetConfigDir(dir string)
	EnableEnrichment(dirs ...string)
	GetEnricher() *enrich.Enricher
	SetReporter(r reporting.Reporter)

	// Policy
	ApplyFloodRules(c *config.Config) error
	ApplyHardeningRules(c *config.Config) error
	ApplyPortsPolicy(cfg *config.PortsConfig) error
	ApplyConnlimit(rules []config.ConnlimitRule) error
	ApplyPortFlood(rules []config.PortFloodRule) error
	ApplySMTPBlock(cfg *config.SMTPBlockConfig) error
	ApplyOutboundObserve(cfg *config.OutboundConfig) error
	DumpFloodCounters()
	DumpThrottledIPs()
	LoadPortScanner()

	// Manual lists
	AddBlock(ip net.IP, comment string, ttl *time.Duration) error
	RemoveBlock(ip net.IP) error
	RemoveBlockBatch(ips []net.IP) error
	ListBlocks() ([]BlockedEntry, error)
	ListAllows() ([]BlockedEntry, error)
	AddAllow(ip net.IP, ttl *time.Duration) error
	RemoveAllow(ip net.IP) error

	// NEW: CIDR subnets (manual)
	// cidr must be canonical (but we’ll also accept any valid ParseCIDR) e.g. "47.128.0.0/14"
	AddBlockNet(cidr string, ttl *time.Duration) error
	RemoveBlockNet(cidr string) error
	AddAllowNet(cidr string, ttl *time.Duration) error
	RemoveAllowNet(cidr string) error

	// NEW: Ignore (manual) — skip enforcement but still log/notify/report
	AddIgnore(ip net.IP, ttl *time.Duration) error
	RemoveIgnore(ip net.IP) error
	AddIgnoreNet(cidr string, ttl *time.Duration) error
	RemoveIgnoreNet(cidr string) error

	// Feed/bulk/set ops + diagnostics
	ApplyFeed(ctx context.Context, f blocklists.Feed, res *blocklists.FetchResult) error
	RebuildExternalUnions() error
	PruneExternalFeeds(activeKeys []string) error
	DropFeedSets(feedName string)
	RemoveFeedByKey(feedKey string) error
	DeleteSetIfExists(name string) error
	EnsureSetDynamic(name string, v6 bool, isNet bool) error
	ReplaceSetFlushAdd(setName string, elems []string, ttl *time.Duration) error
	AddElementsBulk(setName string, elems []string, ttl *time.Duration) error
	HasElem(setName, elem string) (bool, error)
	ListSetElementsRaw(setName string) ([]string, error)
	ListSetElementsTimed(setName string) ([]SetElementTimed, error)
	ListTableJSON(family, table string) ([]byte, error)
	ListSetJSON(family, table, set string) ([]byte, error)
	ListTableTextNoDNS(family, table string) (string, error)
	ListChainText(family, table, chain string) (string, error)
	FlushSet(family, table, set string) error

	// DNAT/redirect inspection + toggle APIs (implementation-neutral aliases).
	DNATStatus(family, table string) (bool, error)
	DNATShow(family, table string) (string, error)
	DNATOn(family, table string, httpPort, httpsPort int) error
	// DNATOff removes the web redirect and its scoped accepts. CFM's own
	// table (DNATDefaultTable) is deleted whole on both backends, so no
	// redirect left in it — tagged by this backend or not — survives.
	DNATOff(family, table string) error
	// EnsureDNATAccepts re-asserts the scoped `ct status dnat` accept rules
	// in inet cfm/input for whatever web-DNAT mapping is currently active.
	// Idempotent and a no-op when web DNAT is OFF. Intended to be called
	// after ApplyPortsPolicy on every reload so the accepts survive the
	// drop-rule rewrite.
	EnsureDNATAccepts() error

	// Panel DNAT APIs manage cPanel/DirectAdmin panel redirects and scoped input accepts.
	// The accepts are nft text on both backends (panel_dnat_accepts.go).
	PanelDNATOn(priority int) error
	PanelDNATOff() error
	PanelDNATStatus() (bool, string, error)
	EnsurePanelDNATAccepts() ([]string, error)
	RemovePanelDNATAccepts() ([]string, error)
	PanelDNATAcceptState() map[int]string

	// ReportBlock: centralized policy-aware API reporting.
	// source: "detector" | "autoblock" | "manual"
	// mode:   "ttl" | "permanent" | "dryrun"
	// ttlSeconds used only when mode == "ttl".
	ReportBlock(ip, comment, source, mode string, ttlSeconds int) error
}
