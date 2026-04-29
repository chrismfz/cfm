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

type Backend interface {
	// Lifecycle / wiring
	EnsureBase() error
	DropEverything() error
	ResetTable() error
	SetConfigDir(dir string)
	EnableEnrichment(dirs ...string)
	GetEnricher() *enrich.Enricher
	SetReporter(r reporting.Reporter)
	SetChallengeLogger(f func(format string, args ...any))

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

	// NEW: Challenge (HTTP/HTTPS redirect for selected source IPs)
	AddChallenge(ip net.IP, ttl *time.Duration) error
	RemoveChallenge(ip net.IP) error
	SetChallengeRedirectEnabled(enabled bool)
	CleanupChallengeRedirect() error
	EnsureChallengeRedirect(httpListen, httpsListen string) error

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

	// DNAT/redirect inspection + toggle APIs (implementation-neutral aliases).
	DNATStatus(family, table string) (bool, error)
	DNATShow(family, table string) (string, error)
	DNATOn(family, table string, httpPort, httpsPort int) error
	DNATOff(family, table string) error

	// ReportBlock: centralized policy-aware API reporting.
	// source: "detector" | "autoblock" | "manual"
	// mode:   "ttl" | "permanent" | "dryrun"
	// ttlSeconds used only when mode == "ttl".
	ReportBlock(ip, comment, source, mode string, ttlSeconds int) error
}
