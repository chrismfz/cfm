package firewall

// Self-test diagnostics for the firewall backend — a READ-ONLY snapshot used to
// root-cause nftlib slowdowns (the EnsureBase duration climbing over a run) and
// feed-apply failures (a large feed that fails to write with "message too long").
// Only the nftlib backend records these; the exec-nft backend does not implement
// SelfTester, so the endpoint reports available=false there.

// NftlibSelfTest is the diagnostics snapshot.
type NftlibSelfTest struct {
	Engine string `json:"engine"`
	// Samples is the total number of EnsureBase calls observed since boot
	// (EnsureBaseRecent is the bounded tail of these).
	Samples          int                `json:"samples"`
	EnsureBaseRecent []EnsureBaseSample `json:"ensure_base_recent"`
	// EnsureBaseWorst is the slowest observed call in the retained window — the
	// one to look at first when EnsureBase is climbing.
	EnsureBaseWorst *EnsureBaseSample `json:"ensure_base_worst,omitempty"`
	FeedWrites      []FeedWriteSample `json:"feed_writes"`
	// Netlink covers every netlink call the backend makes — reads such as the
	// heartbeat's DNAT probe as well as batch writes — not just EnsureBase.
	// The nft CLI calls some paths make are not included.
	Netlink *NetlinkStats `json:"netlink,omitempty"`
}

// NetlinkStats summarises the backend's netlink calls since boot. Each runs on
// its own socket. Reads (dumps, lookups) carry an OpTimeoutMs deadline, so a
// stuck read shows up here as a timeout instead of holding the backend lock
// forever; writes carry none, because the kernel may still be applying a batch
// the deadline would report as failed. Timeouts > 0 means a read got no answer
// for that long; SlowRecent names which calls, and when.
type NetlinkStats struct {
	OpTimeoutMs int64  `json:"op_timeout_ms"`
	Ops         uint64 `json:"ops"`
	// Errors counts every failed round-trip, including routine not-found
	// lookups; Timeouts is the one that means trouble.
	Errors   uint64 `json:"errors"`
	Timeouts uint64 `json:"timeouts"`
	// DeadlineUnsupported is set if the socket refused a deadline; operations
	// then run unbounded, as they did before deadlines existed.
	DeadlineUnsupported string            `json:"deadline_unsupported,omitempty"`
	LastTimeout         *NetlinkOpSample  `json:"last_timeout,omitempty"`
	SlowRecent          []NetlinkOpSample `json:"slow_recent"` // ≥1s or timed out, oldest first
}

// NetlinkOpSample is one slow or timed-out netlink round-trip.
type NetlinkOpSample struct {
	At    string `json:"at"` // RFC3339
	Op    string `json:"op"` // nftables call, e.g. GetRules, Flush
	DurMs int64  `json:"dur_ms"`
	Err   string `json:"err,omitempty"`
}

// EnsureBaseSample splits one EnsureBase call into where the time went. The
// split is the key discriminator: a climbing LockWaitMs means contention (another
// op holding the backend mutex — e.g. a slow/failed feed write); a climbing
// NLWorkMs means the kernel is slow to apply the batch; CLIWorkMs is
// the `nft` CLI portion (self-sets + base input rules).
type EnsureBaseSample struct {
	At         string `json:"at"` // RFC3339
	LockWaitMs int64  `json:"lock_wait_ms"`
	NLWorkMs   int64  `json:"nl_work_ms"`
	CLIWorkMs  int64  `json:"cli_work_ms"`
	Err        string `json:"err,omitempty"`
}

// FeedWriteSample is the latest observed write of one feed/union set. A non-empty
// Err with a large Elems (e.g. "message too long") is the "feed not applied"
// signal; a climbing DurMs across refreshes means the kernel side is slowing down.
type FeedWriteSample struct {
	Set   string `json:"set"`
	At    string `json:"at"` // RFC3339
	Elems int    `json:"elems"`
	DurMs int64  `json:"dur_ms"`
	Err   string `json:"err,omitempty"`
}

// SelfTester is implemented by backends that expose self-test diagnostics
// (currently only nftlib). Callers type-assert a firewall.Backend to it.
type SelfTester interface {
	NftlibSelfTest() NftlibSelfTest
}
