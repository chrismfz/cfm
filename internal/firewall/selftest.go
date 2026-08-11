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
}

// EnsureBaseSample splits one EnsureBase call into where the time went. The
// split is the key discriminator: a climbing LockWaitMs means contention (another
// op holding the backend mutex — e.g. a slow/failed feed write); a climbing
// NLWorkMs means the shared netlink connection itself is degrading; CLIWorkMs is
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
// signal; a climbing DurMs across refreshes is netlink-connection degradation.
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
