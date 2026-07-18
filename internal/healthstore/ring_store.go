package healthstore

import (
	"strings"
	"sync"
	"time"
)

// DefaultCapacity sizes the per-node ring for a full day of history: the
// health detector samples every 10-20s, so 8640 slots cover 24h at 10s
// (48h at 20s). Sample is ~120 bytes → ~1 MB per node; the WebUI Health
// page's 24h window reads the whole ring. Was 720 (only 2-4h) before the
// Health page shipped.
const DefaultCapacity = 8640

type NodeMeta struct {
	NodeID     string    `json:"node_id"`
	Capacity   int       `json:"capacity"`
	Count      int       `json:"count"`
	Appends    uint64    `json:"appends"`
	OldestAt   time.Time `json:"oldest_at"`
	LatestAt   time.Time `json:"latest_at"`
	LastAppend time.Time `json:"last_append_at"`
}

type RingStore struct {
	mu       sync.RWMutex
	capacity int
	nodes    map[string]*nodeRing
}

type nodeRing struct {
	samples    []Sample
	head       int
	count      int
	appends    uint64
	lastAppend time.Time
}

type Sample struct {
	NodeID      string    `json:"node_id"`
	Hostname    string    `json:"hostname"`
	CollectedAt time.Time `json:"collected_at"`

	Load1       float64 `json:"load1"`
	CPUPct      float64 `json:"cpu_pct"` // real busy% from /proc/stat deltas; 0 on the seeding tick
	RamUsedPct  float64 `json:"ram_used_pct"`
	SwapUsedPct float64 `json:"swap_used_pct"`
	DiskRootPct float64 `json:"disk_root_pct"`
	DiskTmpPct  float64 `json:"disk_tmp_pct"`
	TempMaxC    float64 `json:"temp_max_c"`
	RxMbps      float64 `json:"rx_mbps"`
	TxMbps      float64 `json:"tx_mbps"`
}

func NewRingStore(capacity int) *RingStore {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &RingStore{capacity: capacity, nodes: make(map[string]*nodeRing)}
}

func (s *RingStore) Append(node string, sample Sample) {
	node = normalizeNode(node)
	if node == "" {
		return
	}
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	r := s.ensureNodeLocked(node)
	if r.count < s.capacity {
		idx := (r.head + r.count) % s.capacity
		r.samples[idx] = sample
		r.count++
	} else {
		r.samples[r.head] = sample
		r.head = (r.head + 1) % s.capacity
	}
	r.appends++
	r.lastAppend = now
}

func (s *RingStore) Latest(node string) (Sample, bool) {
	node = normalizeNode(node)
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.nodes[node]
	if r == nil || r.count == 0 {
		return Sample{}, false
	}
	idx := (r.head + r.count - 1) % s.capacity
	return r.samples[idx], true
}

func (s *RingStore) Range(node string, from, to time.Time) []Sample {
	node = normalizeNode(node)
	from = from.UTC()
	to = to.UTC()
	if !from.IsZero() && !to.IsZero() && from.After(to) {
		from, to = to, from
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.nodes[node]
	if r == nil || r.count == 0 {
		return nil
	}

	out := make([]Sample, 0, r.count)
	for i := 0; i < r.count; i++ {
		idx := (r.head + i) % s.capacity
		sm := r.samples[idx]
		ts := sm.CollectedAt.UTC()
		if !from.IsZero() && ts.Before(from) {
			continue
		}
		if !to.IsZero() && ts.After(to) {
			continue
		}
		out = append(out, sm)
	}
	return out
}

func (s *RingStore) LastWindow(node string, now time.Time, window time.Duration) []Sample {
	if window <= 0 {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return s.Range(node, now.Add(-window), now)
}

func (s *RingStore) Last1h(node string, now time.Time) []Sample {
	return s.LastWindow(node, now, time.Hour)
}

func (s *RingStore) Last6h(node string, now time.Time) []Sample {
	return s.LastWindow(node, now, 6*time.Hour)
}

func (s *RingStore) Last24h(node string, now time.Time) []Sample {
	return s.LastWindow(node, now, 24*time.Hour)
}

func (s *RingStore) Meta(node string) (NodeMeta, bool) {
	node = normalizeNode(node)
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.nodes[node]
	if r == nil || r.count == 0 {
		return NodeMeta{}, false
	}
	oldest := r.samples[r.head].CollectedAt.UTC()
	latestIdx := (r.head + r.count - 1) % s.capacity
	latest := r.samples[latestIdx].CollectedAt.UTC()
	return NodeMeta{
		NodeID:     node,
		Capacity:   s.capacity,
		Count:      r.count,
		Appends:    r.appends,
		OldestAt:   oldest,
		LatestAt:   latest,
		LastAppend: r.lastAppend,
	}, true
}

func (s *RingStore) ensureNodeLocked(node string) *nodeRing {
	r := s.nodes[node]
	if r != nil {
		return r
	}
	r = &nodeRing{samples: make([]Sample, s.capacity)}
	s.nodes[node] = r
	return r
}

func normalizeNode(node string) string {
	return strings.TrimSpace(node)
}

var (
	globalMu    sync.RWMutex
	globalStore = NewRingStore(DefaultCapacity)
)

func Global() *RingStore {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalStore
}

func SetGlobal(store *RingStore) {
	if store == nil {
		store = NewRingStore(DefaultCapacity)
	}
	globalMu.Lock()
	globalStore = store
	globalMu.Unlock()
}
