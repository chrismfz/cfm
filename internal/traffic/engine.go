package traffic

import (
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultTickInterval = time.Second
)

// Collector provides the non-blocking data source used by the poll loop.
// Implementations should avoid DNS and any other potentially blocking calls.
type Collector interface {
	Collect(context.Context) ([]FlowSample, error)
}

// Config controls poll cadence and memory bounds.
type Config struct {
	TickInterval   time.Duration
	SnapshotTopN   int
	MaxFlows       int
	MaxTopTableLen int
}

func (c Config) withDefaults() Config {
	if c.TickInterval <= 0 {
		c.TickInterval = defaultTickInterval
	}
	if c.SnapshotTopN <= 0 {
		c.SnapshotTopN = 20
	}
	if c.MaxFlows <= 0 {
		c.MaxFlows = 5000
	}
	if c.MaxTopTableLen <= 0 {
		c.MaxTopTableLen = 512
	}
	return c
}

// FlowSample is a single flow measurement for one poll iteration.
type FlowSample struct {
	FlowID         string
	Protocol       string
	SrcIP          string
	SrcPort        uint16
	DstIP          string
	DstPort        uint16
	State          string
	InBytes        uint64
	OutBytes       uint64
	ProcessName    string
	PID            int
	StartedAtUnix  int64
	LastSeenUnix   int64
	ConnectionUnit uint32
}

// Snapshot is a stable output payload for API/CLI consumers.
type Snapshot struct {
	TsUnix         int64                        `json:"ts_unix"`
	WindowSec      int32                        `json:"window_sec"`
	Totals         TotalsSnapshot               `json:"totals"`
	Protocols      []ProtocolSnapshot           `json:"protocols"`
	Ports          []PortSnapshot               `json:"ports"`
	TopIPs         []IPSnapshot                 `json:"top_ips"`
	ProcessBuckets []ProcessBucketSnapshot      `json:"process_buckets"`
	Flows          []FlowSnapshot               `json:"flows"`
	Windows        map[string]WindowAggSnapshot `json:"windows"`
}

type TotalsSnapshot struct {
	InBPS             uint64 `json:"in_bps"`
	OutBPS            uint64 `json:"out_bps"`
	InBytes           uint64 `json:"in_bytes"`
	OutBytes          uint64 `json:"out_bytes"`
	ActiveConnections uint64 `json:"active_connections"`
}

type ProtocolSnapshot struct {
	Protocol    string `json:"protocol"`
	Connections uint64 `json:"connections"`
	InBPS       uint64 `json:"in_bps"`
	OutBPS      uint64 `json:"out_bps"`
	InBytes     uint64 `json:"in_bytes"`
	OutBytes    uint64 `json:"out_bytes"`
}

type PortSnapshot struct {
	Port        uint16 `json:"port"`
	Protocol    string `json:"protocol"`
	Connections uint64 `json:"connections"`
	InBPS       uint64 `json:"in_bps"`
	OutBPS      uint64 `json:"out_bps"`
	InBytes     uint64 `json:"in_bytes"`
	OutBytes    uint64 `json:"out_bytes"`
}

type IPSnapshot struct {
	IP          string `json:"ip"`
	Connections uint64 `json:"connections"`
	InBPS       uint64 `json:"in_bps"`
	OutBPS      uint64 `json:"out_bps"`
	InBytes     uint64 `json:"in_bytes"`
	OutBytes    uint64 `json:"out_bytes"`
}

type ProcessBucketSnapshot struct {
	Bucket      string `json:"bucket"`
	Connections uint64 `json:"connections"`
	InBPS       uint64 `json:"in_bps"`
	OutBPS      uint64 `json:"out_bps"`
	InBytes     uint64 `json:"in_bytes"`
	OutBytes    uint64 `json:"out_bytes"`
}

type FlowSnapshot struct {
	FlowID        string `json:"flow_id"`
	Protocol      string `json:"protocol"`
	SrcIP         string `json:"src_ip"`
	SrcPort       uint16 `json:"src_port"`
	DstIP         string `json:"dst_ip"`
	DstPort       uint16 `json:"dst_port"`
	State         string `json:"state"`
	InBPS         uint64 `json:"in_bps"`
	OutBPS        uint64 `json:"out_bps"`
	InBytes       uint64 `json:"in_bytes"`
	OutBytes      uint64 `json:"out_bytes"`
	ProcessName   string `json:"process_name"`
	PID           int    `json:"pid"`
	StartedAtUnix int64  `json:"started_at_unix"`
	LastSeenUnix  int64  `json:"last_seen_unix"`
}

type WindowAggSnapshot struct {
	WindowSec int32          `json:"window_sec"`
	Totals    TotalsSnapshot `json:"totals"`
}

type agg struct {
	inBytes     uint64
	outBytes    uint64
	connections uint64
}

type tickAggregate struct {
	totals    agg
	protocols map[string]agg
	ports     map[portKey]agg
	topIPs    map[string]agg
	processes map[string]agg
}

type portKey struct {
	protocol string
	port     uint16
}

type rollingWindow struct {
	cap  int
	ring []tickAggregate
	idx  int
	used int
	sum  tickAggregate
}

func newRollingWindow(size int) rollingWindow {
	return rollingWindow{
		cap:  size,
		ring: make([]tickAggregate, size),
		sum:  newTickAggregate(0),
	}
}

func (w *rollingWindow) add(a tickAggregate, cfg Config) {
	if w.cap == 0 {
		return
	}
	if w.used == w.cap {
		w.sub(w.ring[w.idx])
	} else {
		w.used++
	}
	w.ring[w.idx] = a
	w.merge(a, cfg)
	w.idx = (w.idx + 1) % w.cap
}

func (w *rollingWindow) merge(a tickAggregate, cfg Config) {
	w.sum.totals.inBytes += a.totals.inBytes
	w.sum.totals.outBytes += a.totals.outBytes
	w.sum.totals.connections += a.totals.connections
	mergeMapAgg(w.sum.protocols, a.protocols, cfg.MaxTopTableLen)
	mergePortAgg(w.sum.ports, a.ports, cfg.MaxTopTableLen)
	mergeMapAgg(w.sum.topIPs, a.topIPs, cfg.MaxTopTableLen)
	mergeMapAgg(w.sum.processes, a.processes, cfg.MaxTopTableLen)
}

func (w *rollingWindow) sub(a tickAggregate) {
	w.sum.totals.inBytes -= min(w.sum.totals.inBytes, a.totals.inBytes)
	w.sum.totals.outBytes -= min(w.sum.totals.outBytes, a.totals.outBytes)
	w.sum.totals.connections -= min(w.sum.totals.connections, a.totals.connections)
	subMapAgg(w.sum.protocols, a.protocols)
	subPortAgg(w.sum.ports, a.ports)
	subMapAgg(w.sum.topIPs, a.topIPs)
	subMapAgg(w.sum.processes, a.processes)
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

// Engine polls collector data every second and exposes stable snapshots.
type Engine struct {
	collector Collector
	cfg       Config

	mu     sync.Mutex
	flows  map[string]FlowSample
	win10s rollingWindow
	win60s rollingWindow
	win5m  rollingWindow
	latest atomic.Pointer[Snapshot]
}

func NewEngine(collector Collector, cfg Config) (*Engine, error) {
	if collector == nil {
		return nil, errors.New("traffic engine requires collector")
	}
	cfg = cfg.withDefaults()
	e := &Engine{
		collector: collector,
		cfg:       cfg,
		flows:     make(map[string]FlowSample, cfg.MaxFlows),
		win10s:    newRollingWindow(10),
		win60s:    newRollingWindow(60),
		win5m:     newRollingWindow(300),
	}
	init := &Snapshot{TsUnix: time.Now().Unix(), WindowSec: int32(cfg.TickInterval / time.Second), Windows: make(map[string]WindowAggSnapshot)}
	e.latest.Store(init)
	return e, nil
}

func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.TickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.pollOnce(ctx)
		}
	}
}

func (e *Engine) Snapshot() Snapshot {
	ptr := e.latest.Load()
	if ptr == nil {
		return Snapshot{}
	}
	return *ptr
}

func (e *Engine) pollOnce(ctx context.Context) {
	samples, err := e.collector.Collect(ctx)
	if err != nil {
		return
	}
	now := time.Now().Unix()

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, s := range samples {
		if s.FlowID == "" {
			continue
		}
		s.LastSeenUnix = now
		e.flows[s.FlowID] = s
	}
	e.trimFlows()

	tick := e.aggregateTick()
	e.win10s.add(tick, e.cfg)
	e.win60s.add(tick, e.cfg)
	e.win5m.add(tick, e.cfg)

	snap := e.buildSnapshot(now, tick)
	e.latest.Store(&snap)
}

func (e *Engine) trimFlows() {
	if len(e.flows) <= e.cfg.MaxFlows {
		return
	}
	type pair struct {
		id   string
		seen int64
	}
	all := make([]pair, 0, len(e.flows))
	for id, f := range e.flows {
		all = append(all, pair{id: id, seen: f.LastSeenUnix})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seen > all[j].seen })
	for _, p := range all[e.cfg.MaxFlows:] {
		delete(e.flows, p.id)
	}
}

func (e *Engine) aggregateTick() tickAggregate {
	a := newTickAggregate(e.cfg.MaxTopTableLen)
	for _, f := range e.flows {
		conns := uint64(maxInt(int(f.ConnectionUnit), 1))
		addAgg(&a.totals, f.InBytes, f.OutBytes, conns)
		addMapAgg(a.protocols, safeKey(f.Protocol, "unknown"), f.InBytes, f.OutBytes, conns, e.cfg.MaxTopTableLen)
		addPortAgg(a.ports, portKey{protocol: safeKey(f.Protocol, "unknown"), port: f.DstPort}, f.InBytes, f.OutBytes, conns, e.cfg.MaxTopTableLen)
		addMapAgg(a.topIPs, safeKey(f.DstIP, "unknown"), f.InBytes, f.OutBytes, conns, e.cfg.MaxTopTableLen)
		addMapAgg(a.processes, processBucket(f), f.InBytes, f.OutBytes, conns, e.cfg.MaxTopTableLen)
	}
	return a
}

func processBucket(f FlowSample) string {
	if f.ProcessName == "" {
		return "unknown"
	}
	return f.ProcessName
}

func safeKey(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func newTickAggregate(capHint int) tickAggregate {
	if capHint <= 0 {
		capHint = 1
	}
	return tickAggregate{
		protocols: make(map[string]agg, capHint),
		ports:     make(map[portKey]agg, capHint),
		topIPs:    make(map[string]agg, capHint),
		processes: make(map[string]agg, capHint),
	}
}

func addAgg(a *agg, in, out, connections uint64) {
	a.inBytes += in
	a.outBytes += out
	a.connections += connections
}

func addMapAgg(dst map[string]agg, key string, in, out, conns uint64, capLen int) {
	v, ok := dst[key]
	if !ok && len(dst) >= capLen {
		return
	}
	addAgg(&v, in, out, conns)
	dst[key] = v
}

func addPortAgg(dst map[portKey]agg, key portKey, in, out, conns uint64, capLen int) {
	v, ok := dst[key]
	if !ok && len(dst) >= capLen {
		return
	}
	addAgg(&v, in, out, conns)
	dst[key] = v
}

func mergeMapAgg(dst, src map[string]agg, capLen int) {
	for k, v := range src {
		d, ok := dst[k]
		if !ok && len(dst) >= capLen {
			continue
		}
		addAgg(&d, v.inBytes, v.outBytes, v.connections)
		dst[k] = d
	}
}

func mergePortAgg(dst, src map[portKey]agg, capLen int) {
	for k, v := range src {
		d, ok := dst[k]
		if !ok && len(dst) >= capLen {
			continue
		}
		addAgg(&d, v.inBytes, v.outBytes, v.connections)
		dst[k] = d
	}
}

func subMapAgg(dst, src map[string]agg) {
	for k, v := range src {
		d, ok := dst[k]
		if !ok {
			continue
		}
		d.inBytes -= min(d.inBytes, v.inBytes)
		d.outBytes -= min(d.outBytes, v.outBytes)
		d.connections -= min(d.connections, v.connections)
		if d.inBytes == 0 && d.outBytes == 0 && d.connections == 0 {
			delete(dst, k)
			continue
		}
		dst[k] = d
	}
}

func subPortAgg(dst, src map[portKey]agg) {
	for k, v := range src {
		d, ok := dst[k]
		if !ok {
			continue
		}
		d.inBytes -= min(d.inBytes, v.inBytes)
		d.outBytes -= min(d.outBytes, v.outBytes)
		d.connections -= min(d.connections, v.connections)
		if d.inBytes == 0 && d.outBytes == 0 && d.connections == 0 {
			delete(dst, k)
			continue
		}
		dst[k] = d
	}
}

func (e *Engine) buildSnapshot(now int64, current tickAggregate) Snapshot {
	windowSec := uint64(maxInt(int(e.cfg.TickInterval/time.Second), 1))
	s := Snapshot{
		TsUnix:         now,
		WindowSec:      int32(windowSec),
		Totals:         toTotals(current.totals, windowSec),
		Protocols:      rankProtocols(current.protocols, e.cfg.SnapshotTopN, windowSec),
		Ports:          rankPorts(current.ports, e.cfg.SnapshotTopN, windowSec),
		TopIPs:         rankIPs(current.topIPs, e.cfg.SnapshotTopN, windowSec),
		ProcessBuckets: rankProcesses(current.processes, e.cfg.SnapshotTopN, windowSec),
		Flows:          rankFlows(e.flows, e.cfg.SnapshotTopN, windowSec),
		Windows:        make(map[string]WindowAggSnapshot, 3),
	}
	s.Windows["10s"] = windowSummary(e.win10s.sum.totals, 10)
	s.Windows["60s"] = windowSummary(e.win60s.sum.totals, 60)
	s.Windows["5m"] = windowSummary(e.win5m.sum.totals, 300)
	return s
}

func windowSummary(a agg, windowSec uint64) WindowAggSnapshot {
	return WindowAggSnapshot{WindowSec: int32(windowSec), Totals: toTotals(a, windowSec)}
}

func toTotals(a agg, windowSec uint64) TotalsSnapshot {
	if windowSec == 0 {
		windowSec = 1
	}
	return TotalsSnapshot{
		InBPS:             (a.inBytes * 8) / windowSec,
		OutBPS:            (a.outBytes * 8) / windowSec,
		InBytes:           a.inBytes,
		OutBytes:          a.outBytes,
		ActiveConnections: a.connections,
	}
}

func rankProtocols(m map[string]agg, n int, windowSec uint64) []ProtocolSnapshot {
	type row struct {
		k string
		a agg
	}
	rows := make([]row, 0, len(m))
	for k, v := range m {
		rows = append(rows, row{k: k, a: v})
	}
	sort.Slice(rows, func(i, j int) bool {
		iw, jw := rows[i].a.inBytes+rows[i].a.outBytes, rows[j].a.inBytes+rows[j].a.outBytes
		if iw == jw {
			return rows[i].k < rows[j].k
		}
		return iw > jw
	})
	if n > len(rows) {
		n = len(rows)
	}
	out := make([]ProtocolSnapshot, 0, n)
	for _, r := range rows[:n] {
		out = append(out, ProtocolSnapshot{Protocol: r.k, Connections: r.a.connections, InBPS: (r.a.inBytes * 8) / windowSec, OutBPS: (r.a.outBytes * 8) / windowSec, InBytes: r.a.inBytes, OutBytes: r.a.outBytes})
	}
	return out
}

func rankPorts(m map[portKey]agg, n int, windowSec uint64) []PortSnapshot {
	type row struct {
		k portKey
		a agg
	}
	rows := make([]row, 0, len(m))
	for k, v := range m {
		rows = append(rows, row{k: k, a: v})
	}
	sort.Slice(rows, func(i, j int) bool {
		iw, jw := rows[i].a.inBytes+rows[i].a.outBytes, rows[j].a.inBytes+rows[j].a.outBytes
		if iw == jw {
			if rows[i].k.port == rows[j].k.port {
				return rows[i].k.protocol < rows[j].k.protocol
			}
			return rows[i].k.port < rows[j].k.port
		}
		return iw > jw
	})
	if n > len(rows) {
		n = len(rows)
	}
	out := make([]PortSnapshot, 0, n)
	for _, r := range rows[:n] {
		out = append(out, PortSnapshot{Port: r.k.port, Protocol: r.k.protocol, Connections: r.a.connections, InBPS: (r.a.inBytes * 8) / windowSec, OutBPS: (r.a.outBytes * 8) / windowSec, InBytes: r.a.inBytes, OutBytes: r.a.outBytes})
	}
	return out
}

func rankIPs(m map[string]agg, n int, windowSec uint64) []IPSnapshot {
	type row struct {
		k string
		a agg
	}
	rows := make([]row, 0, len(m))
	for k, v := range m {
		rows = append(rows, row{k: k, a: v})
	}
	sort.Slice(rows, func(i, j int) bool {
		iw, jw := rows[i].a.inBytes+rows[i].a.outBytes, rows[j].a.inBytes+rows[j].a.outBytes
		if iw == jw {
			return rows[i].k < rows[j].k
		}
		return iw > jw
	})
	if n > len(rows) {
		n = len(rows)
	}
	out := make([]IPSnapshot, 0, n)
	for _, r := range rows[:n] {
		out = append(out, IPSnapshot{IP: r.k, Connections: r.a.connections, InBPS: (r.a.inBytes * 8) / windowSec, OutBPS: (r.a.outBytes * 8) / windowSec, InBytes: r.a.inBytes, OutBytes: r.a.outBytes})
	}
	return out
}

func rankProcesses(m map[string]agg, n int, windowSec uint64) []ProcessBucketSnapshot {
	type row struct {
		k string
		a agg
	}
	rows := make([]row, 0, len(m))
	for k, v := range m {
		rows = append(rows, row{k: k, a: v})
	}
	sort.Slice(rows, func(i, j int) bool {
		iw, jw := rows[i].a.inBytes+rows[i].a.outBytes, rows[j].a.inBytes+rows[j].a.outBytes
		if iw == jw {
			return rows[i].k < rows[j].k
		}
		return iw > jw
	})
	if n > len(rows) {
		n = len(rows)
	}
	out := make([]ProcessBucketSnapshot, 0, n)
	for _, r := range rows[:n] {
		out = append(out, ProcessBucketSnapshot{Bucket: r.k, Connections: r.a.connections, InBPS: (r.a.inBytes * 8) / windowSec, OutBPS: (r.a.outBytes * 8) / windowSec, InBytes: r.a.inBytes, OutBytes: r.a.outBytes})
	}
	return out
}

func rankFlows(m map[string]FlowSample, n int, windowSec uint64) []FlowSnapshot {
	rows := make([]FlowSample, 0, len(m))
	for _, v := range m {
		rows = append(rows, v)
	}
	sort.Slice(rows, func(i, j int) bool {
		iw, jw := rows[i].InBytes+rows[i].OutBytes, rows[j].InBytes+rows[j].OutBytes
		if iw == jw {
			return rows[i].FlowID < rows[j].FlowID
		}
		return iw > jw
	})
	if n > len(rows) {
		n = len(rows)
	}
	out := make([]FlowSnapshot, 0, n)
	for _, r := range rows[:n] {
		out = append(out, FlowSnapshot{
			FlowID: r.FlowID, Protocol: r.Protocol, SrcIP: r.SrcIP, SrcPort: r.SrcPort,
			DstIP: r.DstIP, DstPort: r.DstPort, State: r.State,
			InBPS: (r.InBytes * 8) / windowSec, OutBPS: (r.OutBytes * 8) / windowSec,
			InBytes: r.InBytes, OutBytes: r.OutBytes,
			ProcessName: r.ProcessName, PID: r.PID,
			StartedAtUnix: r.StartedAtUnix, LastSeenUnix: r.LastSeenUnix,
		})
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
