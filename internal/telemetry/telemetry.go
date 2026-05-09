package telemetry

import (
	"sync"
	"sync/atomic"
	"time"
)

type detectorStats struct {
	runs       atomic.Uint64
	failures   atomic.Uint64
	timeouts   atomic.Uint64
	totalRunNS atomic.Uint64
}

type webdetectorStats struct {
	linesSeen       atomic.Uint64
	parseFailures   atomic.Uint64
	ingestCalls     atomic.Uint64
	ingestTotalNS   atomic.Uint64
	runOnceCalls    atomic.Uint64
	runOnceTotalNS  atomic.Uint64
	runOnceFailures atomic.Uint64
}

type Store struct {
	detectors sync.Map // string -> *detectorStats
	webdet    webdetectorStats
}

var global Store

type DetectorSnapshot struct {
	Name            string  `json:"name"`
	Runs            uint64  `json:"runs"`
	Failures        uint64  `json:"failures"`
	Timeouts        uint64  `json:"timeouts"`
	AvgRunMS        float64 `json:"avg_run_ms"`
	TotalRunSeconds float64 `json:"total_run_seconds"`
}

type WebdetectorSnapshot struct {
	LinesSeen       uint64  `json:"lines_seen"`
	ParseFailures   uint64  `json:"parse_failures"`
	IngestCalls     uint64  `json:"ingest_calls"`
	AvgIngestUS     float64 `json:"avg_ingest_us"`
	RunOnceCalls    uint64  `json:"run_once_calls"`
	RunOnceFailures uint64  `json:"run_once_failures"`
	AvgRunOnceMS    float64 `json:"avg_run_once_ms"`
}

type LiveSnapshot struct {
	Now       time.Time           `json:"now"`
	Detectors []DetectorSnapshot  `json:"detectors"`
	Webdet    WebdetectorSnapshot `json:"webdetector"`
}

func getDetector(name string) *detectorStats {
	if name == "" {
		name = "unknown"
	}
	if v, ok := global.detectors.Load(name); ok {
		return v.(*detectorStats)
	}
	d := &detectorStats{}
	actual, _ := global.detectors.LoadOrStore(name, d)
	return actual.(*detectorStats)
}

func RecordDetectorRun(name string, dur time.Duration, failed bool) {
	d := getDetector(name)
	d.runs.Add(1)
	if failed {
		d.failures.Add(1)
	}
	if dur > 0 {
		d.totalRunNS.Add(uint64(dur.Nanoseconds()))
	}
}

func RecordDetectorTimeout(name string) {
	getDetector(name).timeouts.Add(1)
}

func RecordWebdetLineParsed() {
	global.webdet.linesSeen.Add(1)
}

func RecordWebdetParseFailure() {
	global.webdet.parseFailures.Add(1)
}

func RecordWebdetIngestDuration(d time.Duration) {
	global.webdet.ingestCalls.Add(1)
	if d > 0 {
		global.webdet.ingestTotalNS.Add(uint64(d.Nanoseconds()))
	}
}

func RecordWebdetRunOnce(d time.Duration, failed bool) {
	global.webdet.runOnceCalls.Add(1)
	if failed {
		global.webdet.runOnceFailures.Add(1)
	}
	if d > 0 {
		global.webdet.runOnceTotalNS.Add(uint64(d.Nanoseconds()))
	}
}

func Snapshot() LiveSnapshot {
	s := LiveSnapshot{Now: time.Now().UTC()}
	global.detectors.Range(func(k, v any) bool {
		name := k.(string)
		d := v.(*detectorStats)
		runs := d.runs.Load()
		totalNS := d.totalRunNS.Load()
		avgMS := 0.0
		if runs > 0 {
			avgMS = float64(totalNS) / float64(runs) / 1_000_000
		}
		s.Detectors = append(s.Detectors, DetectorSnapshot{
			Name:            name,
			Runs:            runs,
			Failures:        d.failures.Load(),
			Timeouts:        d.timeouts.Load(),
			AvgRunMS:        avgMS,
			TotalRunSeconds: float64(totalNS) / 1_000_000_000,
		})
		return true
	})

	// Take the address: webdetectorStats holds atomic.Uint64 fields whose
	// noCopy marker fires under `go vet` if copied by value. Reads via
	// pointer don't change the per-field Load() semantics.
	wd := &global.webdet
	ingestCalls := wd.ingestCalls.Load()
	runCalls := wd.runOnceCalls.Load()
	avgIngestUS := 0.0
	if ingestCalls > 0 {
		avgIngestUS = float64(wd.ingestTotalNS.Load()) / float64(ingestCalls) / 1_000
	}
	avgRunMS := 0.0
	if runCalls > 0 {
		avgRunMS = float64(wd.runOnceTotalNS.Load()) / float64(runCalls) / 1_000_000
	}
	s.Webdet = WebdetectorSnapshot{
		LinesSeen:       wd.linesSeen.Load(),
		ParseFailures:   wd.parseFailures.Load(),
		IngestCalls:     ingestCalls,
		AvgIngestUS:     avgIngestUS,
		RunOnceCalls:    runCalls,
		RunOnceFailures: wd.runOnceFailures.Load(),
		AvgRunOnceMS:    avgRunMS,
	}
	return s
}
