package apiserver

import (
	cfgpkg "cfm/internal/config"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"cfm/internal/telemetry"
)

type DebugCaptureConfig struct {
	Enabled          bool
	ArtifactDir      string
	AllowedDurations map[int]struct{}
	Cooldown         time.Duration
	MaxDuration      time.Duration
	RetentionCount   int
	RetentionMaxAge  time.Duration
}

type DebugCaptureRecord struct {
	ID                 string                   `json:"id"`
	Status             string                   `json:"status"`
	RequestedDurationS int                      `json:"requested_duration_sec"`
	StartedAt          time.Time                `json:"started_at"`
	CompletedAt        *time.Time               `json:"completed_at,omitempty"`
	ArtifactPath       string                   `json:"artifact_path,omitempty"`
	SummaryPath        string                   `json:"summary_path,omitempty"`
	SummaryText        string                   `json:"summary_text,omitempty"`
	SnapshotsCollected int                      `json:"snapshots_collected"`
	Snapshots          []telemetry.LiveSnapshot `json:"snapshots,omitempty"`
	Error              string                   `json:"error,omitempty"`
}

type debugCaptureRunner struct {
	cfg      DebugCaptureConfig
	mu       sync.Mutex
	records  map[string]*DebugCaptureRecord
	ordered  []string
	activeID string
	lastKick time.Time
}

var globalDebugCapture = newDebugCaptureRunner(DebugCaptureConfig{
	Enabled:          true,
	ArtifactDir:      "/var/lib/cfm/debug-captures",
	AllowedDurations: map[int]struct{}{20: {}, 30: {}, 60: {}},
	Cooldown:         30 * time.Second,
	MaxDuration:      60 * time.Second,
	RetentionCount:   32,
	RetentionMaxAge:  24 * time.Hour,
})

func configureDebugCaptureFromConfig(cfg *cfgpkg.Config) {
	if cfg == nil {
		return
	}
	globalDebugCapture = newDebugCaptureRunner(DebugCaptureConfig{
		Enabled:          cfg.Debug.DebugCaptureEnabled,
		ArtifactDir:      cfg.Debug.DebugCaptureDir,
		AllowedDurations: map[int]struct{}{20: {}, 30: {}, 60: {}},
		Cooldown:         cfg.Debug.DebugCaptureCooldown,
		MaxDuration:      cfg.Debug.DebugCaptureMaxDuration,
		RetentionCount:   cfg.Debug.DebugCaptureRetentionCount,
		RetentionMaxAge:  cfg.Debug.DebugCaptureRetentionAge,
	})
}

func newDebugCaptureRunner(cfg DebugCaptureConfig) *debugCaptureRunner {
	if cfg.ArtifactDir == "" {
		cfg.ArtifactDir = "/var/lib/cfm/debug-captures"
	}
	if len(cfg.AllowedDurations) == 0 {
		cfg.AllowedDurations = map[int]struct{}{20: {}, 30: {}, 60: {}}
	}
	if cfg.MaxDuration <= 0 {
		cfg.MaxDuration = 60 * time.Second
	}
	if cfg.RetentionCount <= 0 {
		cfg.RetentionCount = 32
	}
	if cfg.RetentionMaxAge <= 0 {
		cfg.RetentionMaxAge = 24 * time.Hour
	}
	return &debugCaptureRunner{cfg: cfg, records: map[string]*DebugCaptureRecord{}}
}

func (r *debugCaptureRunner) start(durationSec int) (*DebugCaptureRecord, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.cfg.Enabled {
		return nil, false, errors.New("debug capture disabled")
	}
	if _, ok := r.cfg.AllowedDurations[durationSec]; !ok {
		return nil, false, fmt.Errorf("duration must be one of 20, 30, 60")
	}
	if time.Duration(durationSec)*time.Second > r.cfg.MaxDuration {
		return nil, false, fmt.Errorf("duration exceeds max cap of %s", r.cfg.MaxDuration)
	}
	if r.activeID != "" {
		return cloneRecord(r.records[r.activeID]), true, nil
	}
	if r.cfg.Cooldown > 0 && !r.lastKick.IsZero() && time.Since(r.lastKick) < r.cfg.Cooldown {
		return nil, false, fmt.Errorf("capture cooldown active for %s", (r.cfg.Cooldown - time.Since(r.lastKick)).Round(time.Second))
	}

	now := time.Now().UTC()
	id := now.Format("20060102T150405")
	rec := &DebugCaptureRecord{ID: id, Status: "running", RequestedDurationS: durationSec, StartedAt: now}
	r.records[id] = rec
	r.ordered = append(r.ordered, id)
	r.activeID = id
	r.lastKick = now
	go r.run(id, durationSec)
	return cloneRecord(rec), false, nil
}

func (r *debugCaptureRunner) run(id string, durationSec int) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	deadline := time.Now().Add(time.Duration(durationSec) * time.Second)
	captured := make([]telemetry.LiveSnapshot, 0, durationSec+2)
	captured = append(captured, telemetry.Snapshot())
	for time.Now().Before(deadline) {
		<-ticker.C
		captured = append(captured, telemetry.Snapshot())
	}

	rec := r.finishRecord(id, captured, "")
	if rec != nil {
		r.writeArtifacts(rec)
	}
}

func (r *debugCaptureRunner) finishRecord(id string, snapshots []telemetry.LiveSnapshot, errMsg string) *DebugCaptureRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.records[id]
	if rec == nil {
		return nil
	}
	completed := time.Now().UTC()
	rec.CompletedAt = &completed
	rec.Snapshots = snapshots
	rec.SnapshotsCollected = len(snapshots)
	rec.Status = "completed"
	if errMsg != "" {
		rec.Status = "failed"
		rec.Error = errMsg
	}
	if r.activeID == id {
		r.activeID = ""
	}
	r.pruneLocked(time.Now().UTC())
	return cloneRecord(rec)
}

func (r *debugCaptureRunner) writeArtifacts(rec *DebugCaptureRecord) {
	if err := os.MkdirAll(r.cfg.ArtifactDir, 0o750); err != nil {
		r.updateArtifactError(rec.ID, err)
		return
	}
	jsonPath := filepath.Join(r.cfg.ArtifactDir, rec.ID+".json")
	txtPath := filepath.Join(r.cfg.ArtifactDir, rec.ID+".txt")
	b, _ := json.MarshalIndent(rec, "", "  ")
	if err := os.WriteFile(jsonPath, b, 0o600); err != nil {
		r.updateArtifactError(rec.ID, err)
		return
	}
	summary := fmt.Sprintf("capture_id=%s\nstatus=%s\nduration_sec=%d\nsnapshots=%d\nstarted_at=%s\ncompleted_at=%s\n",
		rec.ID, rec.Status, rec.RequestedDurationS, rec.SnapshotsCollected,
		rec.StartedAt.Format(time.RFC3339), rec.CompletedAt.Format(time.RFC3339))
	if err := os.WriteFile(txtPath, []byte(summary), 0o600); err != nil {
		r.updateArtifactError(rec.ID, err)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur := r.records[rec.ID]; cur != nil {
		cur.ArtifactPath = jsonPath
		cur.SummaryPath = txtPath
		cur.SummaryText = strings.TrimSpace(summary)
	}
}

func (r *debugCaptureRunner) updateArtifactError(id string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec := r.records[id]; rec != nil {
		rec.Status = "failed"
		rec.Error = err.Error()
		if r.activeID == id {
			r.activeID = ""
		}
	}
}

func (r *debugCaptureRunner) get(id string) *DebugCaptureRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneRecord(r.records[id])
}

func (r *debugCaptureRunner) export(id string, format string) ([]byte, string, error) {
	rec := r.get(id)
	if rec == nil {
		return nil, "", errors.New("capture not found")
	}
	if rec.Status == "running" {
		return nil, "", errors.New("capture still running")
	}
	if format == "txt" {
		if rec.SummaryText == "" {
			rec.SummaryText = fmt.Sprintf("capture_id=%s\nstatus=%s", rec.ID, rec.Status)
		}
		return []byte(rec.SummaryText + "\n"), "text/plain; charset=utf-8", nil
	}
	b, _ := json.MarshalIndent(rec, "", "  ")
	return b, "application/json; charset=utf-8", nil
}

func (r *debugCaptureRunner) pruneLocked(now time.Time) {
	if len(r.ordered) == 0 {
		return
	}
	kept := make([]string, 0, len(r.ordered))
	for _, id := range r.ordered {
		rec := r.records[id]
		if rec == nil {
			continue
		}
		if r.cfg.RetentionMaxAge > 0 && now.Sub(rec.StartedAt) > r.cfg.RetentionMaxAge {
			delete(r.records, id)
			continue
		}
		kept = append(kept, id)
	}
	if len(kept) > r.cfg.RetentionCount {
		drop := len(kept) - r.cfg.RetentionCount
		for _, id := range kept[:drop] {
			delete(r.records, id)
		}
		kept = kept[drop:]
	}
	r.ordered = kept
	sort.Strings(r.ordered)
}

func cloneRecord(in *DebugCaptureRecord) *DebugCaptureRecord {
	if in == nil {
		return nil
	}
	cp := *in
	if in.Snapshots != nil {
		cp.Snapshots = append([]telemetry.LiveSnapshot(nil), in.Snapshots...)
	}
	return &cp
}
