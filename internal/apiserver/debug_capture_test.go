package apiserver

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDebugCaptureRunnerSingleflight(t *testing.T) {
	r := newDebugCaptureRunner(DebugCaptureConfig{
		Enabled:          true,
		ArtifactDir:      t.TempDir(),
		AllowedDurations: map[int]struct{}{20: {}},
		Cooldown:         0,
		MaxDuration:      20 * time.Second,
		RetentionCount:   5,
		RetentionMaxAge:  time.Hour,
	})

	first, existing, err := r.start(20)
	if err != nil {
		t.Fatalf("start first: %v", err)
	}
	if existing {
		t.Fatalf("first start should not be existing")
	}
	second, existing, err := r.start(20)
	if err != nil {
		t.Fatalf("start second: %v", err)
	}
	if !existing {
		t.Fatalf("second start should return active single-flight capture")
	}
	if first.ID != second.ID {
		t.Fatalf("expected same capture id, got %s and %s", first.ID, second.ID)
	}
}

func TestDebugCaptureSerialization(t *testing.T) {
	r := newDebugCaptureRunner(DebugCaptureConfig{
		Enabled:          true,
		ArtifactDir:      t.TempDir(),
		AllowedDurations: map[int]struct{}{20: {}},
		Cooldown:         0,
		MaxDuration:      20 * time.Second,
		RetentionCount:   5,
		RetentionMaxAge:  time.Hour,
	})
	st, _, err := r.start(20)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	r.finishRecord(st.ID, nil, "")

	body, ctype, err := r.export(st.ID, "json")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if ctype == "" {
		t.Fatalf("expected content type")
	}
	var got DebugCaptureRecord
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ID != st.ID {
		t.Fatalf("expected id %s got %s", st.ID, got.ID)
	}
}
