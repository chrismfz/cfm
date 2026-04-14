package apiabuse

import (
	"context"
	"testing"
	"time"

	core "cfm/internal/detectors/core"
)

func TestDetectorStages(t *testing.T) {
	d := New(Config{
		Every:              time.Second,
		Window:             time.Minute,
		Stage1Threshold:    2,
		Stage2Threshold:    3,
		Stage3Threshold:    4,
		Stage2ChallengeTTL: 5 * time.Minute,
	})

	out := make(chan core.Alert, 8)
	now := time.Now()
	for i := 0; i < 4; i++ {
		d.Enqueue(core.InputEvent{When: now, Source: "apiserver", Reason: "api_probe", Signal: "unknown_endpoint_burst", SrcIP: "203.0.113.99", Path: "/x"})
		if err := d.RunOnce(context.Background(), out); err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
	}

	var stages []string
	close(out)
	for a := range out {
		stages = append(stages, a.Extra["stage"])
	}
	if len(stages) != 3 || stages[0] != "1" || stages[1] != "2" || stages[2] != "3" {
		t.Fatalf("unexpected stages: %+v", stages)
	}
}

func TestDetectorAllowPathException(t *testing.T) {
	d := New(Config{
		PathExceptions:  []string{"/api/v1/system/status"},
		Stage1Threshold: 1,
	})
	out := make(chan core.Alert, 1)
	d.Enqueue(core.InputEvent{Source: "apiserver", Reason: "api_probe", Signal: "sensitive_path_probe", SrcIP: "198.51.100.20", Path: "/api/v1/system/status"})
	_ = d.RunOnce(context.Background(), out)
	select {
	case a := <-out:
		t.Fatalf("expected no alert for excepted path, got %+v", a)
	default:
	}
}
