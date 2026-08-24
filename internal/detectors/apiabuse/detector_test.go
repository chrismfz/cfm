package apiabuse

import (
	"context"
	"fmt"
	"strings"
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
	d.Enqueue(core.InputEvent{Source: "apiserver", Reason: "api_unauthorized_burst", Signal: "unauthorized_burst", SrcIP: "198.51.100.20", Path: "/api/v1/system/status"})
	_ = d.RunOnce(context.Background(), out)
	select {
	case a := <-out:
		t.Fatalf("expected no alert for excepted path, got %+v", a)
	default:
	}
}

func TestDetectorPathExceptionPreservesSecuritySignalsAndChildPaths(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason string
		signal string
		path   string
	}{
		{name: "direct auth", reason: "AUTH_TOKEN_INVALID", signal: "AUTH_TOKEN_INVALID", path: "/api/v1/embed/bootstrap"},
		{name: "fuzz", reason: "api_fuzz", signal: "path_entropy_or_fuzz", path: "/api/v1/embed/bootstrap"},
		{name: "child path", reason: "api_unauthorized_burst", signal: "unauthorized_burst", path: "/api/v1/embed/bootstrap/probe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := New(Config{PathExceptions: []string{"/api/v1/embed/bootstrap"}, Stage1Threshold: 1})
			out := make(chan core.Alert, 1)
			d.Enqueue(core.InputEvent{Source: "apiserver", Reason: tc.reason, Signal: tc.signal, SrcIP: "198.51.100.20", Path: tc.path})
			if err := d.RunOnce(context.Background(), out); err != nil {
				t.Fatalf("RunOnce: %v", err)
			}
			select {
			case <-out:
			default:
				t.Fatal("security-relevant event was hidden by path exception")
			}
		})
	}
}

func TestDetectorAlertReasonUsesEventReason(t *testing.T) {
	d := New(Config{
		Stage1Threshold: 1,
	})
	out := make(chan core.Alert, 1)
	d.Enqueue(core.InputEvent{
		Source: "apiserver",
		Reason: "api_unauthorized_burst",
		Signal: "unauthorized_burst",
		SrcIP:  "198.51.100.21",
		Path:   "/api/v1/mysql/state",
		Status: 401,
	})
	if err := d.RunOnce(context.Background(), out); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	select {
	case alert := <-out:
		if got := alert.Extra["reason"]; got != "api_unauthorized_burst" {
			t.Fatalf("expected reason api_unauthorized_burst, got %q", got)
		}
	default:
		t.Fatal("expected alert")
	}
}

func TestDetectorBypassesGlobalIgnoreBeforeCounting(t *testing.T) {
	d := New(Config{Stage1Threshold: 1})
	d.SetBypassFunc(func(ip string) bool { return ip == "84.54.49.20" })
	out := make(chan core.Alert, 1)
	d.Enqueue(core.InputEvent{Source: "apiserver", Reason: "AUTH_TOKEN_INVALID", SrcIP: "84.54.49.20"})
	if err := d.RunOnce(context.Background(), out); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	select {
	case alert := <-out:
		t.Fatalf("global-ignore IP reached detector counter: %+v", alert)
	default:
	}
}

func TestDetectorAlwaysBypassesLoopback(t *testing.T) {
	d := New(Config{Stage1Threshold: 1})
	out := make(chan core.Alert, 2)
	for _, ip := range []string{"127.0.0.2", "::1"} {
		d.Enqueue(core.InputEvent{Source: "apiserver", Reason: "AUTH_TOKEN_INVALID", SrcIP: ip})
	}
	if err := d.RunOnce(context.Background(), out); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	select {
	case alert := <-out:
		t.Fatalf("loopback reached detector counter: %+v", alert)
	default:
	}
}

func TestDetectorPreservesUnattributedEventsWithoutEnforcement(t *testing.T) {
	d := New(Config{
		Stage1Threshold: 1,
		Stage2Threshold: 2,
		Stage3Threshold: 3,
	})
	out := make(chan core.Alert, 2)
	for i := 0; i < 2; i++ {
		d.Enqueue(core.InputEvent{
			Source:    "apiserver",
			Reason:    "AUTH_TOKEN_INVALID",
			Path:      "/probe/203.0.113.88",
			UserAgent: "monitor 127.0.0.1",
		})
		if err := d.RunOnce(context.Background(), out); err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
	}

	first := <-out
	second := <-out
	if first.Extra["stage"] != "1" || second.Extra["stage"] != "2" {
		t.Fatalf("unattributed stages=%q/%q, want 1/2", first.Extra["stage"], second.Extra["stage"])
	}
	if second.Key != unattributedSourceKey || second.Extra["ip"] != "" || second.Extra["identity"] != "unattributed" {
		t.Fatalf("unexpected unattributed identity: %+v", second)
	}
	if second.Extra[core.ExtraIPScope] != core.IPScopeHost {
		t.Fatalf("unattributed alert may let sink scrape a client-controlled IP: %+v", second.Extra)
	}
	if second.Extra["action"] != "" || second.Extra["ttl"] != "" {
		t.Fatalf("unattributed alert requested enforcement: %+v", second.Extra)
	}
}

func TestDetectorPrunesExpiredSubThresholdSources(t *testing.T) {
	d := New(Config{Window: time.Minute, Stage1Threshold: 10})
	out := make(chan core.Alert, 1)
	old := time.Now().Add(-2 * time.Minute)
	for i := 0; i < 2000; i++ {
		d.Enqueue(core.InputEvent{
			When:   old,
			Source: "apiserver",
			Reason: "api_probe",
			SrcIP:  fmt.Sprintf("2001:db8::%x", i),
		})
	}
	if err := d.RunOnce(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	if len(d.lastSeen) != 0 || len(d.samples.M) != 0 {
		t.Fatalf("expired sub-threshold state retained: sources=%d samples=%d", len(d.lastSeen), len(d.samples.M))
	}
	select {
	case alert := <-out:
		t.Fatalf("expired sub-threshold event alerted: %+v", alert)
	default:
	}
}

func TestDetectorBoundsAndQuotesEvidenceSamples(t *testing.T) {
	d := New(Config{Stage1Threshold: 1})
	out := make(chan core.Alert, 1)
	d.Enqueue(core.InputEvent{
		Source:    "apiserver",
		Reason:    "AUTH_TOKEN_INVALID",
		Signal:    "AUTH_TOKEN_INVALID",
		SrcIP:     "198.51.100.44",
		Path:      "/" + strings.Repeat("x\n", maxEvidenceSampleBytes),
		UserAgent: strings.Repeat("ua\r\n", maxEvidenceSampleBytes),
	})
	if err := d.RunOnce(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	alert := <-out
	if len(alert.Samples) != 1 {
		t.Fatalf("samples=%v, want one bounded sample", alert.Samples)
	}
	if len(alert.Samples[0]) > maxEvidenceSampleBytes {
		t.Fatalf("sample is not bounded: length=%d", len(alert.Samples[0]))
	}
	if strings.ContainsAny(alert.Samples[0], "\r\n") || !strings.Contains(alert.Samples[0], "...[truncated]") {
		t.Fatalf("sample is not single-line and visibly truncated: %q", alert.Samples[0])
	}
}
