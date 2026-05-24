package webdetector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUAEmergency_SetGetDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ua_emergency.json")
	audit := filepath.Join(dir, "ua_emergency.log")

	s := NewUAEmergencyStore(path, audit)

	if _, ok := s.Get("facebookexternalhit"); ok {
		t.Fatal("Get on empty store should miss")
	}

	r, err := s.Set("facebookexternalhit", UAActionBlock, "admin", "DDoS", 15*time.Minute)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if r.ExpiresAt.Sub(r.CreatedAt) != 15*time.Minute {
		t.Errorf("ttl mismatch: %v", r.ExpiresAt.Sub(r.CreatedAt))
	}

	got, ok := s.Get("facebookexternalhit")
	if !ok || got.Action != UAActionBlock {
		t.Fatalf("Get after Set: ok=%v action=%q", ok, got.Action)
	}

	removed, ok := s.Delete("facebookexternalhit", "admin")
	if !ok || removed.UA != "facebookexternalhit" {
		t.Fatalf("Delete miss")
	}
	if _, ok := s.Get("facebookexternalhit"); ok {
		t.Fatal("Get after Delete should miss")
	}
}

func TestUAEmergency_TTLBounds(t *testing.T) {
	dir := t.TempDir()
	s := NewUAEmergencyStore(filepath.Join(dir, "r.json"), filepath.Join(dir, "a.log"))

	// Positive-but-below floor → clamped to MinTTL (NOT silently promoted
	// to DefaultTTL — that would surprise the operator with a 30× larger
	// blast radius than they asked for).
	r, _ := s.Set("a", UAActionBlock, "admin", "", 5*time.Second)
	if got := r.ExpiresAt.Sub(r.CreatedAt); got != UAEmergencyMinTTL {
		t.Errorf("sub-floor ttl = %v, want min %v", got, UAEmergencyMinTTL)
	}

	// Zero / negative TTL → default (caller didn't specify).
	r, _ = s.Set("z", UAActionBlock, "admin", "", 0)
	if got := r.ExpiresAt.Sub(r.CreatedAt); got != UAEmergencyDefaultTTL {
		t.Errorf("zero ttl = %v, want default %v", got, UAEmergencyDefaultTTL)
	}

	// Above cap → cap.
	r, _ = s.Set("b", UAActionBlock, "admin", "", 24*time.Hour)
	if got := r.ExpiresAt.Sub(r.CreatedAt); got != UAEmergencyMaxTTL {
		t.Errorf("super-cap ttl = %v, want cap %v", got, UAEmergencyMaxTTL)
	}
}

func TestUAEmergency_InvalidAction(t *testing.T) {
	dir := t.TempDir()
	s := NewUAEmergencyStore(filepath.Join(dir, "r.json"), filepath.Join(dir, "a.log"))
	if _, err := s.Set("a", "nuke", "admin", "", 5*time.Minute); err == nil {
		t.Fatal("expected error for invalid action")
	}
	if _, err := s.Set("", UAActionBlock, "admin", "", 5*time.Minute); err == nil {
		t.Fatal("expected error for empty ua")
	}
}

func TestUAEmergency_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.json")
	audit := filepath.Join(dir, "a.log")

	s1 := NewUAEmergencyStore(path, audit)
	if _, err := s1.Set("semrushbot", UAActionThrottle, "admin", "noise", 20*time.Minute); err != nil {
		t.Fatal(err)
	}

	// Reload in a fresh store.
	s2 := NewUAEmergencyStore(path, audit)
	got, ok := s2.Get("semrushbot")
	if !ok {
		t.Fatal("rule lost across reload")
	}
	if got.Action != UAActionThrottle {
		t.Errorf("action lost: %q", got.Action)
	}
}

func TestUAEmergency_PruneExpired(t *testing.T) {
	dir := t.TempDir()
	s := NewUAEmergencyStore(filepath.Join(dir, "r.json"), filepath.Join(dir, "a.log"))

	r, _ := s.Set("bytespider", UAActionBlock, "admin", "", 5*time.Minute)
	// Force expiry by mutating the in-memory rule directly via a future "now".
	future := r.ExpiresAt.Add(1 * time.Second)
	if n := s.PruneExpired(future); n != 1 {
		t.Errorf("PruneExpired removed %d, want 1", n)
	}
	if _, ok := s.Get("bytespider"); ok {
		t.Fatal("expired rule still present after prune")
	}
}

func TestUAEmergency_IncHits(t *testing.T) {
	dir := t.TempDir()
	s := NewUAEmergencyStore(filepath.Join(dir, "r.json"), filepath.Join(dir, "a.log"))
	s.Set("ahrefsbot", UAActionThrottle, "admin", "", 10*time.Minute)
	s.IncHits("ahrefsbot", 100)
	s.IncHits("ahrefsbot", 23)
	got, _ := s.Get("ahrefsbot")
	if got.Hits != 123 {
		t.Errorf("Hits = %d, want 123", got.Hits)
	}
	// Unknown UA is a silent no-op.
	s.IncHits("doesnotexist", 5)
}

func TestUAEmergency_List(t *testing.T) {
	dir := t.TempDir()
	s := NewUAEmergencyStore(filepath.Join(dir, "r.json"), filepath.Join(dir, "a.log"))
	s.Set("a", UAActionBlock, "admin", "", 60*time.Minute)
	s.Set("b", UAActionBlock, "admin", "", 5*time.Minute)
	s.Set("c", UAActionBlock, "admin", "", 30*time.Minute)
	list := s.List()
	if len(list) != 3 {
		t.Fatalf("List size = %d, want 3", len(list))
	}
	if list[0].UA != "b" || list[2].UA != "a" {
		t.Errorf("expected expiry-ascending order, got %q, %q, %q",
			list[0].UA, list[1].UA, list[2].UA)
	}
}

func TestUAEmergency_AuditLog(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "a.log")
	s := NewUAEmergencyStore(filepath.Join(dir, "r.json"), audit)

	s.Set("dotbot", UAActionBlock, "admin", "crawler", 10*time.Minute)
	s.Delete("dotbot", "admin")

	data, err := os.ReadFile(audit)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "event=create") || !strings.Contains(text, "event=undo") {
		t.Errorf("audit missing lifecycle events:\n%s", text)
	}
	if !strings.Contains(text, "ua=\"dotbot\"") {
		t.Errorf("audit missing ua:\n%s", text)
	}
}
