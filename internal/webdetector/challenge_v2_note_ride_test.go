package webdetector

import (
	"os"
	"strings"
	"testing"
	"time"
)

func noteExpiry(b *NginxBridge, host, src string) time.Time {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.vhAuto[host][src]
}

// A note rides the host's live challenge entry: a webdetector run that times
// out (qualityweb, ~270 a day on 2026-11-18) no longer lets the tier lapse to
// v1 while the challenge is still served. The ride is capped, so a long
// manual entry never keeps an automatic v2 alive; with no entry the note
// keeps its plain TTL.
func TestNoteVhostAutoSource_RidesTheChallengeEntry(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	now := time.Now()

	b.ChallengeVhostWithReason("auto.example", 37*time.Minute, "suspicious_vhost")
	b.NoteVhostAutoSource("auto.example", autoV2SuspiciousVhost, 2*time.Minute)
	if exp := noteExpiry(b, "auto.example", autoV2SuspiciousVhost); exp.Before(now.Add(36 * time.Minute)) {
		t.Fatalf("note expires %s from now, want it to ride the 37m entry", exp.Sub(now).Round(time.Minute))
	}

	b.ChallengeVhostWithReason("manual.example", 24*time.Hour, "manual")
	b.NoteVhostAutoSource("manual.example", autoV2SuspiciousVhost, 2*time.Minute)
	if exp := noteExpiry(b, "manual.example", autoV2SuspiciousVhost); exp.After(now.Add(autoNoteMaxRide + time.Minute)) {
		t.Fatalf("note expires %s from now, want at most the %s cap", exp.Sub(now).Round(time.Minute), autoNoteMaxRide)
	}

	b.NoteVhostAutoSource("bare.example", autoV2SuspiciousVhost, 2*time.Minute)
	if exp := noteExpiry(b, "bare.example", autoV2SuspiciousVhost); exp.After(now.Add(3 * time.Minute)) {
		t.Fatalf("note with no entry expires %s from now, want its 2m TTL", exp.Sub(now).Round(time.Minute))
	}

	// A drop still ends it at once: "off" is immediate whatever the ride.
	b.DropVhostAutoSource("auto.example", autoV2SuspiciousVhost)
	if own, _, _, _ := b.vhostAutoSources("auto.example"); len(own) != 0 {
		t.Fatalf("dropped note still live: %v", own)
	}
}

// The uniqpaths_short burst ending must NOT drop its note: its challenge is
// not cleared but runs out its TTL, and the note rides that entry. Dropping
// it served the rest of the challenge at v1 (orion/titan, 2026-11-18). The
// tick needs a full log pipeline to drive, so this pins the source: the one
// place allowed to drop the uniqpaths_short note is none.
func TestUniqPathsShortNoteNotDroppedOnBurstEnd(t *testing.T) {
	src, err := os.ReadFile("challenge_rules.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "DropVhostAutoSource(host, autoV2UniqPathsShort)") {
		t.Fatal("challenge_rules.go drops the uniqpaths_short note again: its challenge keeps running, so its v2 tier must too (let the note ride the entry)")
	}
}
