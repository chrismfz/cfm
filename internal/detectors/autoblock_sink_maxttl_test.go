package detectors

import (
	"testing"
	"time"

	"cfm/internal/detectors/core"
)

// core.ExtraMaxBlockTTL caps one finding's ban whatever the section's BLOCK:
// the dovecot section bans permanently on failed passwords, and its
// user_disabled finding (Imunify's RBL lock, or a suspended mailbox) must not.
func TestSectionSinkMaxBlockTTL(t *testing.T) {
	cases := []struct {
		name     string
		pol      blockPolicy
		extra    map[string]string
		wantLeft time.Duration // 0 = permanent
		wantRep  int           // reported TTL seconds (0 = permanent)
	}{
		{"permanent section, capped", blockPolicy{Mode: "permanent"}, map[string]string{core.ExtraMaxBlockTTL: "24h"}, 24 * time.Hour, 24 * 3600},
		{"permanent section, no cap", blockPolicy{Mode: "permanent"}, nil, 0, 0},
		{"ttl section longer than the cap", blockPolicy{Mode: "ttl", TTL: 7 * 24 * time.Hour}, map[string]string{core.ExtraMaxBlockTTL: "24h"}, 24 * time.Hour, 24 * 3600},
		{"ttl section shorter than the cap", blockPolicy{Mode: "ttl", TTL: time.Hour}, map[string]string{core.ExtraMaxBlockTTL: "24h"}, time.Hour, 3600},
		{"per-alert block_ttl past the cap", blockPolicy{Mode: "ttl", TTL: time.Hour}, map[string]string{core.ExtraMaxBlockTTL: "2h", "block_ttl": "48h"}, 2 * time.Hour, 2 * 3600},
		{"unparsable cap is no cap", blockPolicy{Mode: "permanent"}, map[string]string{core.ExtraMaxBlockTTL: "soon"}, 0, 0},
		{"negative cap is no cap", blockPolicy{Mode: "permanent"}, map[string]string{core.ExtraMaxBlockTTL: "-1h"}, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fw := &sinkSetFake{left: map[string]time.Duration{}}
			s := &sectionSink{section: "dovecot_auth", pol: c.pol, fw: fw, inner: &capturingSink{}}
			ip := "103.199.18.15"
			extra := map[string]string{"ip": ip}
			for k, v := range c.extra {
				extra[k] = v
			}
			s.Publish(core.Alert{When: time.Now(), Kind: "DOVECOT/USER_DISABLED", Key: ip, Extra: extra})
			left, ok := fw.left[ip]
			if !ok {
				t.Fatalf("not blocked: %v", fw.left)
			}
			if left != c.wantLeft {
				t.Fatalf("ban %v, want %v", left, c.wantLeft)
			}
			if len(fw.reports) != 1 || fw.reports[0] != c.wantRep {
				t.Fatalf("reported %v, want [%d]", fw.reports, c.wantRep)
			}
		})
	}
}

// A dry run stays a dry run under a cap.
func TestSectionSinkMaxBlockTTLDryRun(t *testing.T) {
	fw := &sinkSetFake{left: map[string]time.Duration{}}
	s := &sectionSink{section: "dovecot_auth", pol: blockPolicy{Mode: "dryrun"}, fw: fw, inner: &capturingSink{}}
	ip := "103.199.18.15"
	s.Publish(core.Alert{When: time.Now(), Kind: "DOVECOT/USER_DISABLED", Key: ip,
		Extra: map[string]string{"ip": ip, core.ExtraMaxBlockTTL: "24h"}})
	if len(fw.left) != 0 || len(fw.reports) != 0 {
		t.Fatalf("dry run blocked or reported: %v %v", fw.left, fw.reports)
	}
}

// A capped finding does not stamp the section cooldown: the same IP's main
// finding (dovecot: a password failure, permanent) right after it still bans.
func TestSectionSinkCappedFindingLeavesCooldown(t *testing.T) {
	fw := &sinkSetFake{left: map[string]time.Duration{}}
	s := &sectionSink{section: "dovecot_auth", pol: blockPolicy{Mode: "permanent", Cooldown: 30 * time.Minute},
		fw: fw, inner: &capturingSink{}, last: map[string]time.Time{}}
	ip := "103.199.18.15"
	s.Publish(core.Alert{When: time.Now(), Kind: "DOVECOT/USER_DISABLED", Key: ip,
		Extra: map[string]string{"ip": ip, core.ExtraMaxBlockTTL: "24h"}})
	if fw.left[ip] != 24*time.Hour {
		t.Fatalf("capped ban %v, want 24h", fw.left[ip])
	}
	s.Publish(core.Alert{When: time.Now(), Kind: "DOVECOT/AUTHFAIL", Key: ip, Extra: map[string]string{"ip": ip}})
	if got, ok := fw.left[ip]; !ok || got != 0 {
		t.Fatalf("after the password failure: %v (present=%v), want permanent", got, ok)
	}
	// The main finding does stamp it, as before.
	s.Publish(core.Alert{When: time.Now(), Kind: "DOVECOT/AUTHFAIL", Key: ip, Extra: map[string]string{"ip": ip}})
	if len(fw.reports) != 2 {
		t.Fatalf("reports %v, want 2 (the second AUTHFAIL is inside the cooldown)", fw.reports)
	}
}
