package detectors

import (
	"os"
	"path/filepath"
	"testing"

	"cfm/internal/hostsecrets"
)

const (
	hostTokA = "0123456789abcdef0123456789abcdef0123456789abcdef"
	hostTokB = "fedcba9876543210fedcba9876543210fedcba9876543210"
)

// useHostSecretsDir points the token store at a temp dir: a test must never
// touch the live /var/lib/cfm/secrets (CLAUDE.md §5).
func useHostSecretsDir(t *testing.T) string {
	t.Helper()
	old := hostsecrets.Dir
	hostsecrets.Dir = filepath.Join(t.TempDir(), "secrets")
	t.Cleanup(func() { hostsecrets.Dir = old })
	return hostsecrets.Dir
}

func writeSnapshot(t *testing.T, dir, conf string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostsecrets.PreUpgradePath(), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
}

func wdSection(t *testing.T, conf string) KV {
	t.Helper()
	p := filepath.Join(t.TempDir(), "detectors.conf")
	if err := os.WriteFile(p, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := ReadSectionsFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return s.ByName["webdetector"]
}

// The package replaced detectors.conf with the stock one (placeholders)
// before the new daemon started: the tokens come from the pre-upgrade
// snapshot, beat a different (stale) store, and the snapshot is removed.
func TestResolveHostTokensTakesOverThePreUpgradeSnapshot(t *testing.T) {
	dir := useHostSecretsDir(t)
	writeSnapshot(t, dir, "[webdetector]\nCHALLENGE_TOKEN = "+hostTokA+"\n; the shape an old binary left after mangling an empty line:\nOPENRESTY_TOKEN =\n"+hostTokB+"\n")
	// A stale store from before a rollback.
	if err := os.WriteFile(hostsecrets.Path(hostsecrets.ChallengeToken), []byte(hostTokB+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := wdSection(t, "[webdetector]\nCHALLENGE_TOKEN = placeholder\nOPENRESTY_TOKEN = placeholder\n")

	chal, bridge := resolveHostTokens(base, base)
	if chal != hostTokA || bridge != hostTokB {
		t.Fatalf("resolveHostTokens = (%q, %q), want the snapshot's (A, B)", chal, bridge)
	}
	if _, err := os.Stat(hostsecrets.PreUpgradePath()); !os.IsNotExist(err) {
		t.Fatalf("snapshot not removed after the takeover (err %v)", err)
	}
	// The next reload runs the stored values.
	if chal2, bridge2 := resolveHostTokens(base, base); chal2 != chal || bridge2 != bridge {
		t.Fatalf("after the takeover: (%q, %q), want the same tokens from the store", chal2, bridge2)
	}
}

// A usable value in the live detectors.conf beats the snapshot.
func TestResolveHostTokensLiveConfBeatsTheSnapshot(t *testing.T) {
	dir := useHostSecretsDir(t)
	writeSnapshot(t, dir, "[webdetector]\nCHALLENGE_TOKEN = "+hostTokA+"\n")
	live := wdSection(t, "[webdetector]\nCHALLENGE_TOKEN = "+hostTokB+"\n")
	chal, _ := resolveHostTokens(live, live)
	if chal != hostTokB {
		t.Fatalf("CHALLENGE_TOKEN = %q, want the live detectors.conf value", chal)
	}
}

// Every value hostsecrets accepts runs as itself: the webdetector config
// re-reads the pinned token through kvStrClean, and the bridge token is
// mirrored verbatim to cfm_bridge_token.lua, so the cleaner must not alter it.
func TestUsableTokensSurviveTheConfigCleaner(t *testing.T) {
	var samples []string
	for _, c := range "!$%&()*+,-./:<=>?@[\\]^_`{|}~" {
		samples = append(samples, hostTokA+string(c)+hostTokB, string(c)+hostTokA, hostTokA+string(c))
	}
	samples = append(samples, hostTokA+"//"+hostTokB, hostTokA+"://x", "//"+hostTokA, `"`+hostTokA+`"`, "'"+hostTokA+"'")
	for _, v := range samples {
		if !hostsecrets.Usable(v) {
			continue
		}
		if got := kvStrClean(KV{"K": v}, "K", ""); got != v {
			t.Errorf("Usable(%q) but kvStrClean gives %q", v, got)
		}
	}
}

// The snapshot is consumed per key: when one token cannot be stored yet, the
// other, already taken over, is dropped from the snapshot, so rotating it
// (placeholder, delete its store file) cannot bring the old value back.
func TestResolveHostTokensConsumesTheSnapshotPerKey(t *testing.T) {
	dir := useHostSecretsDir(t)
	writeSnapshot(t, dir, "[webdetector]\nCHALLENGE_TOKEN = "+hostTokA+"\nOPENRESTY_TOKEN = "+hostTokB+"\n")
	// OPENRESTY_TOKEN's store cannot be written (a directory in its place).
	if err := os.Mkdir(hostsecrets.Path(hostsecrets.BridgeToken), 0o700); err != nil {
		t.Fatal(err)
	}
	base := wdSection(t, "[webdetector]\nCHALLENGE_TOKEN = placeholder\nOPENRESTY_TOKEN = placeholder\n")
	if chal, bridge := resolveHostTokens(base, base); chal != hostTokA || bridge != hostTokB {
		t.Fatalf("resolveHostTokens = (%q, %q), want the snapshot's (A, B)", chal, bridge)
	}
	snap, err := ReadSectionsFile(hostsecrets.PreUpgradePath())
	if err != nil {
		t.Fatalf("snapshot gone while OPENRESTY_TOKEN is not stored: %v", err)
	}
	if got := snap.ByName["webdetector"]; len(got) != 1 || got["OPENRESTY_TOKEN"] != hostTokB {
		t.Fatalf("snapshot [webdetector] = %v, want only the unstored OPENRESTY_TOKEN", got)
	}

	// Rotate CHALLENGE_TOKEN: delete its store file, reload.
	if err := os.Remove(hostsecrets.Path(hostsecrets.ChallengeToken)); err != nil {
		t.Fatal(err)
	}
	if chal, _ := resolveHostTokens(base, base); chal == hostTokA || chal == "" {
		t.Fatalf("rotation brought the snapshot's CHALLENGE_TOKEN back: %q", chal)
	}

	// Once OPENRESTY_TOKEN can be stored, the snapshot goes.
	if err := os.Remove(hostsecrets.Path(hostsecrets.BridgeToken)); err != nil {
		t.Fatal(err)
	}
	if _, bridge := resolveHostTokens(base, base); bridge != hostTokB {
		t.Fatalf("OPENRESTY_TOKEN = %q, want the snapshot's B", bridge)
	}
	if _, err := os.Stat(hostsecrets.PreUpgradePath()); !os.IsNotExist(err) {
		t.Fatalf("snapshot not removed once every token was stored (err %v)", err)
	}
}

// A token set only in a detectors.d overlay (no [webdetector] in the base)
// ran as-is on the old binary and keeps running: it is the merged value.
func TestResolveHostTokensOverlayOnlyTokenKeepsRunning(t *testing.T) {
	useHostSecretsDir(t)
	merged := wdSection(t, "[webdetector]\nCHALLENGE_TOKEN = "+hostTokA+"\nOPENRESTY_TOKEN = "+hostTokB+"\n")
	if chal, bridge := resolveHostTokens(nil, merged); chal != hostTokA || bridge != hostTokB {
		t.Fatalf("resolveHostTokens = (%q, %q), want the overlay's (A, B)", chal, bridge)
	}
	// A usable base value still wins over the overlay.
	base := wdSection(t, "[webdetector]\nCHALLENGE_TOKEN = "+hostTokB+"\n")
	if chal, _ := resolveHostTokens(base, merged); chal != hostTokB {
		t.Fatalf("CHALLENGE_TOKEN = %q, want the base value", chal)
	}
}
