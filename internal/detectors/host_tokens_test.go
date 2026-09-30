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

	chal, bridge := resolveHostTokens(base)
	if chal != hostTokA || bridge != hostTokB {
		t.Fatalf("resolveHostTokens = (%q, %q), want the snapshot's (A, B)", chal, bridge)
	}
	if _, err := os.Stat(hostsecrets.PreUpgradePath()); !os.IsNotExist(err) {
		t.Fatalf("snapshot not removed after the takeover (err %v)", err)
	}
	// The next reload runs the stored values.
	if chal2, bridge2 := resolveHostTokens(base); chal2 != chal || bridge2 != bridge {
		t.Fatalf("after the takeover: (%q, %q), want the same tokens from the store", chal2, bridge2)
	}
}

// A usable value in the live detectors.conf beats the snapshot.
func TestResolveHostTokensLiveConfBeatsTheSnapshot(t *testing.T) {
	dir := useHostSecretsDir(t)
	writeSnapshot(t, dir, "[webdetector]\nCHALLENGE_TOKEN = "+hostTokA+"\n")
	chal, _ := resolveHostTokens(wdSection(t, "[webdetector]\nCHALLENGE_TOKEN = "+hostTokB+"\n"))
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
