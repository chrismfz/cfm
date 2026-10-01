package detectors

import (
	"errors"
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
func useHostSecretsDir(t *testing.T) {
	t.Helper()
	t.Cleanup(hostsecrets.SetDirForTest(filepath.Join(t.TempDir(), "secrets")))
}

func sections(t *testing.T, conf string) Sections {
	t.Helper()
	p := filepath.Join(t.TempDir(), "detectors.conf")
	if err := os.WriteFile(p, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := ReadSectionsFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The detectors.conf token is read where the old binary read it: the BASE
// [webdetector] when the base has one (an overlay token is ignored), the
// merged section only when it has none (the old binary ran an overlay token
// as-is), nothing when the base cannot be read. So the migration copies the
// token the node actually ran.
func TestConfSectionReadsWhereTheOldBinaryDid(t *testing.T) {
	merged := KV{"CHALLENGE_TOKEN": hostTokB}
	withWD := sections(t, "[webdetector]\nCHALLENGE_TOKEN = "+hostTokA+"\n")
	if got := kvStrClean(hostsecrets.ConfSection(withWD, nil, merged), "CHALLENGE_TOKEN", ""); got != hostTokA {
		t.Errorf("base has [webdetector]: token = %q, want the base value", got)
	}
	noWD := sections(t, "[global]\nENRICH = 1\n")
	if got := kvStrClean(hostsecrets.ConfSection(noWD, nil, merged), "CHALLENGE_TOKEN", ""); got != hostTokB {
		t.Errorf("base has no [webdetector]: token = %q, want the merged (overlay) value", got)
	}
	if got := hostsecrets.ConfSection(Sections{}, errors.New("read failed"), merged); got != nil {
		t.Errorf("unreadable base: section = %v, want nil (an overlay token must not stand in)", got)
	}
}

// The migration end to end: the node's token is copied into an empty store,
// then the store wins whatever detectors.conf says.
func TestResolveHostTokensMigratesThenTheStoreWins(t *testing.T) {
	useHostSecretsDir(t)
	conf := KV{"CHALLENGE_TOKEN": hostTokA, "OPENRESTY_TOKEN": hostTokB}
	if chal, bridge := resolveHostTokens(conf, true); chal != hostTokA || bridge != hostTokB {
		t.Fatalf("migration: resolveHostTokens = (%q, %q), want the detectors.conf tokens", chal, bridge)
	}
	// The stock placeholder, or a different token (an older binary after a
	// rollback writes its own), no longer matters.
	for _, c := range []KV{{"CHALLENGE_TOKEN": "placeholder"}, {"CHALLENGE_TOKEN": hostTokB, "OPENRESTY_TOKEN": hostTokA}, nil} {
		if chal, bridge := resolveHostTokens(c, true); chal != hostTokA || bridge != hostTokB {
			t.Fatalf("conf %v: resolveHostTokens = (%q, %q), want the stored tokens", c, chal, bridge)
		}
	}
}

// Every value hostsecrets accepts runs as itself: the webdetector config
// re-reads the pinned token through kvStrClean, and the bridge token is
// mirrored verbatim to cfm_bridge_token.lua, so the cleaner must not alter it.
func TestUsableTokensSurviveTheConfigCleaner(t *testing.T) {
	var samples []string
	for _, c := range "!$%&()*+,-./:<=>?@[\\]^_`{|}~\"';#" {
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

// The base detectors.conf could not be read on the first start (store still
// empty): a generated token is run but not stored, so the next reload still
// copies the node's own token.
func TestResolveHostTokensUnreadableConfNeverPinsAGeneratedToken(t *testing.T) {
	useHostSecretsDir(t)
	chal, _ := resolveHostTokens(nil, false)
	if chal == "" || chal == hostTokA {
		t.Fatalf("conf unknown: CHALLENGE_TOKEN = %q, want a running generated token", chal)
	}
	if _, err := os.Stat(hostsecrets.Path(hostsecrets.ChallengeToken)); !os.IsNotExist(err) {
		t.Fatalf("a generated token was stored while detectors.conf was unreadable (err %v)", err)
	}
	if chal, _ := resolveHostTokens(KV{"CHALLENGE_TOKEN": hostTokA}, true); chal != hostTokA {
		t.Fatalf("next reload: CHALLENGE_TOKEN = %q, want the node's detectors.conf token", chal)
	}
}
