package edge

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"cfm/internal/hostsecrets"
)

func TestReadBridgeTokenProbeRequiresCanonicalFile(t *testing.T) {
	t.Setenv("OPENRESTY_TOKEN", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("BRIDGE_TOKEN", "012345abcdefghijklmnopqrstuvwxyz")

	got := ReadBridgeTokenProbe(filepath.Join(t.TempDir(), "missing-bridge-token.lua"))
	if got.Present || got.Token != "" {
		t.Fatalf("expected missing canonical bridge file, got %+v", got)
	}
}

func TestReadLuaTokenDecodesCanonicalWriterEscapes(t *testing.T) {
	const token = `bridge-token-"quoted"-\path-0123456789abcdef`
	path := filepath.Join(t.TempDir(), "cfm_bridge_token.lua")
	if err := os.WriteFile(path, []byte("return "+strconv.Quote(token)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := ReadLuaToken(path)
	if !got.Present || !got.Valid || got.Token != token {
		t.Fatalf("ReadLuaToken() = %+v, want valid token %q", got, token)
	}
}

// ReadChallengeTokenProbe reports the token the daemon runs: the per-host
// store (hostsecrets), whatever detectors.conf says. A node whose
// detectors.conf no longer carries the line must not read as "no token".
func TestReadChallengeTokenProbeFallsBackToTheStore(t *testing.T) {
	t.Setenv("CHALLENGE_TOKEN", "")
	old := hostsecrets.Dir
	hostsecrets.Dir = filepath.Join(t.TempDir(), "secrets")
	t.Cleanup(func() { hostsecrets.Dir = old })

	const stored = "0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, _, err := hostsecrets.Resolve(hostsecrets.ChallengeToken, stored); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(t.TempDir(), "detectors.conf")
	for name, body := range map[string]string{
		"no line":          "[webdetector]\nENABLED = 1\n",
		"placeholder line": "[webdetector]\nCHALLENGE_TOKEN = placeholder\n",
		"no section":       "[global]\nENRICH = 1\n",
	} {
		if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		got := ReadChallengeTokenProbe(conf)
		if !got.Present || !got.Valid || got.Token != stored {
			t.Errorf("%s: ReadChallengeTokenProbe = %+v, want the stored token", name, got)
		}
	}

	const inConf = "fedcba9876543210fedcba9876543210fedcba9876543210"
	if err := os.WriteFile(conf, []byte("[webdetector]\nCHALLENGE_TOKEN = "+inConf+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ReadChallengeTokenProbe(conf); got.Token != stored {
		t.Errorf("strong detectors.conf value: ReadChallengeTokenProbe = %+v, want the stored token (the store wins)", got)
	}
}

// While the store is empty, the probe reports the detectors.conf token the
// daemon would copy: like the daemon, one set only in a detectors.d overlay
// when the base has no [webdetector] section, and not otherwise.
func TestReadChallengeTokenProbeOverlayOnlyToken(t *testing.T) {
	t.Setenv("CHALLENGE_TOKEN", "")
	old := hostsecrets.Dir
	hostsecrets.Dir = filepath.Join(t.TempDir(), "secrets")
	t.Cleanup(func() { hostsecrets.Dir = old })

	dir := t.TempDir()
	conf := filepath.Join(dir, "detectors.conf")
	const overlay = "0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(conf, []byte("[global]\nENRICH = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "detectors.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "detectors.d", "50-web.conf"), []byte("[webdetector]\nCHALLENGE_TOKEN = "+overlay+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ReadChallengeTokenProbe(conf); got.Token != overlay || !got.Valid {
		t.Fatalf("ReadChallengeTokenProbe = %+v, want the overlay token", got)
	}

	// With a base [webdetector] the overlay token is ignored, as by the daemon.
	if err := os.WriteFile(conf, []byte("[webdetector]\nCHALLENGE_TOKEN = placeholder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ReadChallengeTokenProbe(conf); got.Token == overlay {
		t.Fatalf("ReadChallengeTokenProbe = %+v, want the overlay token ignored", got)
	}
}
