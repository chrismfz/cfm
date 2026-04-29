//go:build linux

package nftlib

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// internal/firewall/nftlib
	return filepath.Clean(filepath.Join(wd, "..", "..", ".."))
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func TestEngineSelectorSupportsNftlib(t *testing.T) {
	mainGo := readRepoFile(t, "cmd/cfm/main.go")
	if !strings.Contains(mainGo, "CFM_FIREWALL_ENGINE") {
		t.Fatalf("cmd/cfm/main.go must read CFM_FIREWALL_ENGINE")
	}
	if !strings.Contains(mainGo, "case \"nftlib\"") {
		t.Fatalf("cmd/cfm/main.go must route case \"nftlib\"")
	}
}

func TestNftlibParityCoverageMarkers(t *testing.T) {
	checks := []struct {
		file     string
		snippets []string
	}{
		{"internal/firewall/nftlib/lifecycle.go", []string{"EnsureBase(", "ResetTable(", "DropEverything("}},
		{"internal/firewall/nftlib/sets.go", []string{"AddBlock(", "RemoveBlockBatch(", "AddAllow(", "AddIgnore(", "AddChallenge("}},
		{"internal/firewall/nftlib/feeds.go", []string{"ApplyFeed(", "RebuildExternalUnions(", "PruneExternalFeeds(", "DropFeedSets("}},
		{"internal/firewall/nftlib/policy.go", []string{"ApplyFloodRules(", "ApplyHardeningRules(", "ApplyPortsPolicy(", "ApplyConnlimit(", "ApplyPortFlood(", "ApplySMTPBlock("}},
		{"internal/firewall/nftlib/challenge.go", []string{"DNATOn(", "DNATOff(", "DNATStatus(", "EnsureChallengeRedirect("}},
	}

	for _, tc := range checks {
		body := readRepoFile(t, tc.file)
		for _, sn := range tc.snippets {
			if !strings.Contains(body, sn) {
				t.Fatalf("%s missing expected method marker %q", tc.file, sn)
			}
		}
	}
}

func TestNftlibCutoverGate_NoNftImportsOrCtor(t *testing.T) {
	root := filepath.Join(repoRoot(t), "internal", "firewall", "nftlib")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("readdir nftlib: %v", err)
	}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".go") {
			continue
		}
		name := ent.Name()
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(body)
		if strings.Contains(src, "\"cfm/internal/firewall/nft\"") {
			t.Fatalf("cutover gate failed: internal/firewall/nftlib/%s imports internal/firewall/nft", name)
		}
		if strings.Contains(src, "nft.New()") {
			t.Fatalf("cutover gate failed: internal/firewall/nftlib/%s calls nft.New()", name)
		}
	}
}
