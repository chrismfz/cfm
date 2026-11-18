package webdetector

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// CHALLENGE_PATHS has read webdetector_malpaths.txt since 2026-03-12, and the
// package no longer ships webdetector_challenge_paths.txt (retired
// 2026-11-18). A config without CHALLENGE_PATHS_FILE, or one that still names
// the retired file, must read the malpath list, not a file that no longer
// exists (an armed check with no rules).
func TestChallengePathsFileDefaultsToMalpathList(t *testing.T) {
	var c Config
	c.FillDefaults()
	if c.ChallengePathsFile != DefaultMalPathFile {
		t.Fatalf("ChallengePathsFile default = %q, want %q", c.ChallengePathsFile, DefaultMalPathFile)
	}
}

func TestResolveChallengePathsFile(t *testing.T) {
	for _, tc := range []struct {
		in, want   string
		redirected bool
	}{
		{"", DefaultMalPathFile, false},
		{RetiredChallengePathsFile, DefaultMalPathFile, true},
		{"/etc/cfm//webdetector_challenge_paths.txt", DefaultMalPathFile, true},
		{"/etc/cfm/./webdetector_challenge_paths.txt", DefaultMalPathFile, true},
		{DefaultMalPathFile, DefaultMalPathFile, false},
		{"/etc/cfm/my_paths.txt", "/etc/cfm/my_paths.txt", false},
	} {
		got, red := ResolveChallengePathsFile(tc.in)
		if got != tc.want || red != tc.redirected {
			t.Errorf("ResolveChallengePathsFile(%q) = %q, %v; want %q, %v", tc.in, got, red, tc.want, tc.redirected)
		}
	}
	var c Config
	c.ChallengePathsFile = RetiredChallengePathsFile
	c.FillDefaults()
	if c.ChallengePathsFile != DefaultMalPathFile {
		t.Fatalf("FillDefaults kept the retired file: %q", c.ChallengePathsFile)
	}
}

// The reference detectors.conf must point both path checks at the packaged
// list the code defaults to: CHALLENGE_PATHS_FILE (malpath challenge) and
// MALPATH_FILE (flood ban, which has no code default of its own).
func TestReferenceDetectorsConfUsesDefaultMalPathFile(t *testing.T) {
	f, err := os.Open("../../configs/detectors.conf")
	if err != nil {
		t.Fatalf("open reference detectors.conf: %v", err)
	}
	defer f.Close()
	seen := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if k == "CHALLENGE_PATHS_FILE" || k == "MALPATH_FILE" {
			seen[k] = strings.TrimSpace(v)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"CHALLENGE_PATHS_FILE", "MALPATH_FILE"} {
		if seen[k] != DefaultMalPathFile {
			t.Errorf("reference detectors.conf %s = %q, want %q", k, seen[k], DefaultMalPathFile)
		}
	}
}
