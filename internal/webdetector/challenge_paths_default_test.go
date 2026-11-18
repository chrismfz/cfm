package webdetector

import "testing"

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
	if DefaultMalPathFile != "/etc/cfm/webdetector_malpaths.txt" {
		t.Fatalf("DefaultMalPathFile = %q: the packaged list moved; update the reference detectors.conf too", DefaultMalPathFile)
	}
}

func TestResolveChallengePathsFile(t *testing.T) {
	for _, tc := range []struct {
		in, want   string
		redirected bool
	}{
		{"", DefaultMalPathFile, false},
		{RetiredChallengePathsFile, DefaultMalPathFile, true},
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
