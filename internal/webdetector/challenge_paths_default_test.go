package webdetector

import "testing"

// CHALLENGE_PATHS has read webdetector_malpaths.txt since 2026-03-12, and the
// package no longer ships webdetector_challenge_paths.txt (retired
// 2026-11-18). A config without CHALLENGE_PATHS_FILE must fall back to the
// malpath list, not to a file that no longer exists (an armed check with no
// rules).
func TestChallengePathsFileDefaultsToMalpathList(t *testing.T) {
	var c Config
	c.FillDefaults()
	if want := "/etc/cfm/webdetector_malpaths.txt"; c.ChallengePathsFile != want {
		t.Fatalf("ChallengePathsFile default = %q, want %q", c.ChallengePathsFile, want)
	}
}
