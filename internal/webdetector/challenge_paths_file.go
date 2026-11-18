package webdetector

import "path/filepath"

// DefaultMalPathFile is the packaged path list. It is the one default for
// CHALLENGE_PATHS_FILE (the malpath challenge): the detectors register and
// FillDefaults both use it, so the two can no longer drift apart (the old
// default named a second file for months after the config had moved to this
// one). The reference detectors.conf points MALPATH_FILE (the MALPATH flood
// ban) at it too; MALPATH_FILE itself has no default, so a config without
// that key runs the flood ban with no list.
const DefaultMalPathFile = "/etc/cfm/webdetector_malpaths.txt"

// RetiredChallengePathsFile is the list CHALLENGE_PATHS read until
// 2026-03-12. The package stopped shipping it on 2026-11-18, and an upgrade
// removes it (rpm erases an unedited copy, renames an edited one .rpmsave).
const RetiredChallengePathsFile = "/etc/cfm/webdetector_challenge_paths.txt"

// ResolveChallengePathsFile returns the file CHALLENGE_PATHS should read for
// the configured value: the malpath list when it is empty or still names the
// retired file (redirected reports the second case, for a log line). Without
// the redirect a config that kept the old name would arm the check with no
// rules once the upgrade removed the file, with only an "open failed" line to
// show for it.
// The comparison is on the cleaned path, so /etc/cfm//… or /etc/cfm/./…
// spellings of the retired file are redirected too.
func ResolveChallengePathsFile(configured string) (path string, redirected bool) {
	if configured == "" {
		return DefaultMalPathFile, false
	}
	if filepath.Clean(configured) == RetiredChallengePathsFile {
		return DefaultMalPathFile, true
	}
	return configured, false
}
