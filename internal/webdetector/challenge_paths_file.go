package webdetector

// DefaultMalPathFile is the path list both the malpath challenge
// (CHALLENGE_PATHS) and the MALPATH flood ban read. It is the one default for
// CHALLENGE_PATHS_FILE: the detectors register and FillDefaults both use it,
// so the two can no longer drift apart (the old default named a second file
// for months after the config had moved to this one).
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
func ResolveChallengePathsFile(configured string) (path string, redirected bool) {
	switch configured {
	case "":
		return DefaultMalPathFile, false
	case RetiredChallengePathsFile:
		return DefaultMalPathFile, true
	}
	return configured, false
}
