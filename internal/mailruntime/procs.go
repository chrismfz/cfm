package mailruntime

import (
	"os"
	"path/filepath"
	"strings"
)

// DefaultSpamdChildComm is the process COMM a SpamAssassin scanner child runs
// under. spamd rewrites its child process name to "spamd child" (Perl sets both
// $0 and, on Linux, the task comm), so counting this COMM gives the number of
// active scanner children that spamd's --max-children caps. Grounded in-repo:
// CFM's LSM allow-list already tracks this exact COMM (configs/lsm.conf
// allow_comm = spamd child) as observed on the fleet.
const DefaultSpamdChildComm = "spamd child"

// countComms counts how many entries equal target. Pure helper split out so the
// matching is unit-testable without a live /proc.
func countComms(comms []string, target string) int {
	n := 0
	for _, c := range comms {
		if c == target {
			n++
		}
	}
	return n
}

// CountComm counts running processes whose /proc/<pid>/comm equals target. It is
// a light /proc scan (no CPU sampling, no argv), so it is cheap enough for a
// periodic collector tick. A pid that exits mid-scan is skipped. comm is read
// from /proc/<pid>/comm, which reflects the kernel task name (TASK_COMM), the
// same source the LSM observes — so "spamd child" matches what runs on the box.
func CountComm(target string) int {
	return countComms(readCommsIn("/proc"), target)
}

// isPidDir reports whether a /proc entry name is a pid directory (all digits).
// Split out (and pure) so the filter is unit-testable and can't silently drift
// into matching a non-pid /proc entry such as "self", "net" or "sys".
func isPidDir(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}
	return true
}

// readCommsIn returns the COMM of every process directory under procRoot. Best
// effort: unreadable/racing pids are skipped. procRoot is a parameter (not the
// hardcoded "/proc") so the scan is unit-testable against a fixture tree.
func readCommsIn(procRoot string) []string {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	comms := make([]string, 0, len(entries))
	for _, e := range entries {
		if !isPidDir(e.Name()) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "comm"))
		if err != nil {
			continue // pid exited mid-scan, or not permitted
		}
		comms = append(comms, strings.TrimRight(string(raw), "\n"))
	}
	return comms
}
