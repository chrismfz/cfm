package mailruntime

import (
	"os"
	"path/filepath"
	"strconv"
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
	comms := readAllComms()
	return countComms(comms, target)
}

// readAllComms returns the COMM of every currently-visible process. Best effort:
// unreadable/racing pids are skipped.
func readAllComms() []string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	comms := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if name == "" || name[0] < '0' || name[0] > '9' {
			continue // not a pid dir
		}
		if _, err := strconv.Atoi(name); err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", name, "comm"))
		if err != nil {
			continue // pid exited mid-scan, or not permitted
		}
		comms = append(comms, strings.TrimRight(string(raw), "\n"))
	}
	return comms
}
