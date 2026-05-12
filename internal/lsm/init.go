package lsm

import (
	"fmt"
	"io"
	"os"
)

// RunInit writes a default /etc/cfm/lsm.conf if absent. Idempotent:
// re-running on a host that already has the file is a no-op.
func RunInit(w io.Writer) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(w, "lsm init: must run as root")
		return 1
	}
	created, err := WriteDefaultConf()
	if err != nil {
		fmt.Fprintln(w, "lsm init:", err)
		return 1
	}
	if created {
		fmt.Fprintf(w, "Created %s (cfm-lsm globally disabled; every policy at default mode).\n", ConfPath)
		fmt.Fprintln(w, "Review with: cat", ConfPath)
		fmt.Fprintln(w, "Check preflight: cfm lsm status")
		fmt.Fprintln(w, "See what would attach: cfm lsm preview")
	} else {
		fmt.Fprintf(w, "%s already exists; not overwriting.\n", ConfPath)
		fmt.Fprintln(w, "Edit by hand to change the enabled flag or per-policy modes.")
	}
	return 0
}
