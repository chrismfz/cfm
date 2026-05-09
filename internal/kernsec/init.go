package kernsec

import (
	"fmt"
	"io"
	"os"
)

// RunInit writes a default kernsec.conf to ConfPath if absent and
// reports the outcome. Idempotent: re-running on a host that already
// has a conf is a no-op (success, message says "already exists").
func RunInit(w io.Writer) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(w, "kernsec init: must run as root")
		return 1
	}
	created, err := WriteDefaultConf()
	if err != nil {
		fmt.Fprintln(w, "kernsec init:", err)
		return 1
	}
	if created {
		fmt.Fprintf(w, "Created %s with tier=1.\n", ConfPath)
		fmt.Fprintln(w, "Review with: cat", ConfPath)
		fmt.Fprintln(w, "Preview what apply would do: cfm kernsec preview")
	} else {
		fmt.Fprintf(w, "%s already exists; not overwriting.\n", ConfPath)
		fmt.Fprintln(w, "Edit by hand to change tier or add per-rule overrides.")
	}
	return 0
}
