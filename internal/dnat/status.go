package dnat

import "fmt"

const (
	DefaultFamily = "inet"
	DefaultTable  = "cfm_redirect"
)

// Status returns whether DNAT is currently enabled using the same defaults
// as the CLI/report path.
func Status(backend any) (bool, error) {
	d, ok := backend.(Capable)
	if !ok || d == nil {
		return false, fmt.Errorf("backend does not support DNAT")
	}

	return d.DNATStatus(DefaultFamily, DefaultTable)
}
