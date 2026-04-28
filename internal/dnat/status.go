package dnat

import (
	"fmt"
)

const (
	DefaultFamily    = "inet"
	DefaultTable     = "cfm_redirect"
	DefaultHTTPPort  = 9080
	DefaultHTTPSPort = 9043
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

// EffectiveTargetPorts returns the DNAT target ports resolved using the same
// env-driven behavior as the CLI (HTTP_PORT/HTTPS_PORT) with sane defaults.
func EffectiveTargetPorts() (httpPort int, httpsPort int) {
	return getenvInt("HTTP_PORT", DefaultHTTPPort), getenvInt("HTTPS_PORT", DefaultHTTPSPort)
}
