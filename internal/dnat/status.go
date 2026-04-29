package dnat

import (
	"cfm/internal/firewall"
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
func Status(backend firewall.Backend) (bool, error) {
	if backend == nil {
		return false, fmt.Errorf("backend does not support DNAT")
	}

	return backend.DNATStatus(DefaultFamily, DefaultTable)
}

// EffectiveTargetPorts returns the DNAT target ports resolved using the same
// env-driven behavior as the CLI (HTTP_PORT/HTTPS_PORT) with sane defaults.
func EffectiveTargetPorts() (httpPort int, httpsPort int) {
	return getenvInt("HTTP_PORT", DefaultHTTPPort), getenvInt("HTTPS_PORT", DefaultHTTPSPort)
}
