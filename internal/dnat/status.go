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
	// NFTDNATPriority controls the priority of CFM's NAT prerouting chain.
	// Imunify360/WebShield commonly installs DNAT rules at priority dstnat (-100).
	// Recommended values:
	//   -99  = Imunify/WebShield first, CFM fallback for remaining web traffic.
	//   -101 = CFM first, CFM owns web traffic before Imunify/WebShield.
	// Avoid -100 because same-priority NAT chains can produce ambiguous ordering.
	NFTDNATPriority = -99
)

// Status returns whether DNAT is currently enabled using the same defaults
// as the CLI/report path.
func Status(backend firewall.Backend) (bool, error) {
	if backend == nil {
		return false, fmt.Errorf("backend does not support DNAT")
	}

	return backend.DNATStatus(DefaultFamily, DefaultTable)
}

// PanelStatus returns whether panel DNAT is currently enabled using the same
// defaults as the cPanel DNAT CLI/report path.
func PanelStatus() (bool, string, error) {
	return panelStatus()
}

// EffectiveTargetPorts returns the DNAT target ports resolved using the same
// env-driven behavior as the CLI (HTTP_PORT/HTTPS_PORT) with sane defaults.
func EffectiveTargetPorts() (httpPort int, httpsPort int) {
	return getenvInt("HTTP_PORT", DefaultHTTPPort), getenvInt("HTTPS_PORT", DefaultHTTPSPort)
}

type panelChallengeStatus struct {
	RequestedMode string
	RenderedMode  string
	EffectiveMode string
	Enforced      bool
	MismatchCause string
}

func buildPanelChallengeStatus(requestedMode, renderedMode string, luaLoaded bool) panelChallengeStatus {
	s := panelChallengeStatus{
		RequestedMode: requestedMode,
		RenderedMode:  renderedMode,
		EffectiveMode: renderedMode,
	}
	if !luaLoaded {
		s.EffectiveMode = "off"
	}
	s.Enforced = s.EffectiveMode == s.RequestedMode
	if s.EffectiveMode != s.RenderedMode {
		s.MismatchCause = "pending reload or stale listener config"
	}
	return s
}
