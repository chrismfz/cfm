package dnat

import (
	"cfm/internal/firewall"
	"fmt"
)

const (
	DefaultFamily    = firewall.DNATDefaultFamily
	DefaultTable     = firewall.DNATDefaultTable
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

// EffectiveTargetPorts returns the web (edge) DNAT target ports — the same
// HTTP_PORT/HTTPS_PORT env overrides and 9080/9043 defaults that `cfm dnat on`,
// the failsafe, and restore actually install. (The retired per-IP challenge
// DNAT used to make CHALLENGE_HTTP(S)_LISTEN take precedence here; that layer
// is gone, so expected and installed ports can no longer diverge.)
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
