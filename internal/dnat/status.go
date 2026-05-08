package dnat

import (
	"cfm/internal/firewall"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
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

// EffectiveTargetPorts returns the web DNAT target ports resolved from the
// effective challenge listeners. CHALLENGE_HTTP_LISTEN and
// CHALLENGE_HTTPS_LISTEN may be host:port, :port, or a plain port. Legacy
// HTTP_PORT/HTTPS_PORT are retained as fallback overrides for CLI-driven DNAT.
func EffectiveTargetPorts() (httpPort int, httpsPort int) {
	httpPort = effectiveListenPort("CHALLENGE_HTTP_LISTEN", getenvInt("HTTP_PORT", DefaultHTTPPort))
	httpsPort = effectiveListenPort("CHALLENGE_HTTPS_LISTEN", getenvInt("HTTPS_PORT", DefaultHTTPSPort))
	return httpPort, httpsPort
}

func effectiveListenPort(envKey string, def int) int {
	v := strings.TrimSpace(os.Getenv(envKey))
	if v == "" {
		return def
	}
	if p, ok := parseListenPort(v); ok {
		return p
	}
	return def
}

func parseListenPort(addr string) (int, bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return 0, false
	}
	if p, err := strconv.Atoi(addr); err == nil {
		return validPort(p)
	}
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, false
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, false
	}
	return validPort(p)
}

func validPort(p int) (int, bool) {
	if p <= 0 || p > 65535 {
		return 0, false
	}
	return p, true
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
