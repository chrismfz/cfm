package dnat

import (
	"cfm/internal/firewall"
)

// Summary is the read-only DNAT picture `cfm edge` prints: which edge engine
// runs, whether web and panel traffic is redirected to it, and how. It is
// built from the same sources as `cfm dnat` / `cfm dnat cpanel status`, but a
// state it cannot read stays an error here (`cfm dnat cpanel status` prints
// OFF for one), and the web ports are the installed redirect's (the `cfm dnat`
// report prints its flag defaults). Nothing here changes state.
type Summary struct {
	// ActiveEdge is the edge engine the redirect points at, as the DNAT
	// resolver picks it: the one active unit, else the one ENABLED unit (so
	// a crashed engine is still named), "" when neither; Ambiguous when more
	// than one is active. EdgeRunning says whether it actually runs: systemd's
	// answer whenever systemd answers; only without systemd its process (a
	// loose match, `tail -f …/openresty/…` counts, so never over systemd).
	ActiveEdge  string
	EdgeRunning bool
	Ambiguous   bool

	WebOn       bool
	WebErr      error
	WebPriority int // the live chain's priority (only when WebOn)
	HTTPPort    int // the installed redirect's target ports (only when WebOn)
	HTTPSPort   int
	// WebFromConfig: the live chain could not be read or parsed, so the
	// priority / ports above are the configured ones, not the installed.
	WebFromConfig bool
	WebIntent   string // "on", "off" or "" (no intent file)
	WebBypass   int    // entries in the web bypass file
	LastProbe   ProbeResult

	PanelOn       bool
	PanelErr      error
	PanelPriority int // the persisted priority panel on installs (only when PanelOn)
	PanelIntent   string
	PanelBypass   int
}

// CollectSummary reads the DNAT state. Errors are kept per scope: an unknown
// must never read as "off".
func CollectSummary(backend firewall.Backend) Summary {
	var s Summary
	switch svc := detectActiveEdgeService(); svc {
	case panelListenerServiceAmbiguous:
		s.Ambiguous = true
	default:
		s.ActiveEdge = svc
		s.EdgeRunning = svc != "" && edgeRunning(svc)
	}

	if backend == nil {
		s.WebErr = errNoBackend
		s.PanelErr = errNoBackend
	} else {
		s.WebOn, s.WebErr = backend.DNATStatus(DefaultFamily, DefaultTable)
		if s.WebErr == nil && s.WebOn {
			s.WebPriority = ConfiguredWebDNATPriority()
			s.HTTPPort, s.HTTPSPort = EffectiveTargetPorts()
			show, err := backend.DNATShow(DefaultFamily, DefaultTable)
			p, pok := parseDNATChainPriority(show)
			h, hs, hok := firewall.ParseDNATListenerPorts(show)
			if err != nil || !pok || !hok {
				s.WebFromConfig = true
			}
			if err == nil && pok {
				s.WebPriority = p
			}
			if err == nil && hok {
				s.HTTPPort, s.HTTPSPort = h, hs
			}
		}
		s.PanelOn, _, s.PanelErr = panelStatusWithBackend(backend)
		if s.PanelErr == nil && s.PanelOn {
			s.PanelPriority = PanelStartupPriority()
		}
	}

	s.WebIntent = intentWord(ScopeWeb)
	s.PanelIntent = intentWord(ScopeCPanel)
	s.WebBypass = bypassCount(firewall.DNATBypassScopeWeb)
	s.PanelBypass = bypassCount(firewall.DNATBypassScopeCpanel)
	s.LastProbe = daemonSnapshot(ScopeWeb).LastProbe
	return s
}

// edgeRunning trusts systemd whenever it answers; the process fallback only
// covers a host without it.
func edgeRunning(svc string) bool {
	if st, ok := panelSystemdUnitProbe(panelServiceUnit(svc)); ok {
		return st.Active
	}
	return panelListenerProcessDetector() == svc
}

type summaryError string

func (e summaryError) Error() string { return string(e) }

const errNoBackend = summaryError("backend does not support DNAT")

func intentWord(scope DNATScope) string {
	on, present := LoadIntent(scope)
	switch {
	case !present:
		return ""
	case on:
		return "on"
	default:
		return "off"
	}
}

// bypassCount is -1 when the file cannot be read (an unknown, not zero).
func bypassCount(scope firewall.DNATBypassScope) int {
	entries, _, err := firewall.LoadDNATBypass(scope.Path())
	if err != nil {
		return -1
	}
	return len(entries)
}
