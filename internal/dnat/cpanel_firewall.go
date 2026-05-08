package dnat

import (
	"fmt"
	"os/exec"
	"sync"

	"cfm/internal/firewall"
)

var execCommand = exec.Command

type panelFirewallHealth struct {
	State      string
	LastReason string
	Attempted  bool
}

var (
	panelFWMu    sync.Mutex
	panelFWState = panelFirewallHealth{State: "OK"}
)

func getPanelFirewallHealth() panelFirewallHealth {
	panelFWMu.Lock()
	defer panelFWMu.Unlock()
	return panelFWState
}

func setPanelFirewallHealth(state, reason string, attempted bool) {
	panelFWMu.Lock()
	defer panelFWMu.Unlock()
	panelFWState = panelFirewallHealth{State: state, LastReason: reason, Attempted: attempted}
}

func ensurePanelAllowlist() ([]string, error) {
	return ensurePanelAllowlistWithBackend(defaultPanelBackend())
}

func ensurePanelAllowlistWithBackend(backend firewall.Backend) ([]string, error) {
	// Panel DNAT target ports must not be opened broadly. Always use scoped
	// backend-managed accepts when nftables is available.
	if backend == nil {
		return nil, fmt.Errorf("nftables is required for scoped cPanel DNAT firewall rules")
	}
	return backend.EnsurePanelDNATAccepts()
}

func removePanelAllowlist() ([]string, error) {
	return removePanelAllowlistWithBackend(defaultPanelBackend())
}

func removePanelAllowlistWithBackend(backend firewall.Backend) ([]string, error) {
	if backend == nil {
		return nil, fmt.Errorf("nftables is required for scoped cPanel DNAT firewall cleanup")
	}
	return backend.RemovePanelDNATAccepts()
}

func panelMappingMap() map[int]int {
	m := make(map[int]int, len(firewall.PanelDNATMappings()))
	for _, mapping := range firewall.PanelDNATMappings() {
		m[mapping.From] = mapping.To
	}
	return m
}

func panelMappingTargetPorts() []int {
	ports := make([]int, 0, len(firewall.PanelDNATMappings()))
	for _, mapping := range firewall.PanelDNATMappings() {
		ports = append(ports, mapping.To)
	}
	return ports
}

func panelFirewallState() map[int]string { return panelFirewallStateWithBackend(defaultPanelBackend()) }

func panelFirewallStateWithBackend(backend firewall.Backend) map[int]string {
	state := map[int]string{}
	for _, p := range panelTargetPorts {
		state[p] = "unknown"
	}
	if backend == nil {
		return state
	}
	return backend.PanelDNATAcceptState()
}
