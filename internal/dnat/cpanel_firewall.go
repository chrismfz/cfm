package dnat

import (
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const cpanelFWTag = "cfm_cpanel_dnat"

type fwBackend string

const (
	fwUnknown   fwBackend = "unknown"
	fwNft       fwBackend = "nftables"
	fwFirewalld fwBackend = "firewalld"
)

func detectFWBackend() fwBackend {
	if execCommand("firewall-cmd", "--state").Run() == nil {
		return fwFirewalld
	}
	if execCommand("nft", "list", "ruleset").Run() == nil {
		return fwNft
	}
	return fwUnknown
}

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

type FirewallCommandError struct {
	Backend fwBackend
	Command string
	Output  string
	Err     error
}

func (e *FirewallCommandError) Error() string {
	if strings.TrimSpace(e.Output) == "" {
		return fmt.Sprintf("firewall backend=%s command=%q failed: %v", e.Backend, e.Command, e.Err)
	}
	return fmt.Sprintf("firewall backend=%s command=%q failed: %v; output=%s", e.Backend, e.Command, e.Err, strings.TrimSpace(e.Output))
}

func runFirewallCmd(backend fwBackend, name string, args ...string) error {
	cmd := execCommand(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &FirewallCommandError{Backend: backend, Command: name + " " + strings.Join(args, " "), Output: string(out), Err: err}
	}
	return nil
}

func ensurePanelAllowlist() ([]string, error) {
	switch detectFWBackend() {
	case fwFirewalld:
		return ensureFirewalldPorts()
	case fwNft:
		return ensureNftPorts()
	default:
		return nil, fmt.Errorf("no supported firewall backend detected")
	}
}
func removePanelAllowlist() ([]string, error) {
	switch detectFWBackend() {
	case fwFirewalld:
		return removeFirewalldPorts()
	case fwNft:
		return removeNftPorts()
	default:
		return nil, fmt.Errorf("no supported firewall backend detected")
	}
}

func ensureNftPorts() ([]string, error) {
	_ = execCommand("nft", "add", "table", "inet", "cfm").Run()
	_ = execCommand("nft", "add", "chain", "inet", "cfm", "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}").Run()
	out := runOut("nft", "-a", "list", "chain", "inet", "cfm", "input")
	changes := []string{}
	for _, p := range panelTargetPorts {
		want := fmt.Sprintf("tcp dport %d", p)
		if strings.Contains(out, want) && strings.Contains(out, cpanelFWTag) {
			continue
		}
		cmd := fmt.Sprintf("add rule inet cfm input tcp dport %d ct state new accept comment \"%s:%d\"", p, cpanelFWTag, p)
		if err := execCommand("nft", "-f", "-").Run(); err != nil {
			_ = cmd
		}
		if err := runFirewallCmd(fwNft, "nft", "add", "rule", "inet", "cfm", "input", "tcp", "dport", strconv.Itoa(p), "ct", "state", "new", "accept", "comment", fmt.Sprintf("\"%s:%d\"", cpanelFWTag, p)); err != nil {
			return changes, err
		}
		changes = append(changes, fmt.Sprintf("opened tcp/%d (nft cfm/input)", p))
	}
	return changes, nil
}

func removeNftPorts() ([]string, error) {
	out := runOut("nft", "-a", "list", "chain", "inet", "cfm", "input")
	changes := []string{}
	handles := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		port, h, ok := parseManagedRuleLine(line)
		if !ok {
			continue
		}
		handles[port] = h
	}
	for _, p := range panelTargetPorts {
		ps := strconv.Itoa(p)
		h, ok := handles[ps]
		if !ok {
			changes = append(changes, fmt.Sprintf("tcp/%d not found", p))
			continue
		}
		if err := runFirewallCmd(fwNft, "nft", "delete", "rule", "inet", "cfm", "input", "handle", h); err != nil {
			changes = append(changes, fmt.Sprintf("tcp/%d failed (%v)", p, err))
			continue
		}
		changes = append(changes, fmt.Sprintf("tcp/%d removed", p))
	}
	sort.Strings(changes)
	return changes, nil
}

func ensureFirewalldPorts() ([]string, error) { return nil, nil }
func removeFirewalldPorts() ([]string, error) { return nil, nil }

func panelFirewallState() map[int]string {
	state := map[int]string{}
	for _, p := range panelTargetPorts { state[p] = "unknown" }
	out := runOut("nft", "-a", "list", "chain", "inet", "cfm", "input")
	for _, p := range panelTargetPorts {
		if strings.Contains(out, fmt.Sprintf("tcp dport %d", p)) && strings.Contains(out, cpanelFWTag+":"+strconv.Itoa(p)) {
			state[p] = "open"
		} else if out != "" {
			state[p] = "blocked"
		}
	}
	return state
}

func parseManagedRuleLine(line string) (string,string,bool) {
	if !strings.Contains(line, cpanelFWTag+":") || !strings.Contains(line, " handle ") { return "","",false }
	h := strings.TrimSpace(line[strings.LastIndex(line, " handle ")+8:])
	parts := strings.Fields(line)
	port := "?"
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "dport" { port = parts[i+1]; break }
	}
	return port,h,true
}
