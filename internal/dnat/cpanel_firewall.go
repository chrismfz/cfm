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
	// Panel DNAT target ports must not be opened broadly. Always use scoped nft
	// accepts when nft is available, even on hosts that also run firewalld.
	if execCommand("nft", "list", "ruleset").Run() == nil {
		return ensureNftPorts()
	}
	return nil, fmt.Errorf("nftables is required for scoped cPanel DNAT firewall rules")
}
func removePanelAllowlist() ([]string, error) {
	if execCommand("nft", "list", "ruleset").Run() == nil {
		return removeNftPorts()
	}
	return nil, fmt.Errorf("nftables is required for scoped cPanel DNAT firewall cleanup")
}

type panelMapping struct {
	from int
	to   int
}

func panelMappings() []panelMapping {
	mappings := make([]panelMapping, 0, len(panelMap))
	for from, to := range panelMap {
		mappings = append(mappings, panelMapping{from: from, to: to})
	}
	sort.Slice(mappings, func(i, j int) bool { return mappings[i].from < mappings[j].from })
	return mappings
}

func cpanelScopedRuleComment(from, to int) string {
	return fmt.Sprintf("%s:%d:%d", cpanelFWTag, from, to)
}

func ensureNftPorts() ([]string, error) {
	_ = execCommand("nft", "add", "table", "inet", "cfm").Run()
	_ = execCommand("nft", "add", "chain", "inet", "cfm", "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}").Run()
	out := runOut("nft", "-a", "list", "chain", "inet", "cfm", "input")
	changes := []string{}
	for _, m := range panelMappings() {
		comment := cpanelScopedRuleComment(m.from, m.to)
		if strings.Contains(out, comment) && strings.Contains(out, fmt.Sprintf("tcp dport %d", m.to)) && strings.Contains(out, "ct status dnat") {
			continue
		}
		args := []string{"add", "rule", "inet", "cfm", "input", "ct", "state", "new", "ct", "status", "dnat", "ct", "original", "proto-dst", strconv.Itoa(m.from), "tcp", "dport", strconv.Itoa(m.to), "accept", "comment", fmt.Sprintf(`"%s"`, comment)}
		if err := runFirewallCmd(fwNft, "nft", args...); err != nil {
			return changes, err
		}
		changes = append(changes, fmt.Sprintf("opened scoped %d->%d (nft cfm/input)", m.from, m.to))
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
	for _, m := range panelMappings() {
		key := fmt.Sprintf("%d:%d", m.from, m.to)
		h, ok := handles[key]
		if !ok {
			changes = append(changes, fmt.Sprintf("scoped %d->%d not found", m.from, m.to))
			continue
		}
		if err := runFirewallCmd(fwNft, "nft", "delete", "rule", "inet", "cfm", "input", "handle", h); err != nil {
			changes = append(changes, fmt.Sprintf("scoped %d->%d failed (%v)", m.from, m.to, err))
			continue
		}
		changes = append(changes, fmt.Sprintf("scoped %d->%d removed", m.from, m.to))
	}
	sort.Strings(changes)
	return changes, nil
}

func ensureFirewalldPorts() ([]string, error) {
	changes := []string{}
	for _, p := range panelTargetPorts {
		ps := fmt.Sprintf("%d/tcp", p)
		if err := runFirewallCmd(fwFirewalld, "firewall-cmd", "--query-port", ps); err == nil {
			changes = append(changes, fmt.Sprintf("tcp/%d already open", p))
			continue
		}
		if err := runFirewallCmd(fwFirewalld, "firewall-cmd", "--add-port", ps); err != nil {
			return changes, err
		}
		if err := runFirewallCmd(fwFirewalld, "firewall-cmd", "--permanent", "--add-port", ps); err != nil {
			return changes, err
		}
		changes = append(changes, fmt.Sprintf("opened tcp/%d (firewalld)", p))
	}
	return changes, nil
}

func removeFirewalldPorts() ([]string, error) {
	changes := []string{}
	for _, p := range panelTargetPorts {
		ps := fmt.Sprintf("%d/tcp", p)
		if err := runFirewallCmd(fwFirewalld, "firewall-cmd", "--query-port", ps); err != nil {
			changes = append(changes, fmt.Sprintf("tcp/%d not found", p))
			continue
		}
		if err := runFirewallCmd(fwFirewalld, "firewall-cmd", "--remove-port", ps); err != nil {
			changes = append(changes, fmt.Sprintf("tcp/%d failed (%v)", p, err))
			continue
		}
		if err := runFirewallCmd(fwFirewalld, "firewall-cmd", "--permanent", "--remove-port", ps); err != nil {
			changes = append(changes, fmt.Sprintf("tcp/%d failed (%v)", p, err))
			continue
		}
		changes = append(changes, fmt.Sprintf("tcp/%d removed", p))
	}
	sort.Strings(changes)
	return changes, nil
}

func panelFirewallState() map[int]string {
	state := map[int]string{}
	for _, p := range panelTargetPorts {
		state[p] = "unknown"
	}
	out := runOut("nft", "-a", "list", "chain", "inet", "cfm", "input")
	for _, m := range panelMappings() {
		if strings.Contains(out, fmt.Sprintf("tcp dport %d", m.to)) && strings.Contains(out, cpanelScopedRuleComment(m.from, m.to)) && strings.Contains(out, "ct status dnat") {
			state[m.to] = "open"
		} else if out != "" {
			state[m.to] = "blocked"
		}
	}
	return state
}

func parseManagedRuleLine(line string) (string, string, bool) {
	norm := strings.ReplaceAll(line, `"`, "")
	if !strings.Contains(norm, cpanelFWTag+":") || !strings.Contains(norm, " handle ") {
		return "", "", false
	}
	h := strings.TrimSpace(norm[strings.LastIndex(norm, " handle ")+8:])
	if fields := strings.Fields(h); len(fields) > 0 {
		h = fields[0]
	}
	parts := strings.Fields(norm)
	port := "?"
	for _, part := range parts {
		if strings.HasPrefix(part, cpanelFWTag+":") {
			comment := strings.TrimPrefix(part, cpanelFWTag+":")
			cparts := strings.Split(comment, ":")
			if len(cparts) >= 2 {
				return cparts[0] + ":" + cparts[1], h, true
			}
		}
	}
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "dport" {
			port = parts[i+1]
			break
		}
	}
	return port, h, true
}
