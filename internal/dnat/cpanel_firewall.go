package dnat

import (
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

const cpanelFWTag = "cfm_cpanel_dnat"

type fwBackend string

const (
	fwUnknown   fwBackend = "unknown"
	fwNft       fwBackend = "nftables"
	fwFirewalld fwBackend = "firewalld"
)

func detectFWBackend() fwBackend {
	if exec.Command("firewall-cmd", "--state").Run() == nil {
		return fwFirewalld
	}
	if exec.Command("nft", "list", "ruleset").Run() == nil {
		return fwNft
	}
	return fwUnknown
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
	_ = exec.Command("nft", "add", "table", "inet", "cfm").Run()
	_ = exec.Command("nft", "add", "chain", "inet", "cfm", "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}").Run()
	out := runOut("nft", "-a", "list", "chain", "inet", "cfm", "input")
	changes := []string{}
	for _, p := range panelTargetPorts {
		want := fmt.Sprintf("tcp dport %d", p)
		if strings.Contains(out, want) && strings.Contains(out, cpanelFWTag) {
			continue
		}
		cmd := fmt.Sprintf("add rule inet cfm input tcp dport %d ct state new accept comment \"%s:%d\"", p, cpanelFWTag, p)
		if err := exec.Command("nft", "-f", "-").Run(); err != nil {
			_ = cmd
		}
		c := exec.Command("nft", "add", "rule", "inet", "cfm", "input", "tcp", "dport", strconv.Itoa(p), "ct", "state", "new", "accept", "comment", fmt.Sprintf("%s:%d", cpanelFWTag, p))
		if err := c.Run(); err != nil {
			return changes, err
		}
		changes = append(changes, fmt.Sprintf("opened tcp/%d (nft cfm/input)", p))
	}
	return changes, nil
}

func removeNftPorts() ([]string, error) {
	out := runOut("nft", "-a", "list", "chain", "inet", "cfm", "input")
	changes := []string{}
	for _, line := range strings.Split(out, "\n") {
		port, h, ok := parseManagedRuleLine(line)
		if !ok { continue }
		if err := exec.Command("nft", "delete", "rule", "inet", "cfm", "input", "handle", h).Run(); err != nil {
			return changes, err
		}
		changes = append(changes, fmt.Sprintf("closed tcp/%s (nft handle %s)", port, h))
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
