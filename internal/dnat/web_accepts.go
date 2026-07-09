package dnat

import (
	"fmt"
	"strconv"
	"strings"

	"cfm/internal/firewall"
)

// Web DNAT scoped-accept visibility.
//
// `cfm dnat on` installs scoped `ct status dnat` accepts in inet cfm/input so
// DNAT-translated traffic to the edge listener ports (default 9080/9043) is
// accepted WITHOUT those ports appearing in TCP_IN. The install happens
// silently inside backend.DNATOn, so historically the operator had no way to
// confirm the ports were actually opened — the cPanel DNAT path prints
// `Firewall: opened scoped 2082->12082` and reports per-port state, the web
// path printed nothing. The helpers below parse the live input chain and let
// the CLI report the same information for the web scope, which turns an
// invisible mechanism into a diagnosable one: if an accept shows `open` but
// traffic is still blocked, the drop is upstream (CSF/Imunify INPUT filtering
// or the edge not listening on that port), not a missing CFM rule.

// webDNATAcceptSpec is one expected scoped accept for the global web redirect:
// the post-DNAT listener port `To` carrying original destination port `From`
// over `Proto`.
type webDNATAcceptSpec struct {
	Label string
	Proto string
	From  int
	To    int
}

func webDNATAcceptSpecs(httpPort, httpsPort int) []webDNATAcceptSpec {
	return []webDNATAcceptSpec{
		{Label: "web_http_tcp", Proto: "tcp", From: 80, To: httpPort},
		{Label: "web_https_tcp", Proto: "tcp", From: 443, To: httpsPort},
		{Label: "web_https_udp", Proto: "udp", From: 443, To: httpsPort},
	}
}

// webDNATAcceptStatus is the resolved state of one expected accept.
type webDNATAcceptStatus struct {
	webDNATAcceptSpec
	// State is one of:
	//   "open"    present and placed before the default drop (effective)
	//   "blocked" present but sitting AFTER the default drop (never reached)
	//   "absent"  no matching accept rule found
	State string
}

func (s webDNATAcceptStatus) mapping() string {
	return fmt.Sprintf("%d->%d %s", s.From, s.To, s.Proto)
}

// webDNATEdgeLabels are the labels used ONLY by the global web redirect accepts.
// The per-IP challenge redirect emits accepts with labels like web_http_ip_tcp
// and the panel accepts use the cfm_cpanel_dnat comment namespace; both share
// the inet cfm/input chain, so matching on these exact labels keeps this
// report scoped to the `cfm dnat on` accepts.
var webDNATEdgeLabels = map[string]bool{
	"web_http_tcp":  true,
	"web_https_tcp": true,
	"web_https_udp": true,
}

// webDNATIsDefaultDropLine reports whether a rendered chain line is the
// catch-all NEW-state default drop that ApplyPortsPolicy installs. Kept in sync
// with isInputDefaultDropLine in the nft backend.
func webDNATIsDefaultDropLine(line string) bool {
	norm := strings.ReplaceAll(line, `"`, "")
	if !strings.Contains(norm, "ct state new") || !strings.Contains(norm, "dport 0-65535") || !strings.Contains(norm, " drop") {
		return false
	}
	return strings.Contains(norm, "tcp dport 0-65535") || strings.Contains(norm, "udp dport 0-65535")
}

// parseWebDNATAcceptComment extracts (label, from, to) from a scoped edge DNAT
// accept comment token such as the nft backend's
// "cfm_dnat_accept:web_http_tcp:80:9080" or the nftlib backend's
// "cfm_edge_dnat_accept:web_http_tcp:80:9080". ok is false for any other token
// (panel accepts, per-IP challenge accepts, non-edge labels).
func parseWebDNATAcceptComment(line string) (label string, from, to int, ok bool) {
	norm := strings.ReplaceAll(line, `"`, "")
	for _, tok := range strings.Fields(norm) {
		i := strings.Index(tok, "_dnat_accept:")
		if i < 0 {
			continue
		}
		parts := strings.Split(tok[i+len("_dnat_accept:"):], ":")
		if len(parts) != 3 {
			continue
		}
		if !webDNATEdgeLabels[parts[0]] {
			continue
		}
		f, err1 := strconv.Atoi(parts[1])
		t, err2 := strconv.Atoi(parts[2])
		if err1 != nil || err2 != nil {
			continue
		}
		return parts[0], f, t, true
	}
	return "", 0, 0, false
}

// resolveWebDNATAcceptState parses the rendered inet cfm/input chain and returns
// the effective state of each expected web DNAT accept for the given listener
// ports. An accept only counts as "open" when it appears before the default
// drop, since nftables is first-match-wins within the chain.
func resolveWebDNATAcceptState(chainText string, httpPort, httpsPort int) []webDNATAcceptStatus {
	type found struct{ beforeDrop bool }
	present := map[string]found{}
	seenDrop := false
	for _, line := range strings.Split(chainText, "\n") {
		if webDNATIsDefaultDropLine(line) {
			seenDrop = true
			continue
		}
		label, from, to, ok := parseWebDNATAcceptComment(line)
		if !ok {
			continue
		}
		key := fmt.Sprintf("%s:%d:%d", label, from, to)
		if _, exists := present[key]; !exists {
			present[key] = found{beforeDrop: !seenDrop}
		}
	}
	specs := webDNATAcceptSpecs(httpPort, httpsPort)
	out := make([]webDNATAcceptStatus, 0, len(specs))
	for _, s := range specs {
		key := fmt.Sprintf("%s:%d:%d", s.Label, s.From, s.To)
		state := "absent"
		if f, ok := present[key]; ok {
			if f.beforeDrop {
				state = "open"
			} else {
				state = "blocked"
			}
		}
		out = append(out, webDNATAcceptStatus{webDNATAcceptSpec: s, State: state})
	}
	return out
}

// webDNATAcceptStates queries the live input chain via the backend and resolves
// the per-mapping accept state. The bool is false (and the slice nil) when the
// chain cannot be listed, so callers can stay silent rather than print a
// misleading "absent".
func webDNATAcceptStates(backend firewall.Backend, httpPort, httpsPort int) ([]webDNATAcceptStatus, bool) {
	if backend == nil {
		return nil, false
	}
	txt, err := backend.ListChainText("inet", "cfm", "input")
	if err != nil || strings.TrimSpace(txt) == "" {
		return nil, false
	}
	return resolveWebDNATAcceptState(txt, httpPort, httpsPort), true
}

// printWebDNATAcceptsOnEnable reports the scoped accepts that `cfm dnat on` just
// installed, mirroring the cPanel path's `Firewall: opened scoped …` lines and
// warning loudly when a listener port is NOT effectively open.
func printWebDNATAcceptsOnEnable(backend firewall.Backend, httpPort, httpsPort int) {
	states, ok := webDNATAcceptStates(backend, httpPort, httpsPort)
	if !ok {
		fmt.Println("Firewall: WARNING could not verify scoped DNAT accepts in inet cfm/input")
		return
	}
	for _, st := range states {
		switch st.State {
		case "open":
			fmt.Printf("Firewall: opened scoped %s (nft cfm/input)\n", st.mapping())
		case "blocked":
			fmt.Printf("Firewall: WARNING scoped accept %s is present but sits AFTER the default drop; traffic to :%d will be dropped — run `cfm dnat off` then `cfm dnat on` to reinstall it\n", st.mapping(), st.To)
		default:
			fmt.Printf("Firewall: WARNING scoped accept %s NOT installed; traffic to :%d will be dropped unless an external firewall (CSF/Imunify) or TCP_IN opens :%d\n", st.mapping(), st.To, st.To)
		}
	}
}

func webDNATAcceptStateLabel(state string) string {
	switch state {
	case "open":
		return "open"
	case "blocked":
		return "BLOCKED (accept present but after the default drop; reinstall via cfm dnat off/on)"
	default:
		return "ABSENT (listener port not opened — check external firewall/CSF/Imunify or add to TCP_IN)"
	}
}
