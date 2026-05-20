package firewall

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// DNAT bypass list paths. Each file holds one IP or CIDR per line, with `#`
// comments and blank lines ignored — same format as cfm.allow / cfm.deny.
//
// Two separate files for the two DNAT structures cfm manages independently:
//   - DNATBypassWebPath:    exempts source IPs from the WEB DNAT chain
//                           (80 → HTTP_PORT, 443 → HTTPS_PORT) that gets
//                           installed by `cfm dnat on`.
//   - DNATBypassCpanelPath: exempts source IPs from the cPanel panel DNAT
//                           chain (2082/2083/2086/2087/2095/2096/2222 →
//                           12082-12222) that gets installed by
//                           `cfm dnat cpanel on`.
//
// Use case: cluster peers / partner servers / migration source hosts whose
// traffic must reach cpsrvd or Apache directly without going through CFM's
// nginx/openresty challenge+filter layer. Typical example is a cPanel-to-
// cPanel WHM Transfer Tool source, whose `whm_xfer_download-ssl` rsync
// stream uses a custom non-standard HTTP variant that breaks when wrapped
// by any HTTP-aware proxy.
// These are vars rather than consts so tests can point them at a tempdir.
// In production they are never reassigned; the value is the canonical path.
var (
	DNATBypassWebPath    = "/etc/cfm/cfm.dnat_bypass"
	DNATBypassCpanelPath = "/etc/cfm/cfm.dnat_cpanel_bypass"
)

// DNATBypassScope identifies which DNAT chain a bypass entry applies to.
type DNATBypassScope int

const (
	DNATBypassScopeWeb DNATBypassScope = iota
	DNATBypassScopeCpanel
)

// String returns the canonical name of the bypass scope, used by CLI output
// and log messages.
func (s DNATBypassScope) String() string {
	switch s {
	case DNATBypassScopeWeb:
		return "web"
	case DNATBypassScopeCpanel:
		return "cpanel"
	}
	return "unknown"
}

// Path returns the on-disk file path for the bypass list of this scope.
func (s DNATBypassScope) Path() string {
	switch s {
	case DNATBypassScopeWeb:
		return DNATBypassWebPath
	case DNATBypassScopeCpanel:
		return DNATBypassCpanelPath
	}
	return ""
}

// DNATBypassEntry is one parsed line from a bypass list file.
type DNATBypassEntry struct {
	// Raw is the on-disk text of the entry, including any trailing comment.
	Raw string
	// Value is the canonical IP or CIDR (without comments or whitespace).
	Value string
	// IsCIDR is true if Value is a network in CIDR form, false if it is a
	// single IP address.
	IsCIDR bool
	// IsV6 is true if the entry is an IPv6 address or v6 network.
	IsV6 bool
}

// LoadDNATBypass reads a bypass file and returns the parsed entries.
// Returns an empty slice (not an error) if the file does not exist;
// missing-list-means-no-bypass is the desired default behaviour at runtime.
// Lines that fail to parse as IP/CIDR are skipped and counted in the
// returned `skipped` slice so the caller can surface them as warnings.
func LoadDNATBypass(path string) (entries []DNATBypassEntry, skipped []string, err error) {
	clean := filepath.Clean(path)
	b, readErr := os.ReadFile(clean) // #nosec G304 -- caller-supplied path constants
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return nil, nil, nil
		}
		return nil, nil, readErr
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		raw := sc.Text()
		// Strip trailing inline comment, then surrounding whitespace.
		head := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if head == "" {
			continue
		}
		// Each line should be a single IP or CIDR token (anything after a
		// space on the same line is treated as a comment fragment, same as
		// cfm.allow).
		token := strings.Fields(head)[0]
		entry, parseErr := parseBypassToken(token)
		if parseErr != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", raw, parseErr))
			continue
		}
		entry.Raw = raw
		entries = append(entries, entry)
	}
	if sc.Err() != nil {
		return nil, nil, sc.Err()
	}
	return entries, skipped, nil
}

// ParseDNATBypassEntry canonicalises a single CLI input string into a
// DNATBypassEntry. The CLI uses this for `bypass add` validation.
func ParseDNATBypassEntry(s string) (DNATBypassEntry, error) {
	return parseBypassToken(strings.TrimSpace(s))
}

func parseBypassToken(token string) (DNATBypassEntry, error) {
	if strings.ContainsRune(token, '/') {
		_, nw, err := net.ParseCIDR(token)
		if err != nil {
			return DNATBypassEntry{}, fmt.Errorf("invalid CIDR: %w", err)
		}
		nw.IP = nw.IP.Mask(nw.Mask)
		return DNATBypassEntry{
			Value:  nw.String(),
			IsCIDR: true,
			IsV6:   nw.IP.To4() == nil,
		}, nil
	}
	ip := net.ParseIP(token)
	if ip == nil {
		return DNATBypassEntry{}, fmt.Errorf("invalid IP address: %q", token)
	}
	return DNATBypassEntry{
		Value:  ip.String(),
		IsCIDR: false,
		IsV6:   ip.To4() == nil,
	}, nil
}

// DNATBypassComment is the nft rule comment attached to every bypass accept
// rule so operators and the nftlib reconciler can identify them. It is a
// single source of truth shared by both the nft (shell-out) and nftlib
// (netlink-direct) backends.
const DNATBypassComment = "cfm_dnat_bypass"

// DNATBypassRuleExprs returns the nftables `add rule ... accept` lines that
// implement the bypass for a given prerouting chain. The caller is expected
// to inject these between the existing `iif "lo" accept` line and the dport
// DNAT redirect rules, so that the source-IP match short-circuits before
// any NAT translation happens.
//
// Family / tableName / chainName let the same helper serve both the web
// DNAT chain ("inet cfm-dnat-web" / "prerouting") and the cPanel panel
// DNAT chain ("inet cfm_panel_redirect" / "prerouting").
func DNATBypassRuleExprs(entries []DNATBypassEntry, family, tableName, chainName string) []string {
	if len(entries) == 0 {
		return nil
	}
	rules := make([]string, 0, len(entries))
	for _, e := range entries {
		rules = append(rules, fmt.Sprintf(
			"add rule %s %s %s %s %s accept comment %q",
			family, tableName, chainName, dnatBypassMatcherStr(e), e.Value, DNATBypassComment,
		))
	}
	return rules
}

// DNATBypassChainBlock returns nft inline rule text for embedding inside a
// `chain { ... }` table-block script (used by the nft shell-out backend's
// dnatScript). Each bypass entry becomes an indented accept rule; skipped
// entries become inline WARNING comments tagged with fileHint (the filename
// fragment used in the warning, e.g. "cfm.dnat_bypass").
func DNATBypassChainBlock(entries []DNATBypassEntry, skipped []string, fileHint string) string {
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "    %s %s accept comment %q\n", dnatBypassMatcherStr(e), e.Value, DNATBypassComment)
	}
	for _, warn := range skipped {
		fmt.Fprintf(&b, "    # WARNING: %s skipped entry: %s\n", fileHint, warn)
	}
	return b.String()
}

// dnatBypassMatcherStr returns the nft payload matcher prefix for an entry:
// "ip saddr" for IPv4, "ip6 saddr" for IPv6.
func dnatBypassMatcherStr(e DNATBypassEntry) string {
	if e.IsV6 {
		return "ip6 saddr"
	}
	return "ip saddr"
}
