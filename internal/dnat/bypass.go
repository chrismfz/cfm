package dnat

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"cfm/internal/firewall"
)

// runBypassCLI handles the `cfm dnat [cpanel] bypass {add|remove|list}`
// subcommand family. The scope argument selects which on-disk bypass list
// is being managed and which nftables chain gets re-rendered after a
// successful mutation.
//
// Shape (web scope):
//
//	cfm dnat bypass list
//	cfm dnat bypass add    <IP|CIDR>
//	cfm dnat bypass remove <IP|CIDR>
//
// Shape (cpanel scope):
//
//	cfm dnat cpanel bypass list
//	cfm dnat cpanel bypass add    <IP|CIDR>
//	cfm dnat cpanel bypass remove <IP|CIDR>
//
// Mutations are persisted to the bypass file and then the matching DNAT
// table is re-rendered IFF the DNAT in question is currently on. When
// DNAT is off the file is still updated, and the bypass takes effect on
// the next `cfm dnat [cpanel] on`.
func runBypassCLI(args []string, scope firewall.DNATBypassScope, backend firewall.Backend) int {
	if len(args) == 0 {
		printBypassUsage(scope)
		return 2
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "help", "-h", "--help":
		printBypassUsage(scope)
		return 0
	case "list", "ls", "show":
		return bypassList(scope)
	case "add":
		if len(rest) == 0 {
			printBypassUsage(scope)
			return 2
		}
		return bypassAdd(scope, rest[0], backend)
	case "remove", "rm", "del", "delete":
		if len(rest) == 0 {
			printBypassUsage(scope)
			return 2
		}
		return bypassRemove(scope, rest[0], backend)
	default:
		printBypassUsage(scope)
		return 2
	}
}

func printBypassUsage(scope firewall.DNATBypassScope) {
	cmd := "dnat bypass"
	if scope == firewall.DNATBypassScopeCpanel {
		cmd = "dnat cpanel bypass"
	}
	fmt.Fprintf(os.Stderr, `Usage:
  cfm %s list
  cfm %s add    <IP|CIDR>
  cfm %s remove <IP|CIDR>

Manages source-IP bypass for the %s DNAT chain. Listed addresses skip the
DNAT redirect and reach the upstream service (cpsrvd / Apache) directly,
which is useful for trusted peers such as cluster nodes and cPanel-to-
cPanel transfer source hosts.

List file: %s
`, cmd, cmd, cmd, scope.String(), scope.Path())
}

func bypassList(scope firewall.DNATBypassScope) int {
	entries, skipped, err := firewall.LoadDNATBypass(scope.Path())
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", scope.Path(), err)
		return 1
	}
	if len(entries) == 0 && len(skipped) == 0 {
		fmt.Printf("(no entries in %s)\n", scope.Path())
		return 0
	}
	if len(entries) > 0 {
		fmt.Printf("# %s DNAT bypass (%d entries)\n", scope.String(), len(entries))
		for _, e := range entries {
			kind := "ip"
			if e.IsCIDR {
				kind = "cidr"
			}
			if e.IsV6 {
				kind = "ipv6_" + kind
			}
			fmt.Printf("  %-40s %s\n", e.Value, kind)
		}
	}
	if len(skipped) > 0 {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "# skipped (unparseable) entries:")
		for _, s := range skipped {
			fmt.Fprintf(os.Stderr, "  %s\n", s)
		}
		return 1
	}
	return 0
}

func bypassAdd(scope firewall.DNATBypassScope, target string, backend firewall.Backend) int {
	entry, err := firewall.ParseDNATBypassEntry(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid bypass target %q: %v\n", target, err)
		return 2
	}
	added, err := appendBypassUnique(scope.Path(), entry.Value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update %s: %v\n", scope.Path(), err)
		return 1
	}
	if !added {
		fmt.Printf("already present: %s\n", entry.Value)
		return 0
	}
	fmt.Printf("added %s to %s\n", entry.Value, scope.Path())
	return reloadDNATScope(scope, backend)
}

func bypassRemove(scope firewall.DNATBypassScope, target string, backend firewall.Backend) int {
	entry, err := firewall.ParseDNATBypassEntry(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid bypass target %q: %v\n", target, err)
		return 2
	}
	removed, err := removeBypassEntry(scope.Path(), entry.Value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update %s: %v\n", scope.Path(), err)
		return 1
	}
	if !removed {
		fmt.Printf("not found: %s\n", entry.Value)
		return 0
	}
	fmt.Printf("removed %s from %s\n", entry.Value, scope.Path())
	return reloadDNATScope(scope, backend)
}

// appendBypassUnique appends the entry to the bypass file (creating it as
// 0644 if missing) iff the same canonical value is not already present.
// Returns true if a new line was written.
func appendBypassUnique(path, value string) (bool, error) {
	clean := filepath.Clean(path)
	// Best-effort ensure parent dir; /etc/cfm always exists on a real install.
	if dir := filepath.Dir(clean); dir != "." && dir != "/" {
		_ = os.MkdirAll(dir, 0o755)
	}
	existing, err := os.ReadFile(clean) // #nosec G304
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if entryAlreadyPresent(existing, value) {
		return false, nil
	}
	// Append with a trailing newline; we don't care if the file ended
	// without one because os.OpenFile with O_APPEND doesn't touch existing
	// bytes.
	f, err := os.OpenFile(clean, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640) // #nosec G304
	if err != nil {
		return false, err
	}
	defer f.Close()
	if _, err := io.WriteString(f, value+"\n"); err != nil {
		return false, err
	}
	return true, nil
}

// removeBypassEntry strips any line whose canonical value matches `value`
// from the bypass file, preserving comments and ordering of all other
// lines. Returns true if at least one matching line was removed.
func removeBypassEntry(path, value string) (bool, error) {
	clean := filepath.Clean(path)
	existing, err := os.ReadFile(clean) // #nosec G304
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	var out bytes.Buffer
	removed := false
	sc := bufio.NewScanner(bytes.NewReader(existing))
	for sc.Scan() {
		raw := sc.Text()
		head := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if head == "" {
			out.WriteString(raw)
			out.WriteByte('\n')
			continue
		}
		token := strings.Fields(head)[0]
		parsed, err := firewall.ParseDNATBypassEntry(token)
		if err != nil {
			// Preserve unparseable lines verbatim so the operator can fix them.
			out.WriteString(raw)
			out.WriteByte('\n')
			continue
		}
		if parsed.Value == value {
			removed = true
			continue
		}
		out.WriteString(raw)
		out.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return false, err
	}
	if !removed {
		return false, nil
	}
	return true, os.WriteFile(clean, out.Bytes(), 0o640)
}

// entryAlreadyPresent reports whether a canonical bypass value already
// exists in the bypass file content.
func entryAlreadyPresent(fileContent []byte, value string) bool {
	sc := bufio.NewScanner(bytes.NewReader(fileContent))
	for sc.Scan() {
		head := strings.TrimSpace(strings.SplitN(sc.Text(), "#", 2)[0])
		if head == "" {
			continue
		}
		token := strings.Fields(head)[0]
		parsed, err := firewall.ParseDNATBypassEntry(token)
		if err != nil {
			continue
		}
		if parsed.Value == value {
			return true
		}
	}
	return false
}

// reloadDNATScope re-renders the relevant DNAT table so a freshly added or
// removed bypass entry takes effect immediately. No-op when the matching
// DNAT is off (operator will pick up the change on the next `cfm dnat
// [cpanel] on`).
func reloadDNATScope(scope firewall.DNATBypassScope, backend firewall.Backend) int {
	if backend == nil {
		fmt.Fprintln(os.Stderr, "no firewall backend available; file updated but DNAT rules NOT reloaded")
		return 1
	}
	switch scope {
	case firewall.DNATBypassScopeCpanel:
		on, _, err := backend.PanelDNATStatus()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cpanel DNAT status check failed: %v\n", err)
			return 1
		}
		if !on {
			fmt.Println("cpanel DNAT is OFF; bypass will apply on the next `cfm dnat cpanel on`")
			return 0
		}
		// Re-render with the same priority we'd use for a fresh `on`.
		if err := backend.PanelDNATOn(PanelStartupPriority()); err != nil {
			fmt.Fprintf(os.Stderr, "cpanel DNAT reload failed: %v\n", err)
			return 1
		}
		fmt.Println("cpanel DNAT reloaded with updated bypass list")
		return 0
	case firewall.DNATBypassScopeWeb:
		on, err := backend.DNATStatus(DefaultFamily, DefaultTable)
		if err != nil {
			fmt.Fprintf(os.Stderr, "web DNAT status check failed: %v\n", err)
			return 1
		}
		if !on {
			fmt.Println("web DNAT is OFF; bypass will apply on the next `cfm dnat on`")
			return 0
		}
		hp, hsp := currentWebDNATPorts(backend)
		if err := backend.DNATOn(DefaultFamily, DefaultTable, hp, hsp); err != nil {
			fmt.Fprintf(os.Stderr, "web DNAT reload failed: %v\n", err)
			return 1
		}
		fmt.Println("web DNAT reloaded with updated bypass list")
		return 0
	}
	return 0
}

// currentWebDNATPorts returns the HTTP/HTTPS ports currently in use by the
// web DNAT table, falling back to defaults if they can't be determined.
// We need them to re-render the table with the same listener targets after
// a bypass change.
func currentWebDNATPorts(backend firewall.Backend) (int, int) {
	hp, hsp := DefaultHTTPPort, DefaultHTTPSPort
	if backend == nil {
		return hp, hsp
	}
	show, err := backend.DNATShow(DefaultFamily, DefaultTable)
	if err != nil {
		return hp, hsp
	}
	for _, line := range strings.Split(show, "\n") {
		line = strings.TrimSpace(line)
		// Lines like: "tcp dport 80  dnat to :9080"
		if !strings.HasPrefix(line, "tcp dport") && !strings.HasPrefix(line, "udp dport") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		dport := fields[2]
		dest := strings.TrimPrefix(fields[len(fields)-1], ":")
		switch dport {
		case "80":
			if p, err := strconv.Atoi(dest); err == nil {
				hp = p
			}
		case "443":
			if p, err := strconv.Atoi(dest); err == nil {
				hsp = p
			}
		}
	}
	return hp, hsp
}
