// internal/unblock/unblock.go
package unblock

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"cfm/internal/firewall"
	"cfm/internal/reporting"
)

type StepAction string

const (
	ActionRemoved     StepAction = "removed"
	ActionWhitelisted StepAction = "whitelisted"
	ActionNotFound    StepAction = "not_found"
	ActionChecked     StepAction = "checked"
	ActionError       StepAction = "error"
)

type Source string

const (
	SrcNFT      Source = "nft"
	SrcCFMDeny  Source = "cfm.deny"
	SrcCSF      Source = "csf"
	SrcImunify  Source = "imunify360"
	SrcFeeds    Source = "feeds"
	SrcFail2Ban Source = "fail2ban"
	// SrcWAF covers the OpenResty/Lua WAF enforcement planes that live
	// outside the firewall/blocklist: webdetector challenge/block state and
	// the per-IP shared-dict caches (throttle buckets, decision cache, geo,
	// ok-touch, waf-push cooldown). These never appear in a blocklist search.
	SrcWAF Source = "waf"
)

type Step struct {
	Source Source
	Action StepAction
	Detail string
	Feeds  []string
	Err    string
	Dur    time.Duration // how long this step took
}

type Result struct {
	IP          net.IP
	Steps       []Step
	FromFeeds   []string
	WasBlocked  bool
	Whitelisted bool
	// WAF holds the result of clearing the OpenResty/Lua WAF planes for this
	// IP (challenge/block + shared-dict per-IP caches). nil when no WAFCleaner
	// was wired (e.g. DNAT mode, or a process with no in-daemon bridge).
	WAF *WAFResult
	mu  sync.Mutex // protects Steps during concurrent goroutine appends
}

type Options struct {
	BE            firewall.Backend   // nft backend
	ConfigDir     string             // για cfm.deny
	TempWhitelist bool               // αν είναι από feeds -> κάνε allow override
	AllowTTL      *time.Duration     // TTL whitelist (nil/0 = PERMANENT — also governs the imunify white expiration; always set it)
	Reporter      reporting.Reporter // optional: για ReportUnblock/Block
	ReportWhy     string             // π.χ. "cli" ή "agent"
	SendAPI       bool               // αν θέλουμε να γίνει report/unblock
	// ImunifyWhiteTTL, when set, adds an imunify white entry with this TTL
	// on every unblock (not just feeds-origin ones), except for an IP (or IPv6
	// /64) an operator's white entry already lists, an IPv6 IP whose /64
	// imunify wasn't blocking,
	// and, in a batch larger than graceBatchMax, an IP imunify wasn't blocking
	// (imunifyUnblockMany). This is the grace window that stops imunify's own
	// engine from re-greylisting the visitor seconds after we cleared them —
	// without it, a user bounced by imunify GRAY can loop: unblock →
	// re-greylist → unblock.
	ImunifyWhiteTTL *time.Duration
	// WAF, when set, also clears the OpenResty/Lua WAF planes for the IP
	// (webdetector challenge/block + per-IP shared-dict caches) as part of a
	// "force unblock". Best-effort: failures are recorded as a step, never
	// fatal. Do clears the WAF plane iff this is non-nil — there is no
	// implicit fallback, so a caller that already cleared the WAF plane
	// synchronously (e.g. the /unblock handler, which needs the findings in
	// its immediate response) can leave this nil to avoid a double clear.
	// Callers that want it should set it to unblock.WAFCleanerHook().
	WAF WAFCleaner
}

// ----------------------------------------------

// Do unblocks one IP: DoMany for one address. It returns *Result rather than
// Result so the embedded sync.Mutex is never copied — the tool steps append
// to r.Steps under it from concurrent goroutines.
func Do(ctx context.Context, ip net.IP, opts Options) (*Result, error) {
	if ip == nil {
		return nil, errors.New("nil IP")
	}
	return DoMany(ctx, []net.IP{ip}, opts)[ip.String()], nil
}

// ----------------- helpers -----------------------

func binaryExists(name string) bool { _, err := exec.LookPath(name); return err == nil }

func runCmd(ctx context.Context, r *Result, src Source, name string, args ...string) {
	addStep(r, runTool(ctx, src, name, args...))
}

// listSetNamesByPrefixes parses a single "nft -t -n list table inet cfm" output
// and returns set names that start with any of the provided prefixes.
func listSetNamesByPrefixes(be firewall.Backend, prefixes ...string) ([]string, error) {
	outS, err := be.ListTableTextNoDNS("inet", "cfm")
	if err != nil {
		return nil, err
	}
	// normalize prefixes
	pfx := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p != "" {
			pfx = append(pfx, p)
		}
	}
	var names []string
	sc := bufio.NewScanner(bytes.NewReader([]byte(outS)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		// lines like:  set block_ext_v4_hosts_myblock { type ipv4_addr; flags timeout; }
		if !strings.HasPrefix(line, "set ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[1]
		for _, p := range pfx {
			if strings.HasPrefix(name, p) {
				names = append(names, name)
				break
			}
		}
	}
	return names, nil
}

// feedHostSetPrefixes are the per-feed host sets' name prefixes; the feed key
// follows them.
var feedHostSetPrefixes = []string{
	"allow_ext_v4_hosts_", "block_ext_v4_hosts_",
	"allow_ext_v6_hosts_", "block_ext_v6_hosts_",
}

// feedKeyFromSet extracts the feed key from a set name like
// "block_ext_v4_hosts_myblock" ("" for any other set), and whether the set
// holds IPv4 addresses. Both come from the prefix: a feed key can itself
// contain "_v4_" or "_" (a feed named bl-v4-ssh has the key bl_v4_ssh).
func feedKeyFromSet(setName string) (key string, v4 bool) {
	for _, p := range feedHostSetPrefixes {
		if strings.HasPrefix(setName, p) && len(setName) > len(p) {
			return setName[len(p):], strings.Contains(p, "_v4_")
		}
	}
	return "", false
}

// unitActive returns true if `systemctl is-active --quiet <unit>` succeeds.
func unitActive(unit string) bool {
	if !binaryExists("systemctl") {
		return true // best-effort: if no systemd, don't block
	}
	if !allowedSystemdUnit(unit) {
		return false
	}
	// #nosec G204 -- unit is restricted to a static allowlist.
	return exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil
}

func allowedBinary(name string) bool {
	switch name {
	case "csf", "fail2ban-client", "imunify360-agent":
		return true
	default:
		return false
	}
}

func allowedConfigFile(name string) bool {
	return name == "cfm.deny"
}

func allowedSystemdUnit(unit string) bool {
	switch unit {
	case "csf", "fail2ban", "imunify360", "imunify360-agent", "imunify360.service", "imunify360-agent.service":
		return true
	default:
		return false
	}
}
