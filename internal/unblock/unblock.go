// internal/unblock/unblock.go
package unblock

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
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
	mu          sync.Mutex // protects Steps during concurrent goroutine appends
}

type Options struct {
	BE            firewall.Backend   // nft backend
	ConfigDir     string             // για cfm.deny
	TempWhitelist bool               // αν είναι από feeds -> κάνε allow override
	AllowTTL      *time.Duration     // TTL whitelist (nil = permanent)
	Reporter      reporting.Reporter // optional: για ReportUnblock/Block
	ReportWhy     string             // π.χ. "cli" ή "agent"
	SendAPI       bool               // αν θέλουμε να γίνει report/unblock
	Fail2BanUnban bool
}

// ----------------------------------------------

// Do returns *Result rather than Result so the embedded sync.Mutex is never
// copied — runCmd holds it during concurrent goroutine appends to r.Steps,
// and a value-return would copy the mutex into the caller's frame, leaving
// the goroutines synchronizing on a now-orphaned lock.
func Do(ctx context.Context, ip net.IP, opts Options) (*Result, error) {
	if ip == nil {
		return nil, errors.New("nil IP")
	}
	r := &Result{IP: ip}

	// 0) Feeds detection — FAST: discover per-feed sets (terse) and probe membership with HasElem
	t0 := time.Now()
	feeds := feedsBlockingFast(opts.BE, ip)
	if len(feeds) > 0 {
		r.FromFeeds = feeds
		r.Steps = append(r.Steps, Step{
			Source: SrcFeeds, Action: ActionChecked, Feeds: feeds, Dur: time.Since(t0),
		})
	}

	// 1) nft remove (no expensive EnsureBase; table should already exist in normal ops)
	if opts.BE != nil {
		if err := opts.BE.EnsureBase(); err != nil {
			r.Steps = append(r.Steps, Step{Source: SrcNFT, Action: ActionError, Detail: "EnsureBase failed", Err: err.Error()})
		}
		t1 := time.Now()
		if err := opts.BE.RemoveBlock(ip); err != nil {
			r.Steps = append(r.Steps, Step{Source: SrcNFT, Action: ActionError, Detail: "RemoveBlock failed", Err: err.Error()})
		} else {
			r.Steps = append(r.Steps, Step{Source: SrcNFT, Action: ActionRemoved, Dur: time.Since(t1)})
			r.WasBlocked = true
		}
	}

	// 1a) cfm.deny cleanup
	if opts.ConfigDir != "" {
		t2 := time.Now()
		if removed := removeFromFile(opts.ConfigDir, "cfm.deny", ip.String()); removed {
			r.Steps = append(r.Steps, Step{Source: SrcCFMDeny, Action: ActionRemoved, Dur: time.Since(t2)})
			r.WasBlocked = true
		} else {
			r.Steps = append(r.Steps, Step{Source: SrcCFMDeny, Action: ActionNotFound, Dur: time.Since(t2)})
		}
	}

	// 2) CSF (παράλληλα με άλλες εντολές)
	var wg sync.WaitGroup
	if binaryExists("csf") && unitActive("csf") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// -tr, -dr, -ta
			runCmd(ctx, r, SrcCSF, "csf", "-tr", ip.String())
			runCmd(ctx, r, SrcCSF, "csf", "-dr", ip.String())
			runCmd(ctx, r, SrcCSF, "csf", "-ta", ip.String())
		}()
	} else {
		r.Steps = append(r.Steps, Step{Source: SrcCSF, Action: ActionChecked, Detail: "not present or inactive"})
	}

	// 2.5) Fail2Ban (no opts; check binary + unit)
	t3 := time.Now()
	if binaryExists("fail2ban-client") && unitActive("fail2ban") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runCmd(ctx, r, SrcFail2Ban, "fail2ban-client", "unban", ip.String())
		}()
	} else {
		r.Steps = append(r.Steps, Step{
			Source: SrcFail2Ban, Action: ActionChecked, Detail: "not present or inactive", Dur: time.Since(t3),
		})
	}

	// 3) Imunify360
	imunifyActive := unitActive("imunify360") || unitActive("imunify360-agent") || unitActive("imunify360.service") || unitActive("imunify360-agent.service")
	if binaryExists("imunify360-agent") && imunifyActive {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runCmd(ctx, r, SrcImunify, "imunify360-agent", "ip-list", "local", "delete", "--purpose", "drop", ip.String())
			runCmd(ctx, r, SrcImunify, "imunify360-agent", "ip-list", "local", "delete", "--purpose", "captcha", ip.String())
			// Προαιρετικά: να μπει white όταν προέρχεται από feeds
			if len(r.FromFeeds) > 0 {
				whiteArgs := []string{"ip-list", "local", "add", "--purpose", "white", "--comment", "CFM auto-unblock", ip.String()}
				// imunify defaults to a PERMANENT entry; bound it to the
				// same TTL as the nft allow override (--expiration wants
				// an absolute unix timestamp, not a duration).
				if opts.AllowTTL != nil && *opts.AllowTTL > 0 {
					whiteArgs = append(whiteArgs, "--expiration", strconv.FormatInt(time.Now().Add(*opts.AllowTTL).Unix(), 10))
				}
				runCmd(ctx, r, SrcImunify, "imunify360-agent", whiteArgs...)
			}
		}()
	} else {
		r.Steps = append(r.Steps, Step{Source: SrcImunify, Action: ActionChecked, Detail: "not present or inactive"})
	}

	wg.Wait()

	// 4) Αν είναι από feeds -> τοπικό whitelist override (προαιρετικά)
	if len(r.FromFeeds) > 0 && opts.BE != nil && opts.TempWhitelist {
		if err := opts.BE.AddAllow(ip, opts.AllowTTL); err != nil {
			r.Steps = append(r.Steps, Step{Source: SrcFeeds, Action: ActionError, Detail: "AddAllow failed", Err: err.Error(), Feeds: r.FromFeeds})
		} else {
			r.Steps = append(r.Steps, Step{Source: SrcFeeds, Action: ActionWhitelisted, Feeds: r.FromFeeds})
			r.Whitelisted = true
		}
	}

	// 5) Optional API report (ενοποιημένα — π.χ. να στείλουμε reason = "feeds: a,b" ή "manual")
	if opts.SendAPI && opts.Reporter != nil && opts.ReportWhy != "agent" {
		why := "manual"
		if len(r.FromFeeds) > 0 {
			why = "feeds:" + strings.Join(r.FromFeeds, ",")
		}
		// re-use του συμβολαίου
		_ = opts.Reporter.ReportUnblock(ip.String(), opts.ReportWhy, why)
	}

	return r, nil
}

// ----------------- helpers -----------------------

func binaryExists(name string) bool { _, err := exec.LookPath(name); return err == nil }

func runCmd(ctx context.Context, r *Result, src Source, name string, args ...string) {
	if !allowedBinary(name) {
		r.mu.Lock()
		r.Steps = append(r.Steps, Step{
			Source: src, Action: ActionError, Err: "blocked binary", Detail: "binary not in allowlist",
		})
		r.mu.Unlock()
		return
	}
	start := time.Now()
	// #nosec G204 -- `name/args` are constrained by an internal allowlist + fixed callsites.
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	step := Step{Source: src, Action: ActionChecked, Dur: time.Since(start)}
	if err != nil {
		step.Action = ActionError
		step.Err = err.Error()
		step.Detail = strings.TrimSpace(string(out))
	} else {
		step.Detail = strings.TrimSpace(string(out))
	}
	r.mu.Lock()
	r.Steps = append(r.Steps, step)
	r.mu.Unlock()
}

func removeFromFile(cfgDir, filename, ip string) bool {
	if cfgDir == "" {
		return false
	}
	if !allowedConfigFile(filename) {
		return false
	}
	path := filepath.Join(cfgDir, filename)
	baseCfg := filepath.Clean(cfgDir)
	cleanPath := filepath.Clean(path)
	if cleanPath != baseCfg && !strings.HasPrefix(cleanPath, baseCfg+string(os.PathSeparator)) {
		return false
	}
	// #nosec G304 -- path is constrained to cfgDir + allowlisted filename and verified to remain within cfgDir.
	f, err := os.Open(cleanPath)
	if err != nil {
		return false
	}
	defer f.Close()

	var kept []string
	removed := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			kept = append(kept, line)
			continue
		}
		tok := trimmed
		if i := strings.IndexAny(tok, " \t#"); i >= 0 {
			tok = tok[:i]
		}
		if tok == ip || tok == ip+"/32" {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	// #nosec G304 -- same validated path guarantees as above.
	_ = os.WriteFile(cleanPath, []byte(strings.Join(kept, "\n")+"\n"), 0600)
	return removed
}

// feedsBlockingFast returns the feed keys whose per-feed HOSTS sets contain the given IP,
// without dumping any large set. It uses one terse table listing to discover set names,
// and constant-time "nft get element" (via Backend.HasElem) to test membership.
func feedsBlockingFast(be firewall.Backend, ip net.IP) []string {
	if be == nil || ip == nil {
		return nil
	}
	// Discover per-feed set names once (no elements printed).
	sets, err := listSetNamesByPrefixes(be,
		"allow_ext_v4_hosts_", "block_ext_v4_hosts_",
		"allow_ext_v6_hosts_", "block_ext_v6_hosts_",
	)
	if err != nil {
		return nil
	}
	ipStr := ip.String()
	seen := map[string]struct{}{}
	for _, s := range sets {
		ok, _ := be.HasElem(s, ipStr)
		if ok {
			if fk := feedKeyFromSet(s); fk != "" {
				seen[fk] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	// (optional) keep stable order
	sort.Strings(out)
	return out
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

// feedKeyFromSet extracts the feed key from a set name like "block_ext_v4_hosts_myblock".

func feedKeyFromSet(setName string) string {
	if i := strings.LastIndex(setName, "_"); i > 0 && i < len(setName)-1 {
		return setName[i+1:]
	}
	return ""
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
