// internal/unblock/batch.go
package unblock

import (
	"bufio"
	"context"
	"fmt"
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
	"cfm/internal/locate"
)

// graceBatchMax is the largest batch whose every IP gets the imunify white
// grace entry (the customer-unblock case). Adding one is one
// imunify360-agent run per IP (about a second; the CLI takes one IP per add),
// so a mass unblock adds it only for the IPs imunify itself was blocking.
const graceBatchMax = 20

// toolArgsPerRun bounds the IPs passed to one fail2ban-client unban or
// imunify360-agent delete run.
const toolArgsPerRun = 50

// DoMany unblocks each of ips as Do does, but reads every source once for the
// whole batch and runs each tool only for the IPs it holds:
//   - the feed sets are listed once and each feed host set is read once;
//   - the block sets are written in one batch (RemoveBlockBatch);
//   - cfm.deny is rewritten once;
//   - csf, fail2ban and imunify360 are each checked for once;
//   - every IP is unbanned from fail2ban, many per fail2ban-client run (an
//     unban also clears the IP's ban history, which bantime.increment reads,
//     so it isn't limited to the IPs banned right now);
//   - imunify360's local list is read once and only IPs on its drop or
//     captcha list are deleted, many per run (when the list couldn't be read or
//     reached its cap, the IPs it didn't show are deleted blindly, as before);
//   - the feed-origin IPs are allowed in one batch that never shortens an
//     existing allow (AddAllowBatch).
//
// Do ran every step per IP: for a mass unblock of thousands of IPs that was
// hours of fail2ban-client and imunify360-agent processes. Results are keyed
// by the IP's string form; a nil IP is skipped and a repeated one unblocked
// once.
func DoMany(ctx context.Context, ips []net.IP, opts Options) map[string]*Result {
	out := map[string]*Result{}
	var list []net.IP
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if _, dup := out[ip.String()]; dup {
			continue
		}
		out[ip.String()] = &Result{IP: ip}
		list = append(list, ip)
	}
	if len(list) == 0 {
		return out
	}
	each := func(fn func(r *Result)) {
		for _, ip := range list {
			fn(out[ip.String()])
		}
	}

	// 0) Feeds: which feed host sets hold each IP.
	t0 := time.Now()
	for ip, feeds := range feedsBlockingMany(opts.BE, list) {
		r := out[ip]
		r.FromFeeds = feeds
		r.Steps = append(r.Steps, Step{Source: SrcFeeds, Action: ActionChecked, Feeds: feeds, Dur: time.Since(t0)})
	}

	// 1) nft remove. No EnsureBase: removing needs no base ruleset (without one
	// there is nothing to remove), and EnsureBase runs dozens of nft processes
	// — 10-70s on busy nodes.
	if opts.BE != nil {
		t1 := time.Now()
		// One IP, or a batch that failed (e.g. a block set missing, or the set
		// changing under every attempt): per IP, which tolerates an IP or a set
		// that isn't there.
		errs := map[string]error{}
		if len(list) == 1 || opts.BE.RemoveBlockBatch(list) != nil {
			for _, ip := range list {
				errs[ip.String()] = opts.BE.RemoveBlock(ip)
			}
		}
		each(func(r *Result) {
			if err := errs[r.IP.String()]; err != nil {
				r.Steps = append(r.Steps, Step{Source: SrcNFT, Action: ActionError, Detail: "RemoveBlock failed", Err: err.Error()})
				return
			}
			r.Steps = append(r.Steps, Step{Source: SrcNFT, Action: ActionRemoved, Dur: time.Since(t1)})
			r.WasBlocked = true
		})
	}

	// 1a) cfm.deny: one rewrite for the batch.
	if opts.ConfigDir != "" {
		t2 := time.Now()
		removed, err := removeFromFileMany(opts.ConfigDir, "cfm.deny", list)
		each(func(r *Result) {
			if err != nil {
				r.Steps = append(r.Steps, Step{Source: SrcCFMDeny, Action: ActionError, Detail: "cfm.deny left as is", Err: err.Error(), Dur: time.Since(t2)})
			} else if removed[r.IP.String()] {
				r.Steps = append(r.Steps, Step{Source: SrcCFMDeny, Action: ActionRemoved, Dur: time.Since(t2)})
				r.WasBlocked = true
			} else {
				r.Steps = append(r.Steps, Step{Source: SrcCFMDeny, Action: ActionNotFound, Dur: time.Since(t2)})
			}
		})
	}

	// 2) csf, fail2ban, imunify360 — each checked for once, run in parallel.
	// Their steps go through addStep: the goroutines append to the same
	// results.
	var wg sync.WaitGroup
	if binaryExists("csf") && unitActive("csf") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// csf takes one address per command.
			for _, ip := range list {
				r := out[ip.String()]
				runCmd(ctx, r, SrcCSF, "csf", "-tr", ip.String())
				runCmd(ctx, r, SrcCSF, "csf", "-dr", ip.String())
				runCmd(ctx, r, SrcCSF, "csf", "-ta", ip.String())
			}
		}()
	} else {
		each(func(r *Result) {
			addStep(r, Step{Source: SrcCSF, Action: ActionChecked, Detail: "not present or inactive"})
		})
	}

	if binaryExists("fail2ban-client") && unitActive("fail2ban") {
		wg.Add(1)
		go func() { defer wg.Done(); fail2banUnbanMany(ctx, list, out) }()
	} else {
		each(func(r *Result) {
			addStep(r, Step{Source: SrcFail2Ban, Action: ActionChecked, Detail: "not present or inactive"})
		})
	}

	// The binary first: without it there is nothing to ask systemd about.
	if binaryExists("imunify360-agent") && (unitActive("imunify360") || unitActive("imunify360-agent") ||
		unitActive("imunify360.service") || unitActive("imunify360-agent.service")) {
		wg.Add(1)
		go func() { defer wg.Done(); imunifyUnblockMany(ctx, list, out, opts) }()
	} else {
		each(func(r *Result) {
			addStep(r, Step{Source: SrcImunify, Action: ActionChecked, Detail: "not present or inactive"})
		})
	}

	wg.Wait()

	// 4) Feed-origin IPs: a local allow overrides the feed until it drops them
	// (optional). One batch, and it never shortens an allow already there —
	// AddAllow replaced it, so a permanent allow became a timed one.
	if opts.BE != nil && opts.TempWhitelist {
		var entries []firewall.BlockEntry
		var fromFeeds []*Result
		each(func(r *Result) {
			if len(r.FromFeeds) == 0 {
				return
			}
			e := firewall.BlockEntry{IP: r.IP, Permanent: true}
			if opts.AllowTTL != nil && *opts.AllowTTL > 0 {
				e = firewall.BlockEntry{IP: r.IP, TTL: *opts.AllowTTL}
			}
			entries = append(entries, e)
			fromFeeds = append(fromFeeds, r)
		})
		if len(entries) > 0 {
			_, err := opts.BE.AddAllowBatch(entries)
			for _, r := range fromFeeds {
				if err != nil {
					r.Steps = append(r.Steps, Step{Source: SrcFeeds, Action: ActionError, Detail: "AddAllow failed", Err: err.Error(), Feeds: r.FromFeeds})
					continue
				}
				r.Steps = append(r.Steps, Step{Source: SrcFeeds, Action: ActionWhitelisted, Feeds: r.FromFeeds})
				r.Whitelisted = true
			}
		}
	}

	// 4a) WAF planes (OpenResty/Lua): webdetector challenge/block + per-IP
	// shared-dict caches (throttle, decision cache, geo, ok-touch, waf-push).
	// These live entirely outside the firewall/blocklist, so a "force unblock"
	// that ignores them can leave a user stuck behind a challenge/throttle even
	// though every blocklist search comes back empty. Best-effort by design;
	// the edge purges one IP per request.
	if opts.WAF != nil {
		each(func(r *Result) {
			tw := time.Now()
			wr := opts.WAF.ForceUnblock(r.IP.String())
			r.WAF = &wr
			step := Step{Source: SrcWAF, Dur: time.Since(tw)}
			switch {
			case wr.Err != "":
				step.Action = ActionError
				step.Err = wr.Err
				step.Detail = wr.Summary()
			case len(wr.Cleared) > 0:
				step.Action = ActionRemoved
				step.Detail = wr.Summary()
			default:
				step.Action = ActionNotFound
			}
			r.Steps = append(r.Steps, step)
		})
	}

	// 5) Optional API report (ενοποιημένα — π.χ. να στείλουμε reason = "feeds: a,b" ή "manual")
	if opts.SendAPI && opts.Reporter != nil && opts.ReportWhy != "agent" {
		each(func(r *Result) {
			why := "manual"
			if len(r.FromFeeds) > 0 {
				why = "feeds:" + strings.Join(r.FromFeeds, ",")
			}
			_ = opts.Reporter.ReportUnblock(r.IP.String(), opts.ReportWhy, why)
		})
	}
	return out
}

// feedsBlockingMany returns, per IP, the feed keys whose per-feed HOST sets
// hold it. One terse table listing discovers the sets; one IP is probed with
// HasElem per set (constant time), more read each set once.
func feedsBlockingMany(be firewall.Backend, ips []net.IP) map[string][]string {
	out := map[string][]string{}
	if be == nil || len(ips) == 0 {
		return out
	}
	sets, err := listSetNamesByPrefixes(be,
		"allow_ext_v4_hosts_", "block_ext_v4_hosts_",
		"allow_ext_v6_hosts_", "block_ext_v6_hosts_",
	)
	if err != nil {
		return out
	}
	want := map[string]bool{}
	for _, ip := range ips {
		want[ip.String()] = true
	}
	seen := map[string]map[string]bool{} // ip → feed keys
	hit := func(ip, set string) {
		fk := feedKeyFromSet(set)
		if fk == "" {
			return
		}
		if seen[ip] == nil {
			seen[ip] = map[string]bool{}
		}
		seen[ip][fk] = true
	}
	for _, s := range sets {
		if len(ips) == 1 {
			if ok, _ := be.HasElem(s, ips[0].String()); ok {
				hit(ips[0].String(), s)
			}
			continue
		}
		elems, err := be.ListSetElementsRaw(s)
		if err != nil {
			continue
		}
		for _, e := range elems {
			if ip := net.ParseIP(strings.TrimSpace(e)); ip != nil && want[ip.String()] {
				hit(ip.String(), s)
			}
		}
	}
	for ip, fks := range seen {
		for fk := range fks {
			out[ip] = append(out[ip], fk)
		}
		sort.Strings(out[ip])
	}
	return out
}

// removeFromFileMany drops the lines of cfgDir/filename that list one of ips
// (as the address or address/32), in one read and at most one write, and
// returns the IPs it removed. The path must stay inside cfgDir and the file
// be an allowlisted one. A missing file is nothing to remove; a file it can't
// read to the end is left as is, with an error.
func removeFromFileMany(cfgDir, filename string, ips []net.IP) (map[string]bool, error) {
	removed := map[string]bool{}
	if cfgDir == "" || !allowedConfigFile(filename) {
		return removed, nil
	}
	baseCfg := filepath.Clean(cfgDir)
	cleanPath := filepath.Clean(filepath.Join(cfgDir, filename))
	if cleanPath != baseCfg && !strings.HasPrefix(cleanPath, baseCfg+string(os.PathSeparator)) {
		return removed, nil
	}
	want := map[string]string{} // token as written → the IP's key
	for _, ip := range ips {
		want[ip.String()] = ip.String()
		want[ip.String()+"/32"] = ip.String()
	}
	// #nosec G304 -- path is constrained to cfgDir + allowlisted filename and verified to remain within cfgDir.
	f, err := os.Open(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return removed, nil
		}
		return nil, err
	}
	var kept []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		tok := strings.TrimSpace(line)
		if i := strings.IndexAny(tok, " \t#"); i >= 0 {
			tok = tok[:i]
		}
		if key, ok := want[tok]; ok && tok != "" {
			removed[key] = true
			continue
		}
		kept = append(kept, line)
	}
	scanErr := sc.Err()
	f.Close()
	if scanErr != nil {
		// Writing back what was read would drop everything after that line.
		return nil, fmt.Errorf("read %s: %w", filename, scanErr)
	}
	if len(removed) == 0 {
		return removed, nil
	}
	// #nosec G304 -- same validated path guarantees as above.
	if err := os.WriteFile(cleanPath, []byte(strings.Join(kept, "\n")+"\n"), 0600); err != nil {
		return nil, err
	}
	return removed, nil
}

// fail2banArgsPerRun bounds the IPs of one fail2ban-client unban run.
const fail2banArgsPerRun = 200

// fail2banUnbanMany unbans every IP, fail2banArgsPerRun per fail2ban-client
// run (fail2ban ≥ 0.10 takes several). Not only the IPs banned right now: an
// unban also deletes the IP's ban history, which bantime.increment reads, as
// the per-IP unban always did.
func fail2banUnbanMany(ctx context.Context, list []net.IP, out map[string]*Result) {
	runForChunks(ctx, list, fail2banArgsPerRun, out, SrcFail2Ban, "fail2ban-client", "unban")
}

// imunifyUnblockMany clears the IPs from imunify360's drop and captcha lists
// and adds the white grace entry: the local list is read once, the listed IPs
// are deleted toolArgsPerRun per run, and the grace entry goes to every IP of
// a small batch (as Do always did) but, in a batch larger than
// graceBatchMax, only to the IPs imunify itself was blocking.
//
// imunify lists an IPv6 address only as its /64, so an IPv6 IP is cleared by
// deleting the /64 entry that holds it.
func imunifyUnblockMany(ctx context.Context, list []net.IP, out map[string]*Result, opts Options) {
	entries, capped, err := locate.ImunifyLocalList(ctx)
	// listed[purpose][key] = the entry as imunify lists it (key: imunifyKey).
	listed := map[string]map[string]string{"drop": {}, "captcha": {}}
	for _, e := range entries {
		if k := imunifyEntryKey(e.Entry); k != "" && listed[e.Purpose] != nil {
			listed[e.Purpose][k] = e.Entry
		}
	}
	isListed := func(ip net.IP) bool {
		k := imunifyKey(ip)
		return listed["drop"][k] != "" || listed["captcha"][k] != ""
	}
	// Without the list, or past its cap, an IP it didn't show may still be
	// listed: delete it blindly, as Do always did.
	blind := err != nil || capped
	for _, ip := range list {
		switch {
		case err != nil:
			addStep(out[ip.String()], Step{Source: SrcImunify, Action: ActionChecked, Detail: "local list unreadable (" + err.Error() + "); deleting blindly"})
		case capped && !isListed(ip):
			addStep(out[ip.String()], Step{Source: SrcImunify, Action: ActionChecked, Detail: fmt.Sprintf("not in the first %d entries of the local list; deleting blindly", len(entries))})
		case !blind && !isListed(ip):
			addStep(out[ip.String()], Step{Source: SrcImunify, Action: ActionNotFound, Detail: "not in the local drop/captcha list"})
		}
	}
	for _, purpose := range []string{"drop", "captcha"} {
		// One address family per run.
		for _, v4 := range []bool{true, false} {
			var ips []net.IP
			var args []string
			for _, ip := range list {
				if (ip.To4() != nil) != v4 {
					continue
				}
				k := imunifyKey(ip)
				switch {
				case listed[purpose][k] != "":
					args = append(args, listed[purpose][k])
				case blind && !isListed(ip):
					args = append(args, k)
				default:
					continue
				}
				ips = append(ips, ip)
			}
			runArgsForChunks(ctx, ips, args, toolArgsPerRun, out, SrcImunify, "imunify360-agent", "ip-list", "local", "delete", "--purpose", purpose)
		}
	}

	// White grace entry: always when ImunifyWhiteTTL is set (manual-unblock
	// grace window), otherwise only for feeds-origin blocks.
	whiteTTL := opts.AllowTTL
	if opts.ImunifyWhiteTTL != nil && *opts.ImunifyWhiteTTL > 0 {
		whiteTTL = opts.ImunifyWhiteTTL
	}
	for _, ip := range list {
		k := ip.String()
		r := out[k]
		if len(r.FromFeeds) == 0 && (opts.ImunifyWhiteTTL == nil || *opts.ImunifyWhiteTTL <= 0) {
			continue
		}
		if len(list) > graceBatchMax && !isListed(ip) {
			addStep(r, Step{Source: SrcImunify, Action: ActionChecked,
				Detail: fmt.Sprintf("no white grace entry: batch of %d IPs (grace goes to every IP of up to %d, else only to IPs imunify listed)", len(list), graceBatchMax)})
			continue
		}
		// imunify takes an IPv6 address only as its /64.
		whiteArgs := []string{"ip-list", "local", "add", "--purpose", "white", "--comment", "CFM auto-unblock", imunifyKey(ip)}
		// imunify defaults to a PERMANENT entry; bound it
		// (--expiration wants an absolute unix timestamp).
		if whiteTTL != nil && *whiteTTL > 0 {
			whiteArgs = append(whiteArgs, "--expiration", strconv.FormatInt(time.Now().Add(*whiteTTL).Unix(), 10))
		}
		runCmd(ctx, r, SrcImunify, "imunify360-agent", whiteArgs...)
	}
}

// imunifyKey is what imunify lists ip as: the address, or for IPv6 its /64.
func imunifyKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	m := net.CIDRMask(64, 128)
	return (&net.IPNet{IP: ip.Mask(m), Mask: m}).String()
}

// imunifyEntryKey is the imunifyKey a local-list entry clears: an IPv4
// address, or an IPv6 /64 (an IPv6 address counts as its /64). Other networks
// give "": deleting one would unblock more than the IP.
func imunifyEntryKey(entry string) string {
	if !strings.Contains(entry, "/") {
		if ip := net.ParseIP(entry); ip != nil {
			return imunifyKey(ip)
		}
		return ""
	}
	_, n, err := net.ParseCIDR(entry)
	if err != nil {
		return ""
	}
	switch ones, bits := n.Mask.Size(); {
	case bits == 32 && ones == 32:
		return n.IP.String()
	case bits == 128 && ones == 64:
		return n.String()
	}
	return ""
}

// runForChunks runs name args… ip… for targets, per IPs per run, and
// records each run on the IPs it named.
func runForChunks(ctx context.Context, targets []net.IP, per int, out map[string]*Result, src Source, name string, args ...string) {
	var ipArgs []string
	for _, ip := range targets {
		ipArgs = append(ipArgs, ip.String())
	}
	runArgsForChunks(ctx, targets, ipArgs, per, out, src, name, args...)
}

// runArgsForChunks is runForChunks with each IP's argument given (ipArgs,
// parallel to targets).
func runArgsForChunks(ctx context.Context, targets []net.IP, ipArgs []string, per int, out map[string]*Result, src Source, name string, args ...string) {
	for i := 0; i < len(targets); i += per {
		j := min(i+per, len(targets))
		argv := append(append([]string(nil), args...), ipArgs[i:j]...)
		step := runTool(ctx, src, name, argv...)
		for _, ip := range targets[i:j] {
			addStep(out[ip.String()], step)
		}
	}
}

// runTool runs an allowlisted tool and describes the run as a step.
func runTool(ctx context.Context, src Source, name string, args ...string) Step {
	if !allowedBinary(name) {
		return Step{Source: src, Action: ActionError, Err: "blocked binary", Detail: "binary not in allowlist"}
	}
	start := time.Now()
	// #nosec G204 -- `name/args` are constrained by an internal allowlist + fixed callsites.
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	step := Step{Source: src, Action: ActionChecked, Dur: time.Since(start), Detail: strings.TrimSpace(string(out))}
	if err != nil {
		step.Action = ActionError
		step.Err = err.Error()
	}
	return step
}

func addStep(r *Result, s Step) {
	r.mu.Lock()
	r.Steps = append(r.Steps, s)
	r.mu.Unlock()
}
