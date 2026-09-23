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
//   - fail2ban's ban list is read once and only banned IPs are unbanned, many
//     per fail2ban-client run;
//   - imunify360's local list is read once and only IPs on its drop or
//     captcha list are deleted, many per run (when the list reached its cap,
//     the IPs it didn't show are deleted blindly, as before);
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
		var err error
		if len(list) == 1 {
			err = opts.BE.RemoveBlock(list[0])
		} else {
			err = opts.BE.RemoveBlockBatch(list)
		}
		each(func(r *Result) {
			if err != nil {
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
		removed := removeFromFileMany(opts.ConfigDir, "cfm.deny", list)
		each(func(r *Result) {
			if removed[r.IP.String()] {
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
// returns the IPs it removed. Same path constraints as removeFromFile.
func removeFromFileMany(cfgDir, filename string, ips []net.IP) map[string]bool {
	removed := map[string]bool{}
	if cfgDir == "" || !allowedConfigFile(filename) {
		return removed
	}
	baseCfg := filepath.Clean(cfgDir)
	cleanPath := filepath.Clean(filepath.Join(cfgDir, filename))
	if cleanPath != baseCfg && !strings.HasPrefix(cleanPath, baseCfg+string(os.PathSeparator)) {
		return removed
	}
	want := map[string]string{} // token as written → the IP's key
	for _, ip := range ips {
		want[ip.String()] = ip.String()
		want[ip.String()+"/32"] = ip.String()
	}
	// #nosec G304 -- path is constrained to cfgDir + allowlisted filename and verified to remain within cfgDir.
	f, err := os.Open(cleanPath)
	if err != nil {
		return removed
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
	if len(removed) == 0 || scanErr != nil {
		// Nothing to drop, or a line the scanner couldn't read: don't write back
		// a file that would lose everything after it.
		if scanErr != nil {
			return map[string]bool{}
		}
		return removed
	}
	// #nosec G304 -- same validated path guarantees as above.
	if err := os.WriteFile(cleanPath, []byte(strings.Join(kept, "\n")+"\n"), 0600); err != nil {
		return map[string]bool{}
	}
	return removed
}

// fail2banUnbanMany unbans the IPs fail2ban holds: its ban list is read once
// and only banned IPs are unbanned, toolArgsPerRun per fail2ban-client run.
// Without the ban list (fail2ban < 0.11) every IP is unbanned, as before.
func fail2banUnbanMany(ctx context.Context, list []net.IP, out map[string]*Result) {
	targets := list
	if banned, ok := locate.Fail2BanBanned(ctx); ok {
		targets = nil
		for _, ip := range list {
			if banned[ip.String()] {
				targets = append(targets, ip)
				continue
			}
			addStep(out[ip.String()], Step{Source: SrcFail2Ban, Action: ActionNotFound, Detail: "not banned"})
		}
	}
	runForChunks(ctx, targets, out, SrcFail2Ban, "fail2ban-client", "unban")
}

// imunifyUnblockMany clears the IPs from imunify360's drop and captcha lists
// and adds the white grace entry: the local list is read once, the listed IPs
// are deleted toolArgsPerRun per run, and the grace entry goes to every IP of
// a small batch (as Do always did) but, in a batch larger than
// graceBatchMax, only to the IPs imunify itself was blocking.
func imunifyUnblockMany(ctx context.Context, list []net.IP, out map[string]*Result, opts Options) {
	entries, capped, err := locate.ImunifyLocalList(ctx)
	listed := map[string]map[string]bool{"drop": {}, "captcha": {}}
	if err == nil {
		for _, e := range entries {
			if ip := imunifyHostEntry(e); ip != "" && listed[e.Purpose] != nil {
				listed[e.Purpose][ip] = true
			}
		}
	}
	// Without the list, or past its cap, an IP it didn't show may still be
	// listed: delete it blindly, as Do always did.
	blind := err != nil || capped
	for _, purpose := range []string{"drop", "captcha"} {
		var targets []net.IP
		for _, ip := range list {
			if listed[purpose][ip.String()] || (blind && !listed["drop"][ip.String()] && !listed["captcha"][ip.String()]) {
				targets = append(targets, ip)
			}
		}
		runForChunks(ctx, targets, out, SrcImunify, "imunify360-agent", "ip-list", "local", "delete", "--purpose", purpose)
	}
	for _, ip := range list {
		k := ip.String()
		if !blind && !listed["drop"][k] && !listed["captcha"][k] {
			addStep(out[k], Step{Source: SrcImunify, Action: ActionNotFound, Detail: "not in the local drop/captcha list"})
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
		if len(list) > graceBatchMax && !listed["drop"][k] && !listed["captcha"][k] {
			continue // a mass unblock: only the IPs imunify was blocking
		}
		whiteArgs := []string{"ip-list", "local", "add", "--purpose", "white", "--comment", "CFM auto-unblock", k}
		// imunify defaults to a PERMANENT entry; bound it
		// (--expiration wants an absolute unix timestamp).
		if whiteTTL != nil && *whiteTTL > 0 {
			whiteArgs = append(whiteArgs, "--expiration", strconv.FormatInt(time.Now().Add(*whiteTTL).Unix(), 10))
		}
		runCmd(ctx, r, SrcImunify, "imunify360-agent", whiteArgs...)
	}
	if len(list) > graceBatchMax {
		for _, ip := range list {
			k := ip.String()
			if !listed["drop"][k] && !listed["captcha"][k] {
				addStep(out[k], Step{Source: SrcImunify, Action: ActionChecked,
					Detail: fmt.Sprintf("no white grace entry: batch of %d IPs (grace goes to every IP of up to %d, else only to IPs imunify listed)", len(list), graceBatchMax)})
			}
		}
	}
}

// imunifyHostEntry is the address of an entry that lists exactly one
// address, or "".
func imunifyHostEntry(e locate.ImunifyEntry) string {
	s := strings.TrimSpace(e.IP)
	bits := -1
	if i := strings.IndexByte(s, '/'); i >= 0 {
		n, err := strconv.Atoi(s[i+1:])
		if err != nil {
			return ""
		}
		s, bits = s[:i], n
	} else if e.Netmask > 0 {
		bits = e.Netmask
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	full := 128
	if ip.To4() != nil {
		full = 32
	}
	if bits >= 0 && bits != full {
		return ""
	}
	return ip.String()
}

// runForChunks runs name args… ip… for targets, toolArgsPerRun IPs per run,
// and records the run on each IP it named.
func runForChunks(ctx context.Context, targets []net.IP, out map[string]*Result, src Source, name string, args ...string) {
	for i := 0; i < len(targets); i += toolArgsPerRun {
		chunk := targets[i:min(i+toolArgsPerRun, len(targets))]
		argv := append([]string(nil), args...)
		for _, ip := range chunk {
			argv = append(argv, ip.String())
		}
		step := runTool(ctx, src, name, argv...)
		for _, ip := range chunk {
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
