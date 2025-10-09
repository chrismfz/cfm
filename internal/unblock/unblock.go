// internal/unblock/unblock.go
package unblock

import (
"sort"
    "bufio"
    "context"
    "errors"
    "net"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "sync"
    "time"
"bytes"
"fmt"

"cfm/internal/firewall"
"cfm/internal/reporting"
"cfm/internal/firewall/nft"


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
    SrcNFT       Source = "nft"
    SrcCFMDeny   Source = "cfm.deny"
    SrcCSF       Source = "csf"
    SrcImunify   Source = "imunify360"
    SrcFeeds     Source = "feeds"
    SrcFail2Ban Source = "fail2ban"
)

type Step struct {
    Source  Source
    Action  StepAction
    Detail  string
    Feeds   []string
    Err     string
    Dur     time.Duration // how long this step took
}

type Result struct {
    IP           net.IP
    Steps        []Step
    FromFeeds    []string // feeds που “πιάνουν” την IP
    WasBlocked   bool     // εντοπίστηκε σε nft/cfm.deny/κλπ.
    Whitelisted  bool     // μπήκε allow override
}

type Options struct {
    BE          firewall.Backend       // nft backend
    ConfigDir   string                 // για cfm.deny
    TempWhitelist bool                 // αν είναι από feeds -> κάνε allow override
    AllowTTL    *time.Duration         // TTL whitelist (nil = permanent)
    Reporter    reporting.Reporter     // optional: για ReportUnblock/Block
    ReportWhy   string                 // π.χ. "cli" ή "agent"
    SendAPI     bool                   // αν θέλουμε να γίνει report/unblock
    Fail2BanUnban bool
}

// ----------------------------------------------

func Do(ctx context.Context, ip net.IP, opts Options) (Result, error) {
    if ip == nil {
        return Result{}, errors.New("nil IP")
    }
    r := Result{IP: ip}

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
        if !nft.TableExistsCFM() {
            // last-resort bootstrap, but extremely rare in practice
            if err := opts.BE.EnsureBase(); err != nil {
                r.Steps = append(r.Steps, Step{Source: SrcNFT, Action: ActionError, Detail: "EnsureBase failed", Err: err.Error()})
            }
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
            runCmd(ctx, &r, SrcCSF, "csf", "-tr", ip.String())
            runCmd(ctx, &r, SrcCSF, "csf", "-dr", ip.String())
            runCmd(ctx, &r, SrcCSF, "csf", "-ta", ip.String())
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
        runCmd(ctx, &r, SrcFail2Ban, "fail2ban-client", "unban", ip.String())
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
            runCmd(ctx, &r, SrcImunify, "imunify360-agent", "ip-list", "local", "delete", "--purpose", "drop", ip.String())
            runCmd(ctx, &r, SrcImunify, "imunify360-agent", "ip-list", "local", "delete", "--purpose", "captcha", ip.String())
            // Προαιρετικά: να μπει white όταν προέρχεται από feeds
            if len(r.FromFeeds) > 0 {
                runCmd(ctx, &r, SrcImunify, "imunify360-agent", "ip-list", "local", "add", "--purpose", "white", "--comment", "CFM auto-unblock", ip.String())
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
    start := time.Now()
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
    r.Steps = append(r.Steps, step)
}




func removeFromFile(cfgDir, filename, ip string) bool {
    if cfgDir == "" { return false }
    path := filepath.Join(cfgDir, filename)
    f, err := os.Open(path)
    if err != nil { return false }
    defer f.Close()

    var kept []string
    removed := false
    sc := bufio.NewScanner(f)
    for sc.Scan() {
        line := sc.Text()
        trimmed := strings.TrimSpace(line)
        if trimmed == "" || strings.HasPrefix(trimmed, "#") {
            kept = append(kept, line); continue
        }
        tok := trimmed
        if i := strings.IndexAny(tok, " \t#"); i >= 0 { tok = tok[:i] }
        if tok == ip || tok == ip+"/32" {
            removed = true
            continue
        }
        kept = append(kept, line)
    }
    _ = os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0644)
    return removed
}


// feedsBlockingFast returns the feed keys whose per-feed HOSTS sets contain the given IP,
// without dumping any large set. It uses one terse table listing to discover set names,
// and constant-time "nft get element" (via Backend.HasElem) to test membership.
func feedsBlockingFast(be firewall.Backend, ip net.IP) []string {
    if be == nil || ip == nil {
        return nil
    }
    nb, ok := be.(*nft.Backend)
    if !ok {
        // only supported for nft backend; silently fall back to none
        return nil
    }
    // Discover per-feed set names once (no elements printed).
    sets, err := listSetNamesByPrefixes(
        "allow_ext_v4_hosts_", "block_ext_v4_hosts_",
        "allow_ext_v6_hosts_", "block_ext_v6_hosts_",
    )
    if err != nil {
        return nil
    }
    ipStr := ip.String()
    seen := map[string]struct{}{}
    for _, s := range sets {
        ok, _ := nb.HasElem(s, ipStr)
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
func listSetNamesByPrefixes(prefixes ...string) ([]string, error) {
    out, err := exec.Command("nft", "-t", "-n", "list", "table", "inet", "cfm").CombinedOutput()
    if err != nil {
        return nil, fmt.Errorf("nft list table: %v: %s", err, string(out))
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
    sc := bufio.NewScanner(bytes.NewReader(out))
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
    return exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil
}


