// internal/unblock/unblock.go
package unblock

import (
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

    "cfm/internal/firewall"
    ipquery "cfm/internal/ipquery"
//    "cfm/internal/logging"
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

    // 0) Feeds detection (χρησιμοποιεί το νέο helper)
    feeds, _ := ipquery.FeedsBlocking(ip.String()) // []string feedIDs/names
    if len(feeds) > 0 {
        r.FromFeeds = feeds
        r.Steps = append(r.Steps, Step{Source: SrcFeeds, Action: ActionChecked, Feeds: feeds})
    }

    // 1) nft remove
    if opts.BE != nil {
        if err := opts.BE.EnsureBase(); err != nil {
            r.Steps = append(r.Steps, Step{Source: SrcNFT, Action: ActionError, Detail: "EnsureBase failed", Err: err.Error()})
        } else {
            if err := opts.BE.RemoveBlock(ip); err != nil {
                r.Steps = append(r.Steps, Step{Source: SrcNFT, Action: ActionError, Detail: "RemoveBlock failed", Err: err.Error()})
            } else {
                r.Steps = append(r.Steps, Step{Source: SrcNFT, Action: ActionRemoved})
                r.WasBlocked = true
            }
        }
    }

    // 1a) cfm.deny cleanup
    if opts.ConfigDir != "" {
        if removed := removeFromFile(opts.ConfigDir, "cfm.deny", ip.String()); removed {
            r.Steps = append(r.Steps, Step{Source: SrcCFMDeny, Action: ActionRemoved})
            r.WasBlocked = true
        } else {
            r.Steps = append(r.Steps, Step{Source: SrcCFMDeny, Action: ActionNotFound})
        }
    }

    // 2) CSF (παράλληλα με άλλες εντολές)
    var wg sync.WaitGroup
    if binaryExists("csf") {
        wg.Add(1)
        go func() {
            defer wg.Done()
            // -tr, -dr, -ta
            runCmd(ctx, &r, SrcCSF, "csf", "-tr", ip.String())
            runCmd(ctx, &r, SrcCSF, "csf", "-dr", ip.String())
            runCmd(ctx, &r, SrcCSF, "csf", "-ta", ip.String())
        }()
    } else {
        r.Steps = append(r.Steps, Step{Source: SrcCSF, Action: ActionChecked, Detail: "not present"})
    }


// 2.5) Fail2Ban (προαιρετικό): unban μόνο αν ενεργοποιηθεί μέσω opts
if opts.Fail2BanUnban {
    if binaryExists("fail2ban-client") {
        wg.Add(1)
        go func() {
            defer wg.Done()
            runCmd(ctx, &r, SrcFail2Ban, "fail2ban-client", "unban", ip.String())
        }()
    } else {
        r.Steps = append(r.Steps, Step{Source: SrcFail2Ban, Action: ActionChecked, Detail: "fail2ban-client not present"})
    }
} else {
    // Αν δεν είναι ενεργό, μπορείς είτε να μη γράψεις τίποτα είτε να αφήσεις ένα “disabled”
    r.Steps = append(r.Steps, Step{Source: SrcFail2Ban, Action: ActionChecked, Detail: "disabled"})
}





    // 3) Imunify360
    if binaryExists("imunify360-agent") {
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
        r.Steps = append(r.Steps, Step{Source: SrcImunify, Action: ActionChecked, Detail: "not present"})
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
    if opts.SendAPI && opts.Reporter != nil {
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
    cmd := exec.CommandContext(ctx, name, args...)
    out, err := cmd.CombinedOutput()
    step := Step{Source: src, Action: ActionChecked}
    if err != nil {
        step.Action = ActionError
        step.Err = err.Error()
        step.Detail = string(out)
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
