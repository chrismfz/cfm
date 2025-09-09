package agent

import (
    "bufio"
    "context"
    "net"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "sync"
//    "time"

    "cfm/internal/firewall"
    "cfm/internal/logging"
)

func runCmd(ctx context.Context, name string, args ...string) {
    cmd := exec.CommandContext(ctx, name, args...)
    out, err := cmd.CombinedOutput()
    if err != nil {
        logging.Logf("[unblock] %s %v FAILED: %v (out: %s)", name, args, err, string(out))
        return
    }
    if len(out) > 0 {
        logging.Logf("[unblock] %s %v OK: %s", name, args, string(out))
    } else {
        logging.Logf("[unblock] %s %v OK", name, args)
    }
}

func binaryExists(name string) bool {
    _, err := exec.LookPath(name)
    return err == nil
}

// removeFromFile removes the ip from cfgDir/cfm.deny (if present). Best-effort.
func removeFromFile(cfgDir, filename, ip string) {
    if cfgDir == "" { return }
    path := filepath.Join(cfgDir, filename)
    f, err := os.Open(path)
    if err != nil { return }
    defer f.Close()

    var kept []string
    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := scanner.Text()
        // κρατάμε γραμμές που ΔΕΝ αρχίζουν με το IP (αγνοούμε σχόλια μετά)
        trimmed := strings.TrimSpace(line)
        if trimmed == "" || strings.HasPrefix(trimmed, "#") {
            kept = append(kept, line)
            continue
        }
        // κόψε στο πρώτο whitespace/#
        tok := trimmed
        if i := strings.IndexAny(tok, " \t#"); i >= 0 {
            tok = tok[:i]
        }
        if tok != ip {
            kept = append(kept, line)
        }
    }
    _ = os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0644)
}

// ProcessUnblockRequest: local nft unblock -> CSF/Imunify cleanup -> API confirm
// cfgDir: αν δοθεί, αφαιρεί και από cfm.deny (best-effort).
func (c *APIClient) ProcessUnblockRequest(ctx context.Context, be firewall.Backend, cfgDir string, id int, ipStr string) {
    // 0) Validate IP
    ip := net.ParseIP(ipStr)
    if ip == nil {
        logging.Logf("[unblock] invalid IP in request id=%d ip=%q", id, ipStr)
        _ = c.ConfirmUnblock(id, ipStr, true) // still confirm so it won’t loop forever
        return
    }

    // 1) Local nft unblock first
    if be != nil {
        if err := be.EnsureBase(); err != nil {
            logging.Logf("[unblock] EnsureBase failed for %s: %v", ipStr, err)
        }
        if err := be.RemoveBlock(ip); err != nil {
            logging.Logf("[unblock] nft RemoveBlock failed for %s: %v", ipStr, err)
        } else {
            logging.Logf("[unblock] nft RemoveBlock OK for %s", ipStr)
        }
    }

    // 1a) Optional: remove from cfm.deny (best-effort)
    if cfgDir != "" {
        removeFromFile(cfgDir, "cfm.deny", ipStr)
    }

    // 2) CSF cleanup (parallel like C++)
    if binaryExists("csf") {
        logging.Logf("[unblock] CSF detected. Cleaning bans for %s ...", ipStr)
        var wg sync.WaitGroup
        wg.Add(3)
        go func() { defer wg.Done(); runCmd(ctx, "csf", "-tr", ipStr) }()
        go func() { defer wg.Done(); runCmd(ctx, "csf", "-dr", ipStr) }()
        go func() { defer wg.Done(); runCmd(ctx, "csf", "-ta", ipStr) }()
        wg.Wait()
    } else {
        logging.Logf("[unblock] CSF not detected.")
    }

    // 3) Imunify360 cleanup
    if binaryExists("imunify360-agent") {
        logging.Logf("[unblock] Imunify360 detected. Cleaning lists for %s ...", ipStr)
        runCmd(ctx, "imunify360-agent", "ip-list", "local", "delete", "--purpose", "drop", ipStr)
        runCmd(ctx, "imunify360-agent", "ip-list", "local", "delete", "--purpose", "captcha", ipStr)
        runCmd(ctx, "imunify360-agent", "ip-list", "local", "add", "--purpose", "white", "--comment", "Auto-unblocked", ipStr)
    } else {
        logging.Logf("[unblock] Imunify360 not detected.")
    }

    // 4) Confirm back to API (always success=true, to avoid stuck queue)

    logging.Logf("[unblock] Confirming unblock to API id=%d ip=%s ...", id, ipStr)
    if err := c.ConfirmUnblock(id, ipStr, true); err != nil {
        logging.Logf("[api] unblock-confirm FAILED id=%d ip=%s: %v", id, ipStr, err)
        return
    }
    logging.Logf("[api] unblock-confirm OK id=%d ip=%s", id, ipStr)
}
