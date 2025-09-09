package agent

import (
    "context"
    "net"
    "strings"
    "time"

    "cfm/internal/firewall"
    "cfm/internal/logging"
    "cfm/internal/unblock"
)


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


    // 1) Unified unblock (nft + cfm.deny + csf + imunify + feeds whitelist)
    if be == nil {
        logging.Logf("[unblock] no backend available for %s", ipStr)
        _ = c.ConfirmUnblock(id, ipStr, true)
        return
    }
    if err := be.EnsureBase(); err != nil {
        logging.Logf("[unblock] EnsureBase failed for %s: %v", ipStr, err)
    }
    ttl := 1 * time.Hour // TODO: ρυθμιζόμενο από config αν θέλεις
    res, err := unblock.Do(ctx, ip, unblock.Options{
        BE:             be,
        ConfigDir:      cfgDir,
        TempWhitelist:  true,       // whitelist override αν είναι από feeds
        AllowTTL:       &ttl,
        Reporter:       c,          // θα στείλει reason "feeds:..." ή "manual"
        ReportWhy:      "agent",
        SendAPI:        true,
        Fail2BanUnban:  true,      // baby-step: OFF στον agent για να αποφύγουμε loops
    })
    if err != nil {
        logging.Logf("[unblock] unified unblock failed for %s: %v", ipStr, err)
    }
    // Log steps για ορατότητα
    for _, s := range res.Steps {
        if s.Err != "" {
            logging.Logf("[unblock] %-9s via %-10s ERR=%s %s", s.Action, s.Source, s.Err, strings.TrimSpace(s.Detail))
        } else {
            logging.Logf("[unblock] %-9s via %-10s %s", s.Action, s.Source, strings.TrimSpace(s.Detail))
        }
    }


    // 2) Confirm back to API (always success=true, to avoid stuck queue)
    logging.Logf("[unblock] Confirming unblock to API id=%d ip=%s ...", id, ipStr)
    if err := c.ConfirmUnblock(id, ipStr, true); err != nil {
        logging.Logf("[api] unblock-confirm FAILED id=%d ip=%s: %v", id, ipStr, err)
        return
    }
    logging.Logf("[api] unblock-confirm OK id=%d ip=%s", id, ipStr)
}
