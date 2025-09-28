// internal/firewall/nft/smtpblock.go
package nft

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	cfgpkg "cfm/internal/config"
)

func (b *Backend) ApplySMTPBlock(cfg *cfgpkg.SMTPBlockConfig) error {
	if cfg == nil || !cfg.Enabled {
		// best effort cleanup if previously present
		_ = b.nftExpr(`delete chain inet cfm smtp_redir`)
		_ = b.nftExpr(`delete chain inet cfm smtpblock`)
		_ = b.nftExpr(`delete set inet cfm smtp_allow_gids`)
		_ = b.nftExpr(`delete set inet cfm smtp_allow_uids`)
		_ = b.nftExpr(`delete set inet cfm smtp_ports`)
		return nil
	}

	// Ensure base table exists (your EnsureBase should already do it)
	_ = b.nftExpr(`add table inet cfm`)

	// --- sets
	_ = b.nftExpr(`add set inet cfm smtp_ports { type inet_service; }`)
	_ = b.nftExpr(`flush set inet cfm smtp_ports`)
	var portElems []string
	if len(cfg.Ports) == 0 {
		portElems = []string{"25", "465", "587"}
	} else {
		for _, p := range cfg.Ports {
			portElems = append(portElems, strconv.Itoa(int(p)))
		}
	}
	_ = b.nftExpr(`add element inet cfm smtp_ports { ` + strings.Join(portElems, ", ") + ` }`)

	_ = b.nftExpr(`add set inet cfm smtp_allow_uids { type uid; flags interval; }`)
	_ = b.nftExpr(`flush set inet cfm smtp_allow_uids`)
	_ = b.nftExpr(`add set inet cfm smtp_allow_gids { type gid; flags interval; }`)
	_ = b.nftExpr(`flush set inet cfm smtp_allow_gids`)

	// Always allow root (0)
	uidSet := map[uint32]struct{}{0: {}}
	for _, u := range cfg.AllowUIDs { uidSet[u] = struct{}{} }
	// NOTE: name→id resolution is done outside (we only receive explicit IDs here).
	// If you want to accept names here too, add lookups similar to earlier examples.

	if len(uidSet) > 0 {
		uids := make([]int, 0, len(uidSet))
		for id := range uidSet { uids = append(uids, int(id)) }
		sort.Ints(uids)
		s := make([]string, len(uids))
		for i, v := range uids { s[i] = strconv.Itoa(v) }
		_ = b.nftExpr(`add element inet cfm smtp_allow_uids { ` + strings.Join(s, ", ") + ` }`)
	}

	if len(cfg.AllowGIDs) > 0 {
		gids := make([]int, 0, len(cfg.AllowGIDs))
		for _, id := range cfg.AllowGIDs { gids = append(gids, int(id)) }
		sort.Ints(gids)
		s := make([]string, len(gids))
		for i, v := range gids { s[i] = strconv.Itoa(v) }
		_ = b.nftExpr(`add element inet cfm smtp_allow_gids { ` + strings.Join(s, ", ") + ` }`)
	}

	// Counters
	_ = b.nftExpr(`add counter inet cfm smtpblock_hits`)
	_ = b.nftExpr(`add counter inet cfm smtpblock_denied`)

	// Build common allow rules (localhost + allowed owners)
	buildCommon := func(chain string, prefix string) {
		if cfg.AllowLocal {
			_ = b.nftExpr(fmt.Sprintf(`add rule inet cfm %s ip daddr 127.0.0.0/8  tcp dport @%ssmtp_ports accept`, chain, prefix))
			_ = b.nftExpr(fmt.Sprintf(`add rule inet cfm %s ip6 daddr ::1       tcp dport @%ssmtp_ports accept`, chain, prefix))
        // Accept connections to any of our own interface IPs (primary/add-on)
        _ = b.nftExpr(fmt.Sprintf(`add rule inet cfm %s ip  daddr @%sself_v4 tcp dport @%ssmtp_ports accept`, chain, prefix, prefix))
        _ = b.nftExpr(fmt.Sprintf(`add rule inet cfm %s ip6 daddr @%sself_v6 tcp dport @%ssmtp_ports accept`, chain, prefix, prefix))
		}
		_ = b.nftExpr(fmt.Sprintf(`add rule inet cfm %s meta skuid @%ssmtp_allow_uids tcp dport @%ssmtp_ports accept`, chain, prefix, prefix))
		_ = b.nftExpr(fmt.Sprintf(`add rule inet cfm %s meta skgid @%ssmtp_allow_gids tcp dport @%ssmtp_ports accept`, chain, prefix, prefix))
	}

	// Logging builder
	logRule := func(chain, prefix string) {
		if !cfg.LogEnabled { return }
		parts := []string{`log prefix "CFM SMTPBLOCK "`}
		if cfg.LogNFLOG > 0 {
			parts = []string{fmt.Sprintf(`log prefix "CFM SMTPBLOCK " group %d`, cfg.LogNFLOG)}
		}
		if cfg.LogLimit != "" && cfg.LogBurst > 0 {
			parts = append(parts, fmt.Sprintf(`limit rate %s burst %d packets`, cfg.LogLimit, cfg.LogBurst))
		} else if cfg.LogLimit != "" {
			parts = append(parts, fmt.Sprintf(`limit rate %s`, cfg.LogLimit))
		}
		 _ = b.nftExpr(fmt.Sprintf(`add rule inet cfm %s tcp dport @%ssmtp_ports counter name smtpblock_hits %s`, chain, prefix, strings.Join(parts, " ")))
	}

	// Mode: block (filter OUTPUT) or redirect (nat OUTPUT)
	if !cfg.Redirect {
		// Filter/output
		if !b.chainExists("smtpblock") {
			if err := b.nftCmd(`add chain inet cfm smtpblock { type filter hook output priority -100; policy accept; }`); err != nil {
				return err
			}
		}
		_ = b.nftExpr(`flush chain inet cfm smtpblock`)
		buildCommon("smtpblock", "")
		logRule("smtpblock", "")
		_ = b.nftExpr(`add rule inet cfm smtpblock tcp dport @smtp_ports counter name smtpblock_denied reject with tcp reset`)
	} else {
		// NAT/output redirect
		if !b.chainExists("smtp_redir") {
			if err := b.nftCmd(`add chain inet cfm smtp_redir { type nat hook output priority 0; policy accept; }`); err != nil {
				return err
			}
		}
		_ = b.nftExpr(`flush chain inet cfm smtp_redir`)
		// When redirecting from inet cfm, reference sets with @cfm: prefix if the table differs.
		buildCommon("smtp_redir", "cfm:")
		logRule("smtp_redir", "cfm:")
		_ = b.nftExpr(fmt.Sprintf(`add rule inet cfm smtp_redir tcp dport @cfm:smtp_ports counter name smtpblock_denied redirect to :%d`, cfg.RedirectPort))
	}

	return nil
}
