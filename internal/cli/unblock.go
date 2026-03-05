// internal/cli/unblock.go
package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	agentpkg "cfm/internal/agent"
	"cfm/internal/firewall"
	"cfm/internal/firewall/nft"
	ipquery "cfm/internal/ipquery"
	"cfm/internal/reporting"
	"cfm/internal/unblock"
)

func RunUnblock(args []string, be firewall.Backend, cfgDir string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: cfm unblock <IP>")
		return 2
	}
	ip := net.ParseIP(args[0])
	if ip == nil {
		fmt.Fprintln(os.Stderr, "invalid IP")
		return 2
	}

	if be == nil {
		fmt.Fprintln(os.Stderr, "no firewall backend available")
		return 1
	}
	if !nft.TableExistsCFM() {
		if err := be.EnsureBase(); err != nil {
			fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
			return 1
		}
	}

	var reporter reporting.Reporter
	var sendAPI bool
	if cfgDir != "" {
		cfgPath := filepath.Clean(filepath.Join(cfgDir, "cfm.conf"))
		if b, err := os.ReadFile(cfgPath); err == nil { // #nosec G304
			if cfg, err := LoadConfigWithAPIOverride(cfgDir, b); err == nil &&
				cfg.API.UnblockSend &&
				cfg.API.URL != "" &&
				cfg.API.AuthToken != "" {
				reporter = &agentpkg.APIClient{BaseURL: cfg.API.URL, Token: cfg.API.AuthToken}
				sendAPI = true
			}
		}
	}

	ttl := 1 * time.Hour
	res, err := unblock.Do(context.Background(), ip, unblock.Options{
		BE:            be,
		ConfigDir:     cfgDir,
		TempWhitelist: true,
		AllowTTL:      &ttl,
		Reporter:      reporter,
		ReportWhy:     "cli",
		SendAPI:       sendAPI,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "unblock error:", err)
		return 1
	}

	suffix := ipquery.EnrichSuffix(cfgDir, ip.String())
	fmt.Printf("Unblock report for %s%s\n", ip, suffix)
	for _, s := range res.Steps {
		feeds := ""
		if len(s.Feeds) > 0 {
			feeds = " [feeds: " + strings.Join(s.Feeds, ",") + "]"
		}
		extra := s.Detail
		if s.Err != "" {
			extra = "ERR: " + s.Err + " " + extra
		}
		dur := ""
		if s.Dur > 0 {
			dur = fmt.Sprintf(" (%.2fs)", s.Dur.Seconds())
		}
		fmt.Printf(" - %-9s via %-10s %s%s%s\n",
			s.Action, s.Source, strings.TrimSpace(extra), feeds, dur)
	}
	if res.Whitelisted {
		fmt.Println("✔ applied local whitelist override (due to feeds)")
	}
	return 0
}
