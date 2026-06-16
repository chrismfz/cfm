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
	ipquery "cfm/internal/ipquery"
	"cfm/internal/locate"
	"cfm/internal/reporting"
	"cfm/internal/unblock"
)

func RunUnblock(args []string, be firewall.Backend, cfgDir string, tableExists func() bool) int {
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
	if tableExists == nil || !tableExists() {
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

	// Where-&-why search before anything is removed.
	var foundOn []locate.Location
	if lres, lerr := locate.FindWithTimeout(ip.String(), locate.Options{BE: be, ConfigDir: cfgDir}, 15*time.Second); lerr == nil {
		foundOn = lres.Locations
	}

	ttl := 1 * time.Hour
	whiteTTL := 1 * time.Hour // imunify grace window
	res, err := unblock.Do(context.Background(), ip, unblock.Options{
		BE:              be,
		ConfigDir:       cfgDir,
		TempWhitelist:   true,
		AllowTTL:        &ttl,
		Reporter:        reporter,
		ReportWhy:       "cli",
		SendAPI:         sendAPI,
		ImunifyWhiteTTL: &whiteTTL,
		WAF:             unblock.WAFCleanerHook(), // clear OpenResty/Lua WAF planes via the local daemon
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "unblock error:", err)
		return 1
	}

	suffix := ipquery.EnrichSuffix(cfgDir, ip.String())
	fmt.Printf("Unblock report for %s%s\n", ip, suffix)
	for _, l := range foundOn {
		reason := ""
		if l.Reason != "" {
			reason = " — " + l.Reason
		}
		fmt.Printf(" * was %s via %s %s [%s]%s\n", l.Action, l.Source, l.List, l.Match, reason)
	}
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
	if res.WAF != nil {
		switch {
		case res.WAF.Err != "" && len(res.WAF.Cleared) == 0:
			fmt.Printf(" - %-9s via %-10s WAF clear error: %s\n", "error", unblock.SrcWAF, res.WAF.Err)
		case res.WAF.Found:
			fmt.Printf(" - %-9s via %-10s %s\n", "removed", unblock.SrcWAF, res.WAF.Summary())
		}
	}
	if res.Whitelisted {
		fmt.Println("✔ applied local whitelist override (due to feeds)")
	}
	return 0
}
