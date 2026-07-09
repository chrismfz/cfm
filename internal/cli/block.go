// internal/cli/block.go
package cli

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	agentpkg "cfm/internal/agent"
	cfgpkg "cfm/internal/config"
	"cfm/internal/firewall"
)

// LoadConfigWithAPIOverride parses cfm.conf then overlays cfm.api.conf when
// present. Only per-server secret fields are overwritten: the cfm-web API
// (URL / AuthToken / *_SEND_TO_API flags) and the MaxMind account credentials
// (MAXMIND_ACCOUNT_ID / MAXMIND_LICENSE_KEY). This lets the base cfm.conf ship
// secret-free and identical on every host, with only cfm.api.conf edited per
// server. Moved here from main.go so CLI commands that need API reporting can
// share it without touching main.
func LoadConfigWithAPIOverride(cfgDir string, baseBytes []byte) (*cfgpkg.Config, error) {
	cfg, err := cfgpkg.ParseCFMConf(bytes.NewReader(baseBytes))
	if err != nil {
		return nil, err
	}
	if cfgDir == "" {
		return cfg, nil
	}

	apiPath := filepath.Clean(filepath.Join(cfgDir, "cfm.api.conf"))
	info, err := os.Stat(apiPath)
	if err != nil {
		return cfg, nil
	}
	if info.Mode().Perm()&0o077 != 0 {
		if chErr := os.Chmod(apiPath, 0o600); chErr != nil {
			fmt.Fprintf(os.Stderr, "warning: could not chmod 600 %s: %v\n", apiPath, chErr)
		}
	}

	b, err := os.ReadFile(apiPath) // #nosec G304
	if err != nil || len(b) == 0 {
		return cfg, nil
	}

	if api, err := cfgpkg.ParseCFMConf(bytes.NewReader(b)); err == nil {
		if s := strings.TrimSpace(api.API.URL); s != "" {
			cfg.API.URL = s
		}
		if s := strings.TrimSpace(api.API.AuthToken); s != "" {
			cfg.API.AuthToken = s
		}
		if api.API.AutoBlockSend {
			cfg.API.AutoBlockSend = true
		}
		if api.API.ManualBlockSend {
			cfg.API.ManualBlockSend = true
		}
		if api.API.UnblockSend {
			cfg.API.UnblockSend = true
		}
		if api.API.DetectorsSend {
			cfg.API.DetectorsSend = true
		}

		// MaxMind account credentials may also live in the overlay so the base
		// cfm.conf stays secret-free. Only overwrite when the overlay sets them,
		// so an overlay that carries only API keys leaves the base MaxMind config
		// untouched.
		if s := strings.TrimSpace(api.MaxMind.AccountID); s != "" {
			cfg.MaxMind.AccountID = s
		}
		if s := strings.TrimSpace(api.MaxMind.LicenseKey); s != "" {
			cfg.MaxMind.LicenseKey = s
		}
	}
	return cfg, nil
}

func RunBlock(args []string, be firewall.Backend, cfgDir string, tableExists func() bool) int {
	fs := flag.NewFlagSet("block", flag.ExitOnError)
	reasonFlag := fs.String("r", "", "reason/comment")
	ttlFlag := fs.String("ttl", "", "optional TTL (e.g. 90s, 5m, 1h)")
	flagArgs, posArgs := SplitFlagsAndPositionals(args, map[string]bool{"--ttl": true, "-r": true})
	_ = fs.Parse(flagArgs)

	if len(posArgs) == 0 && len(fs.Args()) > 0 {
		posArgs = append(posArgs, fs.Args()...)
	}
	if len(posArgs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: cfm block <IP|CIDR> [-r REASON] [--ttl 1h]")
		return 2
	}

	target := strings.TrimSpace(posArgs[0])
	ip := net.ParseIP(target)
	var isCIDR bool
	var cidrNet string
	if ip == nil {
		if strings.ContainsRune(target, '/') {
			if _, nw, err := net.ParseCIDR(target); err == nil {
				nw.IP = nw.IP.Mask(nw.Mask)
				cidrNet = nw.String()
				isCIDR = true
			} else {
				fmt.Fprintln(os.Stderr, "invalid CIDR")
				return 2
			}
		} else {
			fmt.Fprintln(os.Stderr, "invalid IP")
			return 2
		}
	}

	rsn := strings.TrimSpace(*reasonFlag)
	if rsn == "" && len(posArgs) > 1 {
		rsn = strings.TrimSpace(strings.Join(posArgs[1:], " "))
	}
	if rsn == "" {
		rsn = "manual block"
	}

	var dur *time.Duration
	if *ttlFlag != "" {
		if d, err := time.ParseDuration(*ttlFlag); err == nil && d > 0 {
			dur = &d
		} else {
			fmt.Fprintln(os.Stderr, "invalid --ttl (examples: 90s, 5m, 1h)")
			return 2
		}
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

	if isCIDR {
		if err := be.AddBlockNet(cidrNet, dur); err != nil {
			fmt.Fprintln(os.Stderr, "block error:", err)
			return 1
		}
	} else {
		if err := be.AddBlock(ip, rsn, dur); err != nil {
			fmt.Fprintln(os.Stderr, "block error:", err)
			return 1
		}
	}

	// persist to cfm.deny only for permanent entries
	if cfgDir != "" && (dur == nil || *dur <= 0) {
		line := ip.String()
		if isCIDR {
			line = cidrNet
		}
		if rsn != "" {
			line += "  # " + rsn
		}
		if err := AppendUniqueLine(cfgDir, "cfm.deny", line); err != nil {
			fmt.Fprintln(os.Stderr, "warn: could not update cfm.deny:", err)
		}
	}

	// API report
	if cfgDir != "" {
		cfgPath := filepath.Clean(filepath.Join(cfgDir, "cfm.conf"))
		if b, err := os.ReadFile(cfgPath); err == nil { // #nosec G304
			if cfg, err := LoadConfigWithAPIOverride(cfgDir, b); err == nil && cfg.API.ManualBlockSend {
				if cfg.API.URL != "" && cfg.API.AuthToken != "" {
					api := &agentpkg.APIClient{BaseURL: cfg.API.URL, Token: cfg.API.AuthToken}
					mode, ttlSec := "permanent", 0
					if dur != nil && *dur > 0 {
						mode, ttlSec = "ttl", int(dur.Seconds())
					}
					if !isCIDR {
						if err := api.ReportBlock(ip.String(), rsn, "manual-cli", mode, ttlSec); err != nil {
							fmt.Printf("✔ blocked %s (API report failed: %v)\n", target, err)
							return 0
						}
						fmt.Printf("✔ blocked %s (also sent to API)\n", target)
						return 0
					}
					fmt.Printf("✔ blocked %s (API report skipped for CIDR)\n", cidrNet)
					return 0
				}
			}
		}
	}

	if isCIDR {
		fmt.Printf("✔ blocked %s\n", cidrNet)
	} else {
		fmt.Printf("✔ blocked %s\n", ip.String())
	}
	return 0
}
