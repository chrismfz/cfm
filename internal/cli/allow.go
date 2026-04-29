// internal/cli/allow.go
package cli

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"cfm/internal/firewall"
)

func RunAllow(args []string, be firewall.Backend, cfgDir string, tableExists func() bool) int {
	fs := flag.NewFlagSet("allow", flag.ExitOnError)
	ttlFlag := fs.String("ttl", "", "optional TTL (e.g. 90s, 5m, 1h)")
	flagArgs, posArgs := SplitFlagsAndPositionals(args, map[string]bool{"--ttl": true})
	_ = fs.Parse(flagArgs)

	target := ""
	if len(posArgs) > 0 {
		target = strings.TrimSpace(posArgs[0])
	}
	if target == "" {
		if rem := fs.Args(); len(rem) > 0 {
			target = strings.TrimSpace(rem[0])
		}
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "usage: cfm allow <IP|CIDR> [--ttl 1h]")
		return 2
	}

	var (
		ip      = net.ParseIP(target)
		isCIDR  bool
		cidrNet string
	)
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
		if err := be.AddAllowNet(cidrNet, dur); err != nil {
			fmt.Fprintln(os.Stderr, "allow error:", err)
			return 1
		}
	} else {
		if err := be.AddAllow(ip, dur); err != nil {
			fmt.Fprintln(os.Stderr, "allow error:", err)
			return 1
		}
	}

	// persist to cfm.allow only for permanent entries
	if cfgDir != "" && (dur == nil || *dur <= 0) {
		line := ip.String()
		if isCIDR {
			line = cidrNet
		}
		if err := AppendUniqueLine(cfgDir, "cfm.allow", line); err != nil {
			fmt.Fprintln(os.Stderr, "warn: could not update cfm.allow:", err)
		}
	}

	if isCIDR {
		fmt.Printf("✔ allowed %s\n", cidrNet)
	} else {
		fmt.Printf("✔ allowed %s\n", ip.String())
	}
	return 0
}

func RunUnallow(args []string, be firewall.Backend, cfgDir string, tableExists func() bool) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: cfm unallow <IP|CIDR>")
		return 2
	}
	raw := strings.TrimSpace(args[0])

	isCIDR, ipStr, cidrStr, err := NormalizeTarget(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid IP/CIDR")
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

	if isCIDR {
		if err := be.RemoveAllowNet(cidrStr); err != nil {
			fmt.Fprintln(os.Stderr, "unallow error:", err)
			return 1
		}
	} else {
		if err := be.RemoveAllow(net.ParseIP(ipStr)); err != nil {
			fmt.Fprintln(os.Stderr, "unallow error:", err)
			return 1
		}
	}

	if cfgDir != "" {
		if err := RemoveIPFromFile(cfgDir, "cfm.allow", raw); err != nil {
			fmt.Fprintln(os.Stderr, "warn: could not update cfm.allow:", err)
		}
	}

	if isCIDR {
		fmt.Printf("✔ unallowed %s\n", cidrStr)
	} else {
		fmt.Printf("✔ unallowed %s\n", ipStr)
	}
	return 0
}
