package nft

import (
	"fmt"
	"math"
	"os/exec"
	"strconv"
	"strings"

	cfgpkg "cfm/internal/config"
)

// ApplyFloodRules flushes the flood chain and re-applies all rules from config.
func (b *Backend) ApplyFloodRules(f cfgpkg.FloodConfig) error {
	// make idempotent
	_ = b.nftExpr("flush chain inet cfm flood;")

	if err := b.ApplyConnlimit(f.Connlimit); err != nil {
		return err
	}
	if err := b.ApplyPortFlood(f.PortFlood); err != nil {
		return err
	}
	return nil
}

// ApplyConnlimit: concurrent connection limits per IP (per port).
func (b *Backend) ApplyConnlimit(rules []cfgpkg.ConnlimitRule) error {
	for _, r := range rules {
		// ensure named counter per-port/proto
		cname := fmt.Sprintf("connlimit_%d_%s", r.Port, r.Proto)
		b.ensureCounter(cname)

		// flood chain is evaluated before ports accept/drop via 'jump flood'
		expr := fmt.Sprintf(
			"add rule inet cfm flood %s dport %d ct count over %d "+
				"counter name %s drop comment \"connlimit %d;%d\";",
			r.Proto, r.Port, r.Limit,
			cname, r.Limit, r.Port,
		)
		if err := b.nftExpr(expr); err != nil {
			return fmt.Errorf("connlimit rule failed: %w", err)
		}
	}
	return nil
}

// mapRate converts (max per intervalSeconds) into nft syntax <num>/<unit> with unit in {second,minute,hour,day}.
func mapRate(max, intervalSeconds int) (int, string) {
	if intervalSeconds <= 0 {
		intervalSeconds = 60 // sane default to avoid div-by-zero
	}
	type unit struct {
		name string
		sec  int
	}
	candidates := []unit{
		{"day", 86400},
		{"hour", 3600},
		{"minute", 60},
		{"second", 1},
	}
	for _, u := range candidates {
		if intervalSeconds%u.sec == 0 {
			factor := intervalSeconds / u.sec
			num := int(math.Ceil(float64(max) / float64(factor)))
			if num < 1 {
				num = 1
			}
			return num, u.name
		}
	}
	return max, "second"
}

// ApplyPortFlood: per-port new-connection rate limiting.
func (b *Backend) ApplyPortFlood(rules []cfgpkg.PortFloodRule) error {
	for _, r := range rules {
		// ensure named counter per-port/proto
		cname := fmt.Sprintf("portflood_%d_%s", r.Port, r.Proto)
		b.ensureCounter(cname)

		// convert (Max, Interval seconds) -> <num>/<unit> and add burst = Max
		num, unit := mapRate(r.Max, r.Interval)

		expr := fmt.Sprintf(
			"add rule inet cfm flood %s dport %d ct state new "+
				"limit rate %d/%s burst %d packets counter name %s "+
				"drop comment \"portflood %d;%s;%d;%d\";",
			r.Proto, r.Port, num, unit, r.Max, cname,
			r.Port, r.Proto, r.Interval, r.Max,
		)
		if err := b.nftExpr(expr); err != nil {
			return fmt.Errorf("portflood rule failed: %w", err)
		}
	}
	return nil
}

// DumpFloodCounters prints only counters with packets>0 for our flood rules.
func (b *Backend) DumpFloodCounters() {
	out, err := b.runCmdOutput("list counters")
	if err != nil {
		fmt.Println("[flood] cannot list counters:", err)
		return
	}

	lines := strings.Split(out, "\n")
	for _, ln := range lines {
		s := strings.TrimSpace(ln)
		if s == "" {
			continue
		}
		if !(strings.Contains(s, "connlimit_") || strings.Contains(s, "portflood_")) {
			continue
		}
		if strings.Contains(s, "packets") {
			fields := strings.Fields(s)
			for i := 0; i < len(fields)-1; i++ {
				if fields[i] == "packets" {
					if pkts, err := strconv.Atoi(fields[i+1]); err == nil && pkts > 0 {
						fmt.Println("[flood]", s)
					}
				}
			}
		}
	}
}

// ensureCounter creates the named counter if it doesn't already exist (idempotent).
func (b *Backend) ensureCounter(name string) {
	// ignore "already exists"
	_ = b.nftExpr(fmt.Sprintf("add counter inet cfm %s;", name))
}

// ---- helpers (compat) ----

// runCmd executes a single nft command preserving quotes via `sh -lc`.
func (b *Backend) runCmd(cmd string) error {
	out, err := exec.Command("sh", "-lc", "nft "+cmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft failed: %v (out=%s)", err, out)
	}
	return nil
}

// runCmdOutput executes an nft command and returns its combined output.
func (b *Backend) runCmdOutput(cmd string) (string, error) {
	out, err := exec.Command("sh", "-lc", "nft "+cmd).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("nft failed: %v (out=%s)", err, out)
	}
	return string(out), nil
}
