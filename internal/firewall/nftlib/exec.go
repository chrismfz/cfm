// nft CLI helpers for rule-building operations in the nftlib backend.
// These are used at startup and config reload only — not the hot path.
// Hot-path set operations use the netlink conn field instead.

package nftlib

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"cfm/internal/firewall"
)

const nftlibCLITimeout = 10 * time.Second

// nftExec runs `nft -f -` feeding expr via stdin (same mechanism as nft backend's nftExpr).
// Errors from "already exists" are silently swallowed — callers that need to fail-fast
// should inspect the returned error themselves.
func (b *Backend) nftExec(expr string) error {
	expr = strings.TrimSpace(expr)
	if !strings.HasSuffix(expr, ";") {
		expr += ";"
	}
	ctx, cancel := context.WithTimeout(context.Background(), nftlibCLITimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-") // #nosec G204
	cmd.Stdin = strings.NewReader(expr + "\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nftlib nftExec %q: %w: %s", expr, err, stderr.String())
	}
	return nil
}

// chainExistsCLI returns true if the named chain exists in inet cfm.
func (b *Backend) chainExistsCLI(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "list", "chain", "inet", cfmTableName, name) // #nosec G204
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	return cmd.Run() == nil
}

// ruleExistsCLI returns true if a rule containing needle is present in chain.
func (b *Backend) ruleExistsCLI(chain, needle string) bool {
	text, _ := b.chainTextCLI(chain) // unreadable: every rule reads as absent, as it always had
	return firewall.ParseChainRules(text).Has(needle)
}

// chainTextCLI is `nft -a list chain inet cfm <chain>` (with rule handles). It
// gets the CLI write timeout: on a node with large feed sets one nft process
// takes seconds.
func (b *Backend) chainTextCLI(chain string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nftlibCLITimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-a", "list", "chain", "inet", cfmTableName, chain) // #nosec G204
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("nft list chain inet %s %s: %w: %s", cfmTableName, chain, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// ensureCounterCLI creates the named counter if it doesn't already exist (idempotent).
func (b *Backend) ensureCounterCLI(name string) {
	_ = b.nftExec("add counter inet cfm " + name)
}

// ensurePortSetCLI creates an inet_service interval set for port ranges (idempotent).
func (b *Backend) ensurePortSetCLI(name string) error {
	return b.nftExec(fmt.Sprintf(
		"add set inet cfm %s { type inet_service; flags interval; }", name,
	))
}

// replacePortSetCLI flushes a port set and loads the given ranges.
func (b *Backend) replacePortSetCLI(name string, prs []portRange) error {
	if err := b.nftExec(fmt.Sprintf("flush set inet cfm %s", name)); err != nil {
		return err
	}
	if len(prs) == 0 {
		return nil
	}
	prs = normalizePortRanges(prs)
	elems := make([]string, 0, len(prs))
	for _, r := range prs {
		if r.From == r.To {
			elems = append(elems, fmt.Sprintf("%d", r.From))
		} else {
			elems = append(elems, fmt.Sprintf("%d-%d", r.From, r.To))
		}
	}
	return b.nftExec(fmt.Sprintf(
		"add element inet cfm %s { %s }", name, strings.Join(elems, ", "),
	))
}

// listChainOutputCLI returns the raw `nft list chain` output for chain, or "" on error.
func listChainOutputCLI(chain string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "list", "chain", "inet", cfmTableName, chain) // #nosec G204
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if cmd.Run() != nil {
		return ""
	}
	return stdout.String()
}

// delRuleCLI removes every rule in chain whose text contains needle.
func delRuleCLI(chain, needle string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-a", "list", "chain", "inet", cfmTableName, chain) // #nosec G204
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if cmd.Run() != nil {
		return
	}
	for _, line := range strings.Split(stdout.String(), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || !strings.Contains(s, needle) {
			continue
		}
		idx := strings.LastIndex(s, "# handle ")
		if idx < 0 {
			continue
		}
		h := strings.TrimSpace(s[idx+len("# handle "):])
		if sp := strings.Fields(h); len(sp) > 0 {
			h = sp[0]
		}
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		dcmd := exec.CommandContext(dctx, "nft", "delete", "rule", "inet", cfmTableName, chain, "handle", h) // #nosec G204
		_ = dcmd.Run()
		dcancel()
	}
}
