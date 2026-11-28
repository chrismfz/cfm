// nft CLI helpers for rule-building operations in the nftlib backend.
// These are used at startup and config reload only — not the hot path.
// Hot-path set operations use the netlink conn field instead.

package nftlib

import (
	"bytes"
	"context"
	"errors"
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
	return b.nftExecTimeout(expr, nftlibCLITimeout)
}

// nftExecTimeout is nftExec with its own deadline, for a script that can be
// long (EnsureBase's base rules with thousands of duplicate deletes).
func (b *Backend) nftExecTimeout(expr string, timeout time.Duration) error {
	expr = strings.TrimSpace(expr)
	if !strings.HasSuffix(expr, ";") {
		expr += ";"
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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

// chainTextCLI is `nft -a list chain inet cfm <chain>` (with rule handles).
func (b *Backend) chainTextCLI(chain string) (string, error) {
	return nftReadCLI("-a", "list", "chain", "inet", cfmTableName, chain)
}

// inputChainTextCLI is chainTextCLI for EnsureBase's read of the input chain,
// with the exec engine's deadline (firewall.BaseInputReadTimeout): at the CLI
// default (10 s) an EL8 node's 4–12 s listing timed out, and the base rules,
// duplicates included, were left as they were.
func (b *Backend) inputChainTextCLI() (string, error) {
	return nftReadCLITimeout(firewall.BaseInputReadTimeout, "-a", "list", "chain", "inet", cfmTableName, "input")
}

// inputAcceptsChainTextCLI is the DNAT accepts' read of the input chain
// (inputAcceptOps, cleanupScopedDNATAccepts), with firewall.
// InputAcceptsNFTTimeout: the 5 s of ListChainText, a diagnostic listing,
// ran past EL8's 4–12 s `list chain`.
func (b *Backend) inputAcceptsChainTextCLI() (string, error) {
	return nftReadCLITimeout(firewall.InputAcceptsNFTTimeout, "-a", "list", "chain", "inet", cfmTableName, "input")
}

// nftReadCLI runs a read-only nft command (firewall.NFTRead). It gets the CLI
// write timeout: on a node with large feed sets one nft process takes seconds.
// An error carries nft's stderr.
func nftReadCLI(args ...string) (string, error) {
	return nftReadCLITimeout(nftlibCLITimeout, args...)
}

// nftReadCLITimeout is nftReadCLI with its own deadline.
func nftReadCLITimeout(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", args...) // #nosec G204 -- fixed binary, args built by CFM
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			// A timeout is not a missing chain (EnsureInputAccepts).
			return "", fmt.Errorf("nft %s: %w: %w: %s", strings.Join(args, " "), context.DeadlineExceeded, err, strings.TrimSpace(stderr.String()))
		}
		return "", fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// ensureCounterCLI creates the named counter if it doesn't already exist (idempotent).
func (b *Backend) ensureCounterCLI(name string) {
	_ = b.nftExec("add counter inet cfm " + name)
}
