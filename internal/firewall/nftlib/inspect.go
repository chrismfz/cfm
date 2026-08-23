//go:build linux

package nftlib

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"time"

	"cfm/internal/firewall"
)

// HostRulesetJSON gives diagnostics a complete cross-owner view. Runtime
// enforcement remains zero-fork; this is an explicit on-demand CLI read.
func (b *Backend) HostRulesetJSON() ([]byte, error) {
	const maxRulesetJSON = 8 << 20
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-j", "-t", "list", "ruleset")
	stdout := diagnosticLimitedBuffer{max: maxRulesetJSON}
	stderr := diagnosticTailBuffer{max: 64 << 10}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nft -j -t list ruleset: %w: %s", err, stderr.String())
	}
	if stdout.truncated {
		return nil, fmt.Errorf("nft ruleset JSON exceeds %d bytes", maxRulesetJSON)
	}
	return stdout.Bytes(), nil
}

type diagnosticLimitedBuffer struct {
	bytes.Buffer
	max       int
	truncated bool
}

type diagnosticTailBuffer struct {
	buf []byte
	max int
}

func (b *diagnosticTailBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) >= b.max {
		b.buf = append(b.buf[:0], p[len(p)-b.max:]...)
		return n, nil
	}
	overflow := len(b.buf) + len(p) - b.max
	if overflow > 0 {
		copy(b.buf, b.buf[overflow:])
		b.buf = b.buf[:len(b.buf)-overflow]
	}
	b.buf = append(b.buf, p...)
	return n, nil
}

func (b *diagnosticTailBuffer) String() string { return string(b.buf) }

func (b *diagnosticLimitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.max - b.Len()
	if remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		_, _ = b.Buffer.Write(p[:remaining])
	}
	if remaining < len(p) {
		b.truncated = true
	}
	return n, nil
}

// ListBlocks returns all entries in the block_v4 and block_v6 sets.
// Uses conn.GetSetElements — no subprocess, no fork.
func (b *Backend) ListBlocks() ([]firewall.BlockedEntry, error) {
	return b.listHostSetPair(setBlockV4, setBlockV6)
}

// ListAllows returns all entries in the allow_v4 and allow_v6 sets.
func (b *Backend) ListAllows() ([]firewall.BlockedEntry, error) {
	return b.listHostSetPair(setAllowV4, setAllowV6)
}

func (b *Backend) listHostSetPair(v4Name, v6Name string) ([]firewall.BlockedEntry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	var result []firewall.BlockedEntry
	for _, name := range []string{v4Name, v6Name} {
		set, err := b.lookupSet(name)
		if err != nil {
			continue // set may not exist yet
		}
		elems, err := b.conn.GetSetElements(set)
		if err != nil {
			continue
		}
		for _, e := range elems {
			if e.IntervalEnd {
				continue
			}
			ip := keyToIP(e.Key)
			if ip == nil {
				continue
			}
			entry := firewall.BlockedEntry{IP: ip}
			// e.Expires is the remaining lifetime (time.Duration); convert to
			// absolute time so callers can display it as a wall-clock timestamp.
			if e.Expires > 0 {
				exp := now.Add(e.Expires)
				entry.Expires = &exp
			}
			result = append(result, entry)
		}
	}
	return result, nil
}

// HasElem returns true if elem is currently in the named set.
// Fetches elements via netlink and scans for a match — no fork.
// Used by interactive commands, not hot paths.
func (b *Backend) HasElem(setName, elem string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	set, err := b.lookupSet(setName)
	if err != nil {
		return false, fmt.Errorf("nftlib HasElem %s: %w", setName, err)
	}
	elems, err := b.conn.GetSetElements(set)
	if err != nil {
		return false, fmt.Errorf("nftlib HasElem %s: %w", setName, err)
	}

	// Normalise the query to canonical form so "::1" and "0:0:…:1" both match.
	var targetStr string
	if ip := net.ParseIP(elem); ip != nil {
		targetStr = ip.String()
	} else {
		targetStr = elem
	}

	for _, e := range elems {
		if e.IntervalEnd {
			continue
		}
		ip := keyToIP(e.Key)
		if ip != nil && ip.String() == targetStr {
			return true, nil
		}
	}
	return false, nil
}

// ListSetElementsRaw returns all elements of a named set as strings.
// For host sets: IP strings. For interval/CIDR sets: CIDR notation strings.
func (b *Backend) ListSetElementsRaw(setName string) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	set, err := b.lookupSet(setName)
	if err != nil {
		return nil, fmt.Errorf("nftlib ListSetElementsRaw %s: %w", setName, err)
	}
	elems, err := b.conn.GetSetElements(set)
	if err != nil {
		return nil, fmt.Errorf("nftlib ListSetElementsRaw %s: %w", setName, err)
	}
	return elemsToStrings(elems), nil
}

// ListSetElementsTimed returns set elements paired with their remaining TTL.
// Expires is zero on elements without a timeout.
func (b *Backend) ListSetElementsTimed(setName string) ([]firewall.SetElementTimed, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	set, err := b.lookupSet(setName)
	if err != nil {
		return nil, fmt.Errorf("nftlib ListSetElementsTimed %s: %w", setName, err)
	}
	elems, err := b.conn.GetSetElements(set)
	if err != nil {
		return nil, fmt.Errorf("nftlib ListSetElementsTimed %s: %w", setName, err)
	}
	return elemsToTimed(elems), nil
}

// ── Table/set dump methods (text formatting via nft subprocess) ──────────────

func (b *Backend) ListTableJSON(family, table string) ([]byte, error) {
	if strings.TrimSpace(family) != "inet" || strings.TrimSpace(table) != cfmTableName {
		return nil, fmt.Errorf("nftlib: unsupported table path %s %s", family, table)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	tbl, err := b.lookupTable()
	if err != nil {
		return nil, fmt.Errorf("nftlib ListTableJSON %s %s: %w", family, table, err)
	}
	sets, err := b.conn.GetSets(tbl)
	if err != nil {
		return nil, fmt.Errorf("nftlib ListTableJSON %s %s: %w", family, table, err)
	}
	names := make([]string, 0, len(sets))
	for _, s := range sets {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return json.MarshalIndent(map[string]any{
		"family": "inet",
		"table":  cfmTableName,
		"sets":   names,
	}, "", "  ")
}

func (b *Backend) ListSetJSON(family, table, set string) ([]byte, error) {
	if strings.TrimSpace(family) != "inet" || strings.TrimSpace(table) != cfmTableName {
		return nil, fmt.Errorf("nftlib: unsupported set path %s %s %s", family, table, set)
	}
	elems, err := b.ListSetElementsRaw(set)
	if err != nil {
		return nil, err
	}
	sort.Strings(elems)
	return json.MarshalIndent(map[string]any{
		"family":   "inet",
		"table":    cfmTableName,
		"set":      set,
		"elements": elems,
	}, "", "  ")
}

func (b *Backend) ListTableTextNoDNS(family, table string) (string, error) {
	return nftTextOutput(context.Background(), "-t", "-n", "list", "table", family, table)
}

func (b *Backend) ListChainText(family, table, chain string) (string, error) {
	return nftTextOutput(context.Background(), "-a", "list", "chain", family, table, chain)
}

// nftTextOutput runs the nft binary with the given args and returns combined output.
// Used only for diagnostic / human-readable inspection paths (not the data plane).
func nftTextOutput(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", args...) // #nosec G204
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String() + stderr.String(), nil
}
