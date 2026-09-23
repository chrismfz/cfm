//go:build linux

package nft

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"cfm/internal/firewall"
)

// blockBatchStmtElems bounds the elements in one create/delete statement of
// the batch script. Every statement is in the same `nft -f -` run, so the
// whole batch stays one transaction.
const blockBatchStmtElems = 1000

// blockBatchAttempts bounds the read-plan-write rounds of one AddBlockBatch.
const blockBatchAttempts = 3

// AddBlockBatch blocks many host addresses in one `nft -f -` transaction,
// after one `nft -j list set` per address family: three nft processes per
// attempt at most, whatever the batch size, where AddBlock forks two per
// address (four when it hits an existing element). It only adds or extends,
// never shortens
// (firewall.PlanBlockBatch).
//
// Between the read and the write another writer (an autoblock, another API
// request, the CLI) can change the set, and this backend has no lock across
// processes:
//   - An element due for replacement can expire or be removed: its delete
//     fails and nft aborts the whole transaction.
//   - One of the new addresses can be added. A plain `add element` would then
//     rewrite that block's timeout on current kernels — a permanent block
//     would become the batch's TTL — so every add is a `create element`
//     (exclusive), which aborts the transaction instead.
//
// An aborted write is retried from a fresh read, which plans around the
// change, up to blockBatchAttempts times. It never falls back to one nft
// process per address. A writer that keeps landing the same addresses in
// every window (e.g. an autoblocker banning the IPs an operator is
// bulk-blocking) can exhaust the attempts; the call then fails cleanly, having
// never shortened a block, and the caller can simply retry.
func (b *Backend) AddBlockBatch(entries []firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	v4, v6, skipped := firewall.SplitBlockEntries(entries)
	res := firewall.BlockBatchResult{Skipped: skipped}
	if len(v4)+len(v6) == 0 {
		return res, nil
	}
	var lastErr error
	for attempt := 0; attempt < blockBatchAttempts; attempt++ {
		script, planned, err := b.blockBatchScript(v4, v6)
		if err != nil {
			return res, err
		}
		if script == "" {
			return res.Add(planned), nil
		}
		r, err := runNFTCommandInput(context.Background(), script, "-f", "-")
		if err == nil {
			return res.Add(planned), nil
		}
		lastErr = &nftBatchError{msg: nftFirstError(r.Stdout+r.Stderr, err), err: err}
	}
	return res, fmt.Errorf("nft block batch (%d v4, %d v6), %d attempts: %w", len(v4), len(v6), blockBatchAttempts, lastErr)
}

// nftBatchError carries nft's own error line as its message and the command
// error (exit status, timeout) as its cause.
type nftBatchError struct {
	msg string
	err error
}

func (e *nftBatchError) Error() string { return e.msg }
func (e *nftBatchError) Unwrap() error { return e.err }

// nftFirstError is nft's "Error: …" line, naming the element it points at, or
// the command error when nft printed none. nft reports a script error as
//
//	/dev/stdin:1:57-64: Error: Could not process rule: File exists
//	create element inet cfm block_v4 { 10.0.0.1 timeout 1h, 10.0.0.7 timeout 1h }
//	                                                        ^^^^^^^^
//
// — the input location, the whole failing statement (for a batch, up to a
// thousand addresses) and a caret line. The columns of the location pick the
// offending element out of the statement.
func nftFirstError(out string, err error) string {
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		j := strings.Index(line, "Error:")
		if j < 0 {
			continue
		}
		msg := strings.TrimSpace(line[j:])
		if i+1 < len(lines) {
			if at := nftErrorSpan(line[:j], lines[i+1]); at != "" {
				msg += " (at " + at + ")"
			}
		}
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		return msg
	}
	return err.Error()
}

// nftErrorSpan returns the text of stmt that the location prefix
// "<file>:<line>:<first>-<last>: " points at (1-based, inclusive columns), or
// "" if the prefix doesn't parse or the columns fall outside stmt.
func nftErrorSpan(prefix, stmt string) string {
	parts := strings.Split(strings.TrimSpace(prefix), ":")
	if len(parts) < 3 {
		return ""
	}
	first, last, ok := strings.Cut(parts[len(parts)-2], "-")
	if !ok {
		return ""
	}
	c1, err1 := strconv.Atoi(first)
	c2, err2 := strconv.Atoi(last)
	if err1 != nil || err2 != nil || c1 < 1 || c2 < c1 || c2 > len(stmt) {
		return ""
	}
	return strings.TrimSpace(stmt[c1-1 : c2])
}

// blockBatchScript reads the block sets and renders the one-transaction
// script that brings them to the plan. An empty script means nothing to write.
func (b *Backend) blockBatchScript(v4, v6 []firewall.BlockEntry) (string, firewall.BlockBatchResult, error) {
	var sb strings.Builder
	var res firewall.BlockBatchResult
	for _, fam := range []struct {
		set  string
		want []firewall.BlockEntry
	}{{setV4, v4}, {setV6, v6}} {
		if len(fam.want) == 0 {
			continue
		}
		current, err := b.ListSetElementsTimed(fam.set)
		if err != nil {
			return "", res, fmt.Errorf("read %s %s %s: %w", family, tableName, fam.set, err)
		}
		plan := firewall.PlanBlockBatch(fam.want, current)
		res = res.Add(plan.Result())
		writeBlockBatch(&sb, fam.set, plan.Writes)
	}
	return sb.String(), res, nil
}

// writeBlockBatch renders one set's writes: deletes for the replaced
// addresses first, then every address created with its own timeout.
func writeBlockBatch(sb *strings.Builder, set string, writes []firewall.PlannedBlock) {
	var dels, adds []string
	for _, w := range writes {
		ip := w.IP.String()
		if w.Replace {
			dels = append(dels, ip)
		}
		if !w.Permanent {
			ip += " timeout " + humanTimeout(w.TTL)
		}
		adds = append(adds, ip)
	}
	writeElemStmts(sb, "delete", set, dels)
	writeElemStmts(sb, "create", set, adds)
}

func writeElemStmts(sb *strings.Builder, verb, set string, elems []string) {
	for i := 0; i < len(elems); i += blockBatchStmtElems {
		j := min(i+blockBatchStmtElems, len(elems))
		fmt.Fprintf(sb, "%s element %s %s %s { %s }\n", verb, family, tableName, set, strings.Join(elems[i:j], ", "))
	}
}

// RemoveBlockBatch unblocks many host addresses: one `nft -j list set` per
// address family, then one `nft -f -` run deleting just the addresses the
// block sets hold (firewall.HostsPresent). Deleting one a set doesn't hold
// would abort the whole transaction, and most addresses of a fleet-wide
// unblock aren't blocked on any one node; that abort used to send every
// address through RemoveBlock, one nft process each.
//
// An address can still expire or be removed between the read and the write,
// which aborts the transaction; it is then retried from a fresh read, up to
// blockBatchAttempts times, never one process per address.
func (b *Backend) RemoveBlockBatch(ips []net.IP) error {
	v4, v6 := firewall.SplitHostAddrs(ips)
	if len(v4)+len(v6) == 0 {
		return nil
	}
	var lastErr error
	for attempt := 0; attempt < blockBatchAttempts; attempt++ {
		var sb strings.Builder
		for _, fam := range []struct {
			set  string
			want []net.IP
		}{{setV4, v4}, {setV6, v6}} {
			if len(fam.want) == 0 {
				continue
			}
			current, err := b.ListSetElementsTimed(fam.set)
			if err != nil {
				return fmt.Errorf("read %s %s %s: %w", family, tableName, fam.set, err)
			}
			var elems []string
			for _, ip := range firewall.HostsPresent(fam.want, current) {
				elems = append(elems, ip.String())
			}
			writeElemStmts(&sb, "delete", fam.set, elems)
		}
		if sb.Len() == 0 {
			return nil
		}
		r, err := runNFTCommandInput(context.Background(), sb.String(), "-f", "-")
		if err == nil {
			return nil
		}
		lastErr = &nftBatchError{msg: nftFirstError(r.Stdout+r.Stderr, err), err: err}
	}
	return fmt.Errorf("nft unblock batch (%d v4, %d v6), %d attempts: %w", len(v4), len(v6), blockBatchAttempts, lastErr)
}
