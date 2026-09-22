//go:build linux

package nft

import (
	"context"
	"errors"
	"fmt"
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
// attempt at most, whatever the batch size, where AddBlock forks up to three
// per address. It only adds or extends, never shortens
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
// process per address.
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
		lastErr = errors.New(nftFirstError(r.Stdout+r.Stderr, err))
	}
	return res, fmt.Errorf("nft block batch (%d v4, %d v6): %w", len(v4), len(v6), lastErr)
}

// nftFirstError is nft's own "Error: …" line, or the command error: nft
// follows it with the whole failing statement and a caret line, which for a
// batch is thousands of addresses.
func nftFirstError(out string, err error) string {
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "Error:") {
			if len(line) > 300 {
				line = line[:300] + "…"
			}
			return line
		}
	}
	return err.Error()
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
