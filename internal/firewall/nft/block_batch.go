//go:build linux

package nft

import (
	"context"
	"fmt"
	"strings"

	"cfm/internal/firewall"
)

// blockBatchStmtElems bounds the elements in one add/delete statement of the
// batch script. Every statement is still in the same `nft -f -` run, so the
// whole batch stays one transaction.
const blockBatchStmtElems = 1000

// AddBlockBatch blocks many host addresses in one `nft -f -` transaction,
// after one `nft -j list set` per address family: three nft processes at most,
// whatever the batch size, where AddBlock forks up to three per address. It
// only adds or extends, never shortens (firewall.PlanBlockBatch).
//
// Between the read and the write another writer can change the set: an
// element due for replacement can expire (its delete then fails and nft
// aborts the whole transaction), or an autoblock can add one of the new
// addresses (harmless: `add element` doesn't fail on an existing one). A
// failed write is retried once from a fresh read; it never falls back to one
// nft process per address.
func (b *Backend) AddBlockBatch(entries []firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	v4, v6, skipped := firewall.SplitBlockEntries(entries)
	res := firewall.BlockBatchResult{Skipped: skipped}
	if len(v4)+len(v6) == 0 {
		return res, nil
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
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
		lastErr = fmt.Errorf("%v: %s", err, strings.TrimSpace(r.Stdout+r.Stderr))
	}
	return res, fmt.Errorf("nft block batch (%d v4, %d v6): %w", len(v4), len(v6), lastErr)
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
// addresses first, then every add with its own timeout.
func writeBlockBatch(sb *strings.Builder, set string, writes []firewall.PlannedBlock) {
	var dels, adds []string
	for _, w := range writes {
		ip := w.IP.String()
		if w.Replace {
			dels = append(dels, ip)
		}
		if w.TTL > 0 {
			ip += " timeout " + humanTimeout(w.TTL)
		}
		adds = append(adds, ip)
	}
	writeElemStmts(sb, "delete", set, dels)
	writeElemStmts(sb, "add", set, adds)
}

func writeElemStmts(sb *strings.Builder, verb, set string, elems []string) {
	for i := 0; i < len(elems); i += blockBatchStmtElems {
		j := min(i+blockBatchStmtElems, len(elems))
		fmt.Fprintf(sb, "%s element %s %s %s { %s }\n", verb, family, tableName, set, strings.Join(elems[i:j], ", "))
	}
}
