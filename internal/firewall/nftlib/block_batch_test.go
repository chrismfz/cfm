//go:build linux

package nftlib

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"cfm/internal/firewall"
)

// blockBatchBackend serves an empty block_v4 set, records each write
// transaction's message types, and fails the first failWrites of them.
func blockBatchBackend(t *testing.T, failWrites int, batches *[][]int) *Backend {
	t.Helper()
	b := nlBackend(t, func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, io.EOF
		}
		if isBatch(req) {
			var types []int
			for _, m := range req {
				types = append(types, nftMsgType(m))
			}
			*batches = append(*batches, types)
			if failWrites > 0 {
				failWrites--
				return nil, unix.ENOENT
			}
			return nil, io.EOF
		}
		if nftMsgType(req[0]) == unix.NFT_MSG_GETSETELEM { // an empty set
			return []netlink.Message{{Header: netlink.Header{Type: netlink.Done, Flags: netlink.Multi, Sequence: req[0].Header.Sequence}}}, nil
		}
		return nil, io.EOF
	})
	b.namedSets[setBlockV4] = &nftables.Set{Name: setBlockV4, KeyType: nftables.TypeIPAddr, HasTimeout: true,
		Table: &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}}
	return b
}

func v4Entries(n int, ttl time.Duration) []firewall.BlockEntry {
	var out []firewall.BlockEntry
	for i := 0; i < n; i++ {
		out = append(out, firewall.BlockEntry{IP: net.IPv4(10, 2, byte(i/250), byte(i%250+1)), TTL: ttl})
	}
	return out
}

// One transaction per setWriteChunk addresses (the netlink size bound), not
// one per address as AddBlock costs.
func TestAddBlockBatch_OneTransactionPerChunk(t *testing.T) {
	var batches [][]int
	b := blockBatchBackend(t, 0, &batches)
	res, err := b.AddBlockBatch(v4Entries(2500, time.Hour))
	if err != nil {
		t.Fatalf("AddBlockBatch: %v", err)
	}
	if res.Added != 2500 || len(batches) != 3 {
		t.Fatalf("result %+v in %d transactions, want 2500 added in 3", res, len(batches))
	}
}

// Replaced addresses are deleted and re-added in the SAME transaction, the
// deletes first, so the address is never unblocked in between.
func TestWriteBlockBatch_DeletesBeforeAddsInOneTransaction(t *testing.T) {
	var batches [][]int
	b := blockBatchBackend(t, 0, &batches)
	var writes []firewall.PlannedBlock
	for i, e := range v4Entries(1500, time.Hour) {
		writes = append(writes, firewall.PlannedBlock{BlockEntry: e, Replace: i%2 == 0})
	}
	if _, err := b.writeBlockBatch(b.namedSets[setBlockV4], writes); err != nil {
		t.Fatalf("writeBlockBatch: %v", err)
	}
	if len(batches) != 2 {
		t.Fatalf("%d transactions, want 2", len(batches))
	}
	for i, types := range batches {
		del, add := index(types, unix.NFT_MSG_DELSETELEM), index(types, unix.NFT_MSG_NEWSETELEM)
		if del < 0 || add < 0 || del > add {
			t.Errorf("transaction %d: want deletes then adds; types %v", i, types)
		}
	}
}

// A failed write is retried once from a fresh read, then reported — never
// broken up into one transaction per address.
func TestAddBlockBatch_RetriesOnceNeverPerAddress(t *testing.T) {
	var batches [][]int
	b := blockBatchBackend(t, 1, &batches)
	if res, err := b.AddBlockBatch(v4Entries(10, time.Hour)); err != nil || res.Added != 10 {
		t.Fatalf("one failed write must be retried: res=%+v err=%v", res, err)
	}
	if len(batches) != 2 {
		t.Errorf("%d transactions, want 2", len(batches))
	}

	batches = nil
	b = blockBatchBackend(t, 99, &batches)
	if _, err := b.AddBlockBatch(v4Entries(10, time.Hour)); err == nil {
		t.Fatal("want an error once the retry fails too")
	}
	if len(batches) != 2 {
		t.Errorf("%d transactions, want 2 (no per-address fallback)", len(batches))
	}
}
