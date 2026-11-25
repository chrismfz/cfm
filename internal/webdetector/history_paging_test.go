package webdetector

import (
	"path/filepath"
	"testing"
	"time"
)

// Paging the history newest-first: each page continues after the last row of
// the one before, with no row repeated or skipped, rows of one second included.
func TestHistoryQueryEventsBefore(t *testing.T) {
	hs, err := NewHistoryStore(filepath.Join(t.TempDir(), "history.sqlite"), 30, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hs.Close)
	base := time.Now().Add(-time.Hour).Unix()
	for i := 0; i < 25; i++ {
		typ := "waf_trigger"
		if i%5 == 0 {
			typ = "challenge_issued"
		}
		// i/3: three rows share each second.
		if !hs.AppendChecked(HistoryEvent{TsUnix: base + int64(i/3), Type: typ, Host: "shop.gr", IP: "198.51.100.7"}) {
			t.Fatal("append refused")
		}
	}
	all, err := hs.QueryEvents("shop.gr", "", "", 100)
	if err != nil || len(all) != 25 {
		t.Fatalf("all: %d rows, err %v", len(all), err)
	}
	var paged []HistoryEvent
	var ts, id int64
	for page := 0; page < 10; page++ {
		rows, err := hs.QueryEventsBefore("shop.gr", "", "", 10, ts, id)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			break
		}
		paged = append(paged, rows...)
		last := rows[len(rows)-1]
		ts, id = last.TsUnix, last.ID
	}
	if len(paged) != len(all) {
		t.Fatalf("paged %d rows, want %d", len(paged), len(all))
	}
	for i := range all {
		if paged[i].ID != all[i].ID {
			t.Fatalf("row %d: paged id %d, unpaged id %d", i, paged[i].ID, all[i].ID)
		}
	}
	// The cursor composes with the filters.
	first, _ := hs.QueryEventsBefore("shop.gr", "", "challenge_issued", 2, 0, 0)
	if len(first) != 2 {
		t.Fatalf("first filtered page: %d rows", len(first))
	}
	rest, _ := hs.QueryEventsBefore("shop.gr", "", "challenge_issued", 10, first[1].TsUnix, first[1].ID)
	if len(rest) != 3 {
		t.Fatalf("the rest of 5 challenge rows: %d", len(rest))
	}
	for _, r := range rest {
		if r.Type != "challenge_issued" || r.ID == first[0].ID || r.ID == first[1].ID {
			t.Fatalf("filtered page holds %+v", r)
		}
	}
}
