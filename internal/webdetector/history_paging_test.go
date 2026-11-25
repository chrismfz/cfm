package webdetector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// The events answer says itself whether an older page exists, and reads that
// before a scoped caller's server-only rows are dropped: its page comes back
// short, with the rest of its history still reachable, and without a row of
// the node's own.
func TestHistoryEventsNextCursor(t *testing.T) {
	hs, err := NewHistoryStore(filepath.Join(t.TempDir(), "history.sqlite"), 30, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hs.Close)
	e := &Engine{history: hs}
	base := time.Now().Add(-time.Hour).Unix()
	for i := 0; i < 12; i++ {
		typ := "challenge_solved"
		if i >= 9 { // the 3 newest: the node's own fault rows
			typ = "backup_failed"
		}
		hs.AppendChecked(HistoryEvent{TsUnix: base + int64(i), Type: typ, Host: "shop.gr", IP: "198.51.100.7"})
	}
	type page struct {
		Rows []HistoryEvent   `json:"rows"`
		Next map[string]int64 `json:"next"`
	}
	get := func(ctxScoped bool, query string) page {
		t.Helper()
		ctx := adminCtx()
		if ctxScoped {
			ctx = scopedCtx("shop.gr")
		}
		rr := httptest.NewRecorder()
		e.handleHistoryEvents(rr, httptest.NewRequest(http.MethodGet, "/api/v1/webdet/history/events?host=shop.gr&"+query, nil).WithContext(ctx))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", query, rr.Code, rr.Body.String())
		}
		var p page
		if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, enrich := range []string{"", "&enrich=1"} {
		// Admin: 5 + 5 + 2, the last page without a cursor.
		p := get(false, "limit=5"+enrich)
		if len(p.Rows) != 5 || p.Next == nil {
			t.Fatalf("admin page 1%s: %d rows, next %v", enrich, len(p.Rows), p.Next)
		}
		seen := len(p.Rows)
		for p.Next != nil {
			p = get(false, fmt.Sprintf("limit=5&before_ts=%d&before_id=%d%s", p.Next["before_ts"], p.Next["before_id"], enrich))
			seen += len(p.Rows)
		}
		if seen != 12 {
			t.Fatalf("admin paged %d rows%s, want 12", seen, enrich)
		}
		// Scoped: the first page loses its 3 server-only rows and still leads on.
		s := get(true, "limit=5"+enrich)
		if len(s.Rows) != 2 || s.Next == nil {
			t.Fatalf("scoped page 1%s: %d rows, next %v (a short page that is not the last)", enrich, len(s.Rows), s.Next)
		}
		got := len(s.Rows)
		for s.Next != nil {
			s = get(true, fmt.Sprintf("limit=5&before_ts=%d&before_id=%d%s", s.Next["before_ts"], s.Next["before_id"], enrich))
			for _, r := range s.Rows {
				if r.Type != "challenge_solved" {
					t.Fatalf("scoped caller read a %s row", r.Type)
				}
			}
			got += len(s.Rows)
		}
		if got != 9 {
			t.Fatalf("scoped paged %d rows%s, want its 9", got, enrich)
		}
	}
}
