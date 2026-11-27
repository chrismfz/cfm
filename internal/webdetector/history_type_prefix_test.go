package webdetector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// type_prefix=mail_ returns every mail finding type (and its recoveries),
// nothing else; a prefix outside [a-z_]+ matches nothing; a scoped caller
// never reads the server-only mail rows through it.
func TestHistoryEventsTypePrefix(t *testing.T) {
	hs, err := NewHistoryStore(filepath.Join(t.TempDir(), "history.sqlite"), 30, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hs.Close)
	base := time.Now().Add(-time.Hour).Unix()
	for i, typ := range []string{"mail_hijack", "waf_trigger", "mail_recovered", "mailbox_x", "mail_", "maim", "backup_failed", "mail_outbound_spike"} {
		if !hs.AppendChecked(HistoryEvent{TsUnix: base + int64(i), Type: typ, Host: "node.example"}) {
			t.Fatal("append refused")
		}
	}
	got := func(prefix string) []string {
		rows, err := hs.QueryEventsFiltered(HistoryFilter{TypePrefix: prefix}, 100, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rows {
			out = append(out, r.Type)
		}
		return out
	}
	want := []string{"mail_outbound_spike", "mail_", "mail_recovered", "mail_hijack"}
	if g := got("mail_"); len(g) != len(want) {
		t.Fatalf("mail_: %v, want %v", g, want)
	} else {
		for i := range want {
			if g[i] != want[i] {
				t.Fatalf("mail_: %v, want %v (newest first)", g, want)
			}
		}
	}
	for _, bad := range []string{"Mail_", "mail%", "mail'", "m\xff"} {
		if g := got(bad); len(g) != 0 {
			t.Fatalf("prefix %q matched %v", bad, g)
		}
	}

	e := &Engine{history: hs}
	read := func(ctx context.Context, url string) []HistoryEvent {
		rr := httptest.NewRecorder()
		e.handleHistoryEvents(rr, httptest.NewRequest(http.MethodGet, url, nil).WithContext(ctx))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status %d %s", url, rr.Code, rr.Body.String())
		}
		var page struct {
			Rows []HistoryEvent `json:"rows"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		return page.Rows
	}
	if rows := read(adminCtx(), "/api/v1/webdet/history/events?type_prefix=mail_&limit=50"); len(rows) != 4 {
		t.Fatalf("admin: %d rows, want 4", len(rows))
	}
	if rows := read(scopedCtx("node.example"), "/api/v1/webdet/history/events?type_prefix=mail_&host=node.example&limit=50"); len(rows) != 0 {
		t.Fatalf("scoped caller read %d server-only mail rows", len(rows))
	}
}
