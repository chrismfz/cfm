package webdetector

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunHistoryWebTop_NoArgsDoesNotPanic(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/webdet/history/events" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"rows":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("runHistoryWebTop panicked: %v", r)
		}
	}()

	if err := runHistoryWebTop(ts.URL, []string{}); err != nil {
		t.Fatalf("runHistoryWebTop returned error: %v", err)
	}
}
