package mysql

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// Every `cfm mysqltop` command line answers -h, --help and help with its
// usage and makes no API call: `mysqltop history prune --help` pruned 30 days
// of history, and the views fetched before looking at the help word.
func TestCLIHelpWordsMakeNoAPICall(t *testing.T) {
	var calls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		t.Errorf("API call on a help word: %s %s", r.Method, r.URL)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()
	old := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = old }()
	subs := [][]string{
		{}, {"text"}, {"live"}, {"top"}, {"locks"}, {"kills"}, {"watch"}, {"ps"}, {"cpu"},
		{"user-summary"}, {"user-kills"}, {"user-history"}, {"user-kill"}, {"user-kill", "--id=5"},
		{"history"}, {"history", "events"}, {"history", "summary"}, {"history", "prune"},
		{"history", "prune", "--days", "7"}, {"history", "truncate", "--yes"}, {"history", "timeline"},
	}
	for _, h := range []string{"-h", "--help", "help"} {
		for _, s := range subs {
			args := append(append([]string{}, s...), h)
			if err := RunMySQLTop(ts.URL, args); err != nil {
				t.Errorf("mysqltop %s: %v", strings.Join(args, " "), err)
			}
		}
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d API call(s) on help words", n)
	}
}
