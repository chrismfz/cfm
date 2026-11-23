package lvecpu

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// Every `cfm lve` command line answers -h, --help and
// help with its usage and makes no API call (a help word after a subcommand
// used to be read as an argument, or ignored, and the snapshot fetched).
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
	for _, h := range []string{"-h", "--help", "help"} {
		for _, s := range [][]string{{}, {"top"}, {"top", "5"}, {"--json"}, {"10"}} {
			args := append(append([]string{}, s...), h)
			if err := RunCLI(ts.URL, args); err != nil {
				t.Errorf("%s: %v", strings.Join(args, " "), err)
			}
		}
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d API call(s) on help words", n)
	}
}
