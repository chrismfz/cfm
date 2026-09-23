package locate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeImunify puts imunify360-agent (answering from files: byip-<ip>.out,
// list.out) and an always-active systemctl first in PATH.
func fakeImunify(t *testing.T, files map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	agent := fmt.Sprintf(`#!/bin/sh
d=%q
case "$*" in
*--by-ip*) ip=$(echo "$*" | sed 's/.*--by-ip \([^ ]*\).*/\1/'); f="$d/byip-$ip.out"; [ -f "$f" ] && cat "$f" || echo '{"items":[]}';;
*--limit*) cat "$d/list.out";;
esac
`, dir)
	for name, body := range map[string]string{"imunify360-agent": agent, "systemctl": "#!/bin/sh\nexit 0\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil { // #nosec G306 -- test helper must be executable
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func item(ip, purpose string) string {
	return fmt.Sprintf(`{"ip":%q,"purpose":%q}`, ip, purpose)
}

// One query: an unreadable --by-ip answer (a warning on stderr comes back
// with the JSON) goes on to the list, as a miss does.
func TestSearchImunify_UnreadableByIPFallsBackToList(t *testing.T) {
	fakeImunify(t, map[string]string{
		"byip-1.2.3.4.out": "WARNING: deprecated\n" + `{"items":[` + item("1.2.3.4", "drop") + `]}`,
		"list.out":         `{"items":[` + item("1.2.3.0/24", "drop") + `]}`,
	})
	locs, _, why := searchImunify(context.Background(), []*query{mustQuery(t, "1.2.3.4")})
	if why != "" || len(locs) != 1 || len(locs[0]) != 1 || locs[0][0].Match != "1.2.3.0/24" {
		t.Fatalf("locs %+v why %q", locs, why)
	}
}

// Many queries read the list once; a list at the cap may be missing entries,
// so each query is also asked --by-ip and the answers merged.
func TestSearchImunify_CappedListAsksEachQuery(t *testing.T) {
	var entries []string
	for i := 0; i < imunifyListCap-1; i++ {
		entries = append(entries, item(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "drop"))
	}
	entries = append(entries, item("1.2.3.4", "white"))
	fakeImunify(t, map[string]string{
		"list.out":         `{"items":[` + strings.Join(entries, ",") + `]}`,
		"byip-1.2.3.4.out": `{"items":[` + item("1.2.3.4", "white") + "," + item("1.2.3.4", "drop") + `]}`,
		"byip-5.6.7.8.out": "not json",
	})
	qs := []*query{mustQuery(t, "1.2.3.4"), mustQuery(t, "5.6.7.8"), mustQuery(t, "9.9.9.9")}
	locs, skip, why := searchImunify(context.Background(), qs)
	if why != "" {
		t.Fatalf("why %q", why)
	}
	if got := sources(locs[0]); got != "imunify360:white:1.2.3.4 imunify360:drop (BLACK):1.2.3.4" {
		t.Errorf("1.2.3.4: %q (want the list's white entry once, plus --by-ip's drop)", got)
	}
	if len(locs[2]) != 0 || skip[2] != "" {
		t.Errorf("9.9.9.9: %+v skip %q", locs[2], skip[2])
	}
	if !strings.Contains(skip[1], "unreadable output") {
		t.Errorf("5.6.7.8 skip = %q, want the unreadable --by-ip answer named", skip[1])
	}
}
