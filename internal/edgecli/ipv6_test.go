package edgecli

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"cfm/internal/dnat"
	"cfm/internal/originrealip"
)

func TestIPv6Routing(t *testing.T) {
	for args, want := range map[string][]string{
		"ipv6 on":            {"on", "render"},
		"ipv6 off":           {"off", "render"},
		"ipv6 on cfm-edge":   {"on", "render", "cfm-edge"},
		"ipv6 off OpenResty": {"off", "render", "OpenResty"},
		"ipv6 on ANGIE":      {"on", "render", "Angie"},
	} {
		r := &recorder{}
		d, _, _ := testDeps(r, dnat.Summary{}, nil, nil)
		if rc := run(strings.Fields(args), d); rc != 0 || len(r.ipv6Set) != 1 || !reflect.DeepEqual(r.ipv6Set[0], want) {
			t.Errorf("%q: rc=%d calls=%v want %v", args, rc, r.ipv6Set, want)
		}
	}
}

func TestSetEdgeListenV6(t *testing.T) {
	const ref = "A = 1\n# EDGE_LISTEN_V6 = off\nB = 2\n"
	cases := []struct {
		name, in, value, want string
	}{
		{"append when absent", ref, "on", ref + "\n# Set by `cfm edge ipv6 on` (docs/edge-ipv6.md).\nEDGE_LISTEN_V6 = on\n"},
		{"append to a file without a final newline", "A = 1", "off", "A = 1\n\n# Set by `cfm edge ipv6 off` (docs/edge-ipv6.md).\nEDGE_LISTEN_V6 = off\n"},
		{"replace in place, comment untouched", "A = 1\n# EDGE_LISTEN_V6 = off\nEDGE_LISTEN_V6 = on ; note\nB = 2\n", "off",
			"A = 1\n# EDGE_LISTEN_V6 = off\nEDGE_LISTEN_V6 = off\nB = 2\n"},
		{"several active lines become one", "EDGE_LISTEN_V6 = on\nA = 1\n  EDGE_LISTEN_V6=off\n", "on", "EDGE_LISTEN_V6 = on\nA = 1\n"},
		{"default removes every active line", "EDGE_LISTEN_V6 = off\nA = 1\nEDGE_LISTEN_V6 = on\n", "", "A = 1\n"},
		{"default with none is a no-op", ref, "", ref},
		{"a similar key is not touched", "EDGE_LISTEN_V6_X = 1\n", "on", "EDGE_LISTEN_V6_X = 1\n\n# Set by `cfm edge ipv6 on` (docs/edge-ipv6.md).\nEDGE_LISTEN_V6 = on\n"},
		{"already set: unchanged", "EDGE_LISTEN_V6 = on\n", "on", "EDGE_LISTEN_V6 = on\n"},
	}
	for _, c := range cases {
		if got := setEdgeListenV6(c.in, c.value); got != c.want {
			t.Errorf("%s:\ngot  %q\nwant %q", c.name, got, c.want)
		}
	}
}

// The production path: cfm.conf rewritten in place (mode kept), the script's
// render run with CFM_CONF pointing at that same file, its output printed.
func TestSetIPv6WritesTheConfAndRenders(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "cfm.conf")
	if err := os.WriteFile(conf, []byte("A = 1\nEDGE_LISTEN_V6 = off\nB = 2\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "listen-v6.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldConf, oldRun, oldScript := confPath, renderRunner, ListenV6Script
	t.Cleanup(func() { confPath, renderRunner, ListenV6Script = oldConf, oldRun, oldScript })
	confPath = func() string { return conf }
	ListenV6Script = script
	var gotArgs []string
	renderRunner = func(a ...string) (string, error) {
		gotArgs = a
		return "CFM edge IPv6 listen: cfm-edge: listening on IPv6 too (ready)\n", nil
	}

	d, out, _ := testDeps(&recorder{}, dnat.Summary{}, []string{"cfm-edge: listening on IPv6 too (now)"}, nil)
	if rc := setIPv6(d, "on", []string{"render", "cfm-edge"}); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	b, _ := os.ReadFile(conf)
	if string(b) != "A = 1\nB = 2\n" {
		t.Fatalf("conf: %q", b)
	}
	if st, _ := os.Stat(conf); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode changed: %v", st.Mode())
	}
	if !reflect.DeepEqual(gotArgs, []string{"render", "cfm-edge"}) {
		t.Fatalf("render got args=%v", gotArgs)
	}
	for _, want := range []string{"no EDGE_LISTEN_V6 line (the default", "reloads a running edge", "cfm-edge: listening on IPv6 too (ready)", "Now:\n  cfm-edge: listening on IPv6 too (now)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".cfm.conf.edge-ipv6.*")); len(left) != 0 {
		t.Fatalf("temp file left: %v", left)
	}

	// Same value again: no rewrite, render still runs.
	d, out, _ = testDeps(&recorder{}, dnat.Summary{}, nil, nil)
	if rc := setIPv6(d, "on", []string{"render"}); rc != 0 || !strings.Contains(out.String(), "unchanged") {
		t.Fatalf("rc=%d out=%s", rc, out.String())
	}

	// A failed render: exit 1, the conf change stays (and it says so).
	renderRunner = func(...string) (string, error) { return "", errors.New("exit status 1") }
	d, _, errOut := testDeps(&recorder{}, dnat.Summary{}, nil, nil)
	if rc := setIPv6(d, "off", []string{"render"}); rc != 1 || !strings.Contains(errOut.String(), "cfm.conf is changed") {
		t.Fatalf("rc=%d err=%s", rc, errOut.String())
	}
}

// Nothing is written when the script or the conf is not there.
func TestSetIPv6RefusesWithoutTheScriptOrTheConf(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "cfm.conf")
	oldConf, oldRun, oldScript := confPath, renderRunner, ListenV6Script
	t.Cleanup(func() { confPath, renderRunner, ListenV6Script = oldConf, oldRun, oldScript })
	confPath = func() string { return conf }
	ran := false
	renderRunner = func(...string) (string, error) { ran = true; return "", nil }

	ListenV6Script = filepath.Join(dir, "missing.sh")
	if err := os.WriteFile(conf, []byte("A = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, _, _ := testDeps(&recorder{}, dnat.Summary{}, nil, nil)
	if rc := setIPv6(d, "on", []string{"render"}); rc != 1 || ran {
		t.Fatalf("missing script: rc=%d ran=%v", rc, ran)
	}
	if b, _ := os.ReadFile(conf); string(b) != "A = 1\n" {
		t.Fatalf("conf changed without the script: %q", b)
	}

	ListenV6Script = conf // any existing file
	_ = os.Remove(conf)
	d, _, _ = testDeps(&recorder{}, dnat.Summary{}, nil, nil)
	if rc := setIPv6(d, "on", []string{"render"}); rc != 1 || ran {
		t.Fatalf("missing conf: rc=%d ran=%v", rc, ran)
	}
}

// `on` never writes EDGE_LISTEN_V6 = on (an edge start would then turn IPv6
// on unconfirmed): it lifts a kill switch and leaves anything else alone.
func TestV6UpdateOnNeverWritesOn(t *testing.T) {
	for in, want := range map[string]string{
		"A = 1\n":                                   "A = 1\n",
		"EDGE_LISTEN_V6 = on\n":                     "EDGE_LISTEN_V6 = on\n",
		"EDGE_LISTEN_V6 = auto ; mine\n":            "EDGE_LISTEN_V6 = auto ; mine\n",
		"A = 1\nEDGE_LISTEN_V6 = off\nB = 2\n":      "A = 1\nB = 2\n",
		"EDGE_LISTEN_V6 = maybe\n":                  "",
		"EDGE_LISTEN_V6 = on\nEDGE_LISTEN_V6 = 0\n": "",
	} {
		if got := v6Update(in, "on"); got != want {
			t.Errorf("on %q: got %q want %q", in, got, want)
		}
	}
	if got := v6Update("A = 1\n", "off"); !strings.HasSuffix(got, "EDGE_LISTEN_V6 = off\n") {
		t.Errorf("off: %q", got)
	}
}

// For every cfm.conf reading the script and Go share, `on` leaves IPv6
// allowed and `off` leaves it off, read by that same reader.
func TestV6UpdateAgainstTheSharedFixture(t *testing.T) {
	b, err := os.ReadFile("../../scripts/tests/fixtures/edge_listen_v6_mode.txt")
	if err != nil {
		t.Fatal(err)
	}
	octal := regexp.MustCompile(`\\0([0-7]{3})`)
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, body, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("bad fixture line %q", line)
		}
		body = octal.ReplaceAllString(body, `\$1`)
		content, err := strconv.Unquote(`"` + strings.ReplaceAll(body, `"`, `\"`) + `"`)
		if err != nil {
			content, err = strconv.Unquote(`"` + body + `"`)
		}
		if err != nil {
			t.Fatalf("fixture %q: %v", body, err)
		}
		content += "\n"
		if on := v6Update(content, "on"); !originrealip.EdgeListenV6Allowed(on) || strings.Contains(on, "EDGE_LISTEN_V6 = on\n# Set by") {
			t.Errorf("on %q -> %q: IPv6 not allowed", content, on)
		}
		if off := v6Update(content, "off"); originrealip.EdgeListenV6Allowed(off) {
			t.Errorf("off %q -> %q: IPv6 still allowed", content, off)
		}
		n++
	}
	if n < 20 {
		t.Fatalf("only %d fixture cases read", n)
	}
}

// THE cfm.conf: the one the script's `cfm realip` call reads too.
func TestIPv6EditsTheConfRealIPReads(t *testing.T) {
	if got := confPath(); got != "/etc/cfm/cfm.conf" {
		t.Fatalf("confPath() = %q", got)
	}
}

// A status that cannot be read after the render is an error, not a silent 0.
func TestSetIPv6StatusAfterRender(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "cfm.conf")
	if err := os.WriteFile(conf, []byte("A = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldConf, oldRun, oldScript := confPath, renderRunner, ListenV6Script
	t.Cleanup(func() { confPath, renderRunner, ListenV6Script = oldConf, oldRun, oldScript })
	confPath = func() string { return conf }
	ListenV6Script = conf
	renderRunner = func(...string) (string, error) { return "", nil }
	d, _, errOut := testDeps(&recorder{}, dnat.Summary{}, nil, errors.New("sh failed"))
	if rc := setIPv6(d, "off", []string{"render"}); rc != 1 || !strings.Contains(errOut.String(), "status") {
		t.Fatalf("rc=%d err=%s", rc, errOut.String())
	}
}
