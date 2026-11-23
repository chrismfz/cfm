package edgecli

import (
	"bytes"
	"strings"
	"testing"

	"cfm/internal/dnat"
)

// `cfm edge`, `edge status` and `edge web` answer a help word with the usage
// and call nothing (`edge status --help` said "takes no arguments").
func TestCLIHelpWordsCallNothing(t *testing.T) {
	var out, errOut bytes.Buffer
	fail := func(what string) { t.Errorf("%s called on a help word", what) }
	d := deps{
		out:     &out,
		errOut:  &errOut,
		summary: func() dnat.Summary { fail("summary"); return dnat.Summary{} },
		dnat:    func([]string) int { fail("dnat"); return 0 },
		realip:  func([]string) int { fail("realip"); return 0 },
		verdict: func(bool) (bool, string) { fail("verdict"); return true, "" },
		ipv6:    func() ([]string, error) { fail("ipv6"); return nil, nil },
		check:   func(int) ([]byte, error) { fail("check"); return nil, nil },
		setIPv6: func(string, []string) int { fail("setIPv6"); return 0 },
	}
	for _, h := range []string{"-h", "--help", "help"} {
		for _, pre := range [][]string{{}, {"status"}, {"web"}, {"ipv6"}, {"ipv6", "status"}, {"ipv6", "on"}, {"ipv6", "off"}, {"ipv6", "on", "OpenResty"}} {
			out.Reset()
			args := append(append([]string{}, pre...), h)
			want := "cfm edge [status]"
			if len(pre) > 0 && pre[0] == "ipv6" {
				want = "cfm edge ipv6"
			}
			if rc := run(args, d); rc != 0 || !strings.Contains(out.String(), want) {
				t.Errorf("%q: rc=%d out=%q err=%q", args, rc, out.String(), errOut.String())
			}
		}
	}
}
