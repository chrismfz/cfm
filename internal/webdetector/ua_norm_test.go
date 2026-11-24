package webdetector

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// scripts/tests/fixtures/ua_norm.txt is shared with
// scripts/tests/cfm_ua_emergency_test.lua: the daemon (`cfm bots top`, the
// rule key) and the edge (the rule match) must key every UA the same way.
func TestNormalizeUA(t *testing.T) {
	f, err := os.Open("../../scripts/tests/fixtures/ua_norm.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		in, want, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("fixture line without a tab: %q", line)
		}
		in, want = unescapeUAFixture(t, in), unescapeUAFixture(t, want)
		if got := NormalizeUA(in); got != want {
			t.Errorf("NormalizeUA(%q) = %q, want %q", in, got, want)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 30 {
		t.Fatalf("fixture read only %d cases", n)
	}
}

// unescapeUAFixture decodes \n \r \t \v \f \\ and \xHH, like the Lua test.
func unescapeUAFixture(t *testing.T, s string) string {
	t.Helper()
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte('\v')
		case 'f':
			b.WriteByte('\f')
		case '\\':
			b.WriteByte('\\')
		case 'x':
			if i+2 >= len(s) {
				t.Fatalf("short \\x escape in %q", s)
			}
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				t.Fatalf("bad \\x escape in %q", s)
			}
			b.WriteByte(byte(v))
			i += 2
		default:
			t.Fatalf("unknown escape \\%c in %q", s[i], s)
		}
	}
	return b.String()
}

// BenchmarkNormalizeUABrowser is the common case on every ingest event: a
// browser UA with two groups and no marker.
func BenchmarkNormalizeUABrowser(b *testing.B) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = NormalizeUA(ua)
	}
}
