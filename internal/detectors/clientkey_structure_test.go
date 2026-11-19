package detectors

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Every log detector's sliding-window key groups an IPv6 client by its /64
// (core.ClientKey / ipkey.Client; docs/edge-ipv6.md "IPv6 /64 grouping"):
// a key built from the raw address ("AUTHFAIL|ip:" + ip) gave a client
// rotating inside its /64 a fresh window per address. The per-detector unit
// tests (ssh, wafsec, apiabuse, cookiediscard) pin the behaviour; this pins
// the shape in the detectors that share it.
func TestDetectorWindowKeysGroupIPv6Clients(t *testing.T) {
	// The shapes the log detectors build a window key in, spaced any way. A
	// key built another way (fmt.Sprint, a helper) is not seen: the unit
	// tests are the real pin, this catches the copy-paste regression.
	raw := regexp.MustCompile(`\b(?:sk|key)\s*:?=\s*(?:kindKey|p\.kindKey|tag)\s*\+\s*":"\s*\+\s*(?:p\.)?key\b` +
		`|\bsk\s*:?=\s*"ip:"\s*\+\s*ip\b` + // modsec (its metas stay per address)
		`|\.(?:Add|Count|Allow)\(\s*kindKey\s*\+\s*":"\s*\+\s*key\b`)
	var bad []string
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			if raw.MatchString(line) {
				bad = append(bad, path+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) > 0 {
		t.Fatalf("window keys on the raw address (use core.ClientKey):\n%s", strings.Join(bad, "\n"))
	}
}
