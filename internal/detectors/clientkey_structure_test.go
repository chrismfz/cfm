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
	raw := regexp.MustCompile(`sk :?= (?:kindKey|p\.kindKey|tag) \+ ":" \+ (?:p\.)?key\b|"ip:" \+ ip\b`)
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
