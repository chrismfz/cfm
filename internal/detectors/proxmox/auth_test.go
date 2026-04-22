package proxmox

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	core "cfm/internal/detectors/core"
)

type stubSource struct {
	lines []string
	idx   int
}

func (s *stubSource) Open() error { return nil }
func (s *stubSource) ReadNext(context.Context) (string, error) {
	if s.idx >= len(s.lines) {
		return "", io.EOF
	}
	line := s.lines[s.idx]
	s.idx++
	return line, nil
}
func (s *stubSource) Position() (offset uint64, inode uint64, ts int64) { return uint64(s.idx), 1, 0 }
func (s *stubSource) Close() error                                      { return nil }
func (s *stubSource) Shutdown() error                                   { return nil }

func TestNormalizeIP(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "::ffff:141.98.11.50", want: "141.98.11.50"},
		{in: "141.98.11.50", want: "141.98.11.50"},
		{in: "not-an-ip", want: ""},
	}
	for _, tc := range cases {
		if got := normalizeIP(tc.in); got != tc.want {
			t.Fatalf("normalizeIP(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestAuthRunOnceParsesMixedFormatsAndTriggersThresholds(t *testing.T) {
	ipRaw := "::ffff:141.98.11.50"
	ipNorm := "141.98.11.50"
	lines := []string{
		"pvedaemon[1234]: authentication failure; rhost=" + ipRaw + " user=root",
		"pam_unix(proxmox-ve-auth:auth): authentication failure; logname= uid=0 euid=0 tty= ruser= rhost=" + ipRaw + " user=root@pam",
		"pvedaemon[1234]: authentication failure; rhost=" + ipRaw + " user=root",
	}

	d := NewAuth(Config{
		Every:           time.Second,
		Window:          time.Minute,
		Cooldown:        time.Millisecond,
		SampleLimit:     10,
		AuthFailPerIP:   3,
		AuthFailPerUser: 2,
	})
	d.SetSource(&stubSource{lines: lines})

	out := make(chan core.Alert, 8)
	if err := d.RunOnce(context.Background(), out); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	close(out)

	var (
		ipAlert   *core.Alert
		rootAlert *core.Alert
	)
	for a := range out {
		if a.Key == ipNorm {
			aa := a
			ipAlert = &aa
		}
		if a.Key == "root" {
			aa := a
			rootAlert = &aa
		}
	}

	if ipAlert == nil {
		t.Fatalf("expected IP alert for %s", ipNorm)
	}
	if got := ipAlert.Extra["ip"]; got != ipNorm {
		t.Fatalf("ip extra mismatch: got %q want %q", got, ipNorm)
	}
	if ipAlert.Count != 3 {
		t.Fatalf("ip alert count=%d want 3", ipAlert.Count)
	}
	if len(ipAlert.Samples) != 3 {
		t.Fatalf("ip samples=%d want 3", len(ipAlert.Samples))
	}
	for _, want := range lines {
		found := false
		for _, sample := range ipAlert.Samples {
			if strings.Contains(sample, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing sample line: %q in %#v", want, ipAlert.Samples)
		}
	}

	if rootAlert == nil {
		t.Fatalf("expected user alert for root with mixed user formats")
	}
	if rootAlert.Count != 2 {
		t.Fatalf("root alert count=%d want 2", rootAlert.Count)
	}
}
