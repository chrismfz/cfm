package dnat

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfiguredWebDNATPriority(t *testing.T) {
	// Reset the package-global config dir after the test so we don't leak state
	// into other tests in this package.
	t.Cleanup(func() { SetConfigDir("") })

	t.Run("reads NFT_DNAT_PRIORITY from cfm.conf", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "cfm.conf"), []byte("NFT_DNAT_PRIORITY = -101\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		SetConfigDir(dir)
		if got := ConfiguredWebDNATPriority(); got != -101 {
			t.Fatalf("got %d, want -101 (the configured value, not the -99 default)", got)
		}
	})

	t.Run("absent key falls back to -99", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "cfm.conf"), []byte("# no priority key here\nTCP_IN = 80,443\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		SetConfigDir(dir)
		if got := ConfiguredWebDNATPriority(); got != NFTDNATPriority {
			t.Fatalf("got %d, want %d", got, NFTDNATPriority)
		}
	})

	t.Run("missing cfm.conf falls back to -99", func(t *testing.T) {
		SetConfigDir(t.TempDir()) // dir exists but has no cfm.conf
		if got := ConfiguredWebDNATPriority(); got != NFTDNATPriority {
			t.Fatalf("got %d, want %d", got, NFTDNATPriority)
		}
	})

	t.Run("unset config dir falls back to -99", func(t *testing.T) {
		SetConfigDir("")
		if got := ConfiguredWebDNATPriority(); got != NFTDNATPriority {
			t.Fatalf("got %d, want %d", got, NFTDNATPriority)
		}
	})
}

func TestParseDNATChainPriority(t *testing.T) {
	tests := []struct {
		name string
		show string
		want int
		ok   bool
	}{
		{
			name: "symbolic dstnat + 1 is -99",
			show: "table inet cfm_redirect {\n  chain prerouting {\n    type nat hook prerouting priority dstnat + 1; policy accept;\n    tcp dport 80 dnat to :9080\n  }\n}",
			want: -99, ok: true,
		},
		{
			name: "symbolic dstnat - 1 is -101",
			show: "    type nat hook prerouting priority dstnat - 1; policy accept;",
			want: -101, ok: true,
		},
		{
			name: "bare dstnat is -100",
			show: "    type nat hook prerouting priority dstnat; policy accept;",
			want: -100, ok: true,
		},
		{
			name: "raw numeric priority",
			show: "    type nat hook prerouting priority -101; policy accept;",
			want: -101, ok: true,
		},
		{
			name: "positive numeric priority",
			show: "    type nat hook prerouting priority 5; policy accept;",
			want: 5, ok: true,
		},
		{
			name: "no prerouting line",
			show: "table inet cfm_redirect {\n  chain other {\n    type filter hook input priority 0;\n  }\n}",
			want: 0, ok: false,
		},
		{
			name: "empty output",
			show: "",
			want: 0, ok: false,
		},
		{
			name: "unrecognised anchor",
			show: "    type nat hook prerouting priority bogus + 1; policy accept;",
			want: 0, ok: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseDNATChainPriority(tc.show)
			if ok != tc.ok || (ok && got != tc.want) {
				t.Fatalf("parseDNATChainPriority() = (%d, %v), want (%d, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}
