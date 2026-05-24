package sslcollector

import (
	"os"
	"path/filepath"
	"testing"
)

// Verify findDirectAdminChain picks the right file across the DA
// naming variants we've seen — and that the glob fallback catches
// names not in the explicit list.
func TestFindDirectAdminChain(t *testing.T) {
	type setup struct {
		name  string
		files map[string]string // suffix -> content (presence-only test)
		want  string            // expected suffix selected, "" if none
	}

	cases := []setup{
		{
			name:  "modern DA prefers .cacert",
			files: map[string]string{".cert": "x", ".key": "x", ".cacert": "x", ".cert.combined": "x"},
			want:  ".cacert",
		},
		{
			name:  "legacy .ca when no .cacert",
			files: map[string]string{".cert": "x", ".key": "x", ".ca": "x"},
			want:  ".ca",
		},
		{
			name:  ".cert.combined fallback",
			files: map[string]string{".cert": "x", ".key": "x", ".cert.combined": "x"},
			want:  ".cert.combined",
		},
		{
			name:  "no chain available",
			files: map[string]string{".cert": "x", ".key": "x"},
			want:  "",
		},
		{
			name:  "glob fallback picks .ca-bundle",
			files: map[string]string{".cert": "x", ".key": "x", ".ca-bundle": "x"},
			want:  ".ca-bundle",
		},
		{
			name:  "glob fallback picks future .chainfile",
			files: map[string]string{".cert": "x", ".key": "x", ".chainfile": "x"},
			want:  ".chainfile",
		},
		{
			name:  "glob ignores .csr / .conf / .ftp etc",
			files: map[string]string{".cert": "x", ".key": "x", ".csr": "x", ".conf": "x", ".ftp": "x"},
			want:  "",
		},
		{
			name:  "explicit list beats glob (cacert wins over ca-bundle)",
			files: map[string]string{".cert": "x", ".key": "x", ".cacert": "x", ".ca-bundle": "x"},
			want:  ".cacert",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			base := filepath.Join(dir, "example.com")
			for suf, body := range tc.files {
				if err := os.WriteFile(base+suf, []byte(body), 0o644); err != nil {
					t.Fatalf("write %s: %v", suf, err)
				}
			}
			got := findDirectAdminChain(base)
			wantPath := ""
			if tc.want != "" {
				wantPath = base + tc.want
			}
			if got != wantPath {
				t.Errorf("findDirectAdminChain: got %q want %q", got, wantPath)
			}
		})
	}
}

// Verify scanDirectAdmin no longer matches `<domain>.cert.combined` as a
// standalone cert entry (was the cause of phantom duplicates when the
// match was `strings.HasSuffix(name, ".cert")`).
func TestScanDirectAdminSkipsCertCombined(t *testing.T) {
	root := t.TempDir()
	userDom := filepath.Join(root, "u", "domains")
	if err := os.MkdirAll(userDom, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{
		"example.com.cert",
		"example.com.key",
		"example.com.cacert",
		"example.com.cert.combined",
		"example.com.cert.creation_time",
	} {
		if err := os.WriteFile(filepath.Join(userDom, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pairs := scanDirectAdmin(root)
	if len(pairs) != 1 {
		t.Fatalf("expected exactly 1 pair, got %d (%+v)", len(pairs), pairs)
	}
	if pairs[0].ChainPath == "" || filepath.Base(pairs[0].ChainPath) != "example.com.cacert" {
		t.Errorf("expected ChainPath=example.com.cacert, got %q", pairs[0].ChainPath)
	}
}
