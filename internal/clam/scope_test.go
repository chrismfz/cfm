package clam

import (
	"os"
	"path/filepath"
	"testing"
)

// The archives scope gate keys on magic bytes only. Positive: every container
// format we claim to recognise (incl. ZIP-container docs like docx). Negative:
// the high-volume upload types the gate exists to skip, plus short/empty
// inputs and an extension that lies.
func TestIsArchiveMagic(t *testing.T) {
	cases := []struct {
		name string
		head []byte
		want bool
	}{
		{"zip local header", []byte("PK\x03\x04rest"), true},
		{"zip empty archive", []byte("PK\x05\x06"), true},
		{"zip spanned", []byte("PK\x07\x08"), true},
		{"gzip", []byte{0x1f, 0x8b, 0x08}, true},
		{"bzip2", []byte("BZh9data"), true},
		{"rar v4", []byte("Rar!\x1a\x07\x00"), true},
		{"rar v5", []byte("Rar!\x1a\x07\x01\x00"), true},
		{"7z", []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}, true},
		{"xz", []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, true},

		{"png", []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a}, false},
		{"jpeg", []byte{0xff, 0xd8, 0xff, 0xe0}, false},
		{"gif", []byte("GIF89a"), false},
		{"pdf", []byte("%PDF-1.7"), false},
		{"php source", []byte("<?php echo"), false},
		{"plain text", []byte("hello world"), false},
		{"bzip2 bad block size", []byte("BZh0"), false},
		{"pk but not archive marker", []byte("PKZZ"), false},
		{"truncated pk", []byte("PK"), false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isArchiveMagic(tc.head); got != tc.want {
				t.Fatalf("isArchiveMagic(%q) = %v, want %v", tc.head, got, tc.want)
			}
		})
	}
}

// isArchiveFile reads real files (the scanner gates on the spooled temp file);
// name/extension must be irrelevant, and tiny files must not error.
func TestIsArchiveFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	// A "docx" is a ZIP container — stays in scope despite the doc extension.
	docx := write("report.docx", []byte("PK\x03\x04...zipdata..."))
	if ok, err := isArchiveFile(docx); err != nil || !ok {
		t.Fatalf("docx (zip container) = (%v, %v), want in scope", ok, err)
	}
	// An extension that lies the other way: "archive.zip" that is really a PNG.
	fakeZip := write("archive.zip", []byte{0x89, 'P', 'N', 'G'})
	if ok, err := isArchiveFile(fakeZip); err != nil || ok {
		t.Fatalf("png named .zip = (%v, %v), want out of scope", ok, err)
	}
	// Sub-magic-length file: no error, out of scope.
	tiny := write("tiny", []byte("a"))
	if ok, err := isArchiveFile(tiny); err != nil || ok {
		t.Fatalf("tiny file = (%v, %v), want (false, nil)", ok, err)
	}
	// Missing file: error surfaces so process() fails toward scanning.
	if _, err := isArchiveFile(filepath.Join(dir, "gone")); err == nil {
		t.Fatal("missing file should return an error (caller fails open to scanning)")
	}
}
