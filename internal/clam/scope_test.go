package clam

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// pending is writable by the edge's user: a queued file swapped for a
// symlink is not read through.
func TestIsArchiveFileDoesNotFollowASymlink(t *testing.T) {
	dir := t.TempDir()
	zip := filepath.Join(dir, "z")
	if err := os.WriteFile(zip, []byte("PK\x03\x04"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "l")
	if err := os.Symlink(zip, link); err != nil {
		t.Fatal(err)
	}
	if _, err := isArchiveFile(link); err == nil {
		t.Error("isArchiveFile read through a symlink")
	}
}

// A queued temp copy swapped for a symlink (to /: ScanPath walked the whole
// filesystem as root) is dropped, not followed; the link is removed, its
// target left alone.
func TestProcessDropsASymlinkedTempCopy(t *testing.T) {
	victim := t.TempDir()
	keep := filepath.Join(victim, "keep")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "upload_1")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	m := NewManager(Config{Enabled: true, Network: "unix", Address: filepath.Join(t.TempDir(), "none.sock")})
	m.process(Job{Path: link, TempCopy: true})
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Errorf("symlinked temp copy not removed: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("symlink target touched: %v", err)
	}
}

// fakeScanClamd answers every newline-terminated command with "<path>:
// Eicar FOUND" (the async SCAN path).
func fakeScanClamd(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "clamd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				_, _ = c.Write([]byte(strings.TrimPrefix(strings.TrimSpace(line), "SCAN ") + ": Eicar-Test-Signature FOUND\n"))
			}(c)
		}
	}()
	return sock
}

// Async evidence is a copy into a new file, not the edge's spool renamed:
// renamed, its inode stayed writable through an fd the edge's user held, and
// re-posting the (known) name overwrote earlier evidence.
func TestAsyncEvidenceIsANewCopy(t *testing.T) {
	pending, inf := t.TempDir(), t.TempDir()
	spool := filepath.Join(pending, "upload_1")
	if err := os.WriteFile(spool, []byte("X5O!P%@AP"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Earlier evidence under the spool's plain name must survive.
	earlier := filepath.Join(inf, "upload_1")
	if err := os.WriteFile(earlier, []byte("EARLIER"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(Config{Enabled: true, Network: "unix", Address: fakeScanClamd(t), Timeout: 2 * time.Second})
	m.process(Job{Path: spool, TempCopy: true, InfectedDir: inf})
	if _, err := os.Lstat(spool); !os.IsNotExist(err) {
		t.Errorf("spool left in pending: %v", err)
	}
	if b, _ := os.ReadFile(earlier); string(b) != "EARLIER" {
		t.Errorf("earlier evidence overwritten: %q", b)
	}
	got, _ := filepath.Glob(filepath.Join(inf, "upload_1.*"))
	if len(got) != 1 {
		t.Fatalf("evidence copies: %v", got)
	}
	if b, _ := os.ReadFile(got[0]); string(b) != "X5O!P%@AP" {
		t.Errorf("evidence content %q", b)
	}
}
