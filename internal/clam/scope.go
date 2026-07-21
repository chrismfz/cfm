package clam

import (
	"io"
	"os"
)

// Scan-scope gate (CLAM_SCAN_SCOPE=archives): decide from a file's MAGIC BYTES
// whether it is a container/archive worth clamd's time. Extensions are
// forgeable (the multi-digit .phpNN bypass taught us that), so the gate never
// looks at names. v1 recognises leading-signature formats only — plain TAR
// (ustar magic at offset 257, no leading signature) is deliberately out: it is
// rare as a browser upload and .tar.gz presents as gzip anyway.
//
// Note the archive class includes ZIP-container document formats (docx/xlsx/
// odt/jar/apk) — correctly: they can carry macros/payloads, and they are the
// FP surface the sig-ignore layer (not scope) is responsible for.

const (
	ScanScopeArchives = "archives"
	ScanScopeAll      = "all"
)

// scopeMagicLen is the longest prefix any recognised signature needs.
const scopeMagicLen = 8

// isArchiveMagic reports whether head (the file's leading bytes) matches a
// recognised archive/container signature.
func isArchiveMagic(head []byte) bool {
	n := len(head)
	// ZIP: PK\x03\x04 (local header), PK\x05\x06 (empty), PK\x07\x08 (spanned).
	if n >= 4 && head[0] == 'P' && head[1] == 'K' {
		switch {
		case head[2] == 0x03 && head[3] == 0x04,
			head[2] == 0x05 && head[3] == 0x06,
			head[2] == 0x07 && head[3] == 0x08:
			return true
		}
	}
	// GZIP: \x1f\x8b
	if n >= 2 && head[0] == 0x1f && head[1] == 0x8b {
		return true
	}
	// BZIP2: "BZh" + block-size digit 1-9.
	if n >= 4 && head[0] == 'B' && head[1] == 'Z' && head[2] == 'h' &&
		head[3] >= '1' && head[3] <= '9' {
		return true
	}
	// RAR (v4 and v5 share this prefix): "Rar!\x1a\x07"
	if n >= 6 && head[0] == 'R' && head[1] == 'a' && head[2] == 'r' &&
		head[3] == '!' && head[4] == 0x1a && head[5] == 0x07 {
		return true
	}
	// 7-Zip: "7z\xbc\xaf\x27\x1c"
	if n >= 6 && head[0] == '7' && head[1] == 'z' && head[2] == 0xbc &&
		head[3] == 0xaf && head[4] == 0x27 && head[5] == 0x1c {
		return true
	}
	// XZ: "\xfd7zXZ\x00"
	if n >= 6 && head[0] == 0xfd && head[1] == '7' && head[2] == 'z' &&
		head[3] == 'X' && head[4] == 'Z' && head[5] == 0x00 {
		return true
	}
	return false
}

// isArchiveFile reads the leading bytes of path and applies isArchiveMagic.
// An open/read error is returned so the caller can fail toward coverage
// (scan anyway) rather than silently skipping.
func isArchiveFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var buf [scopeMagicLen]byte
	n, rerr := io.ReadFull(f, buf[:])
	if rerr != nil && rerr != io.ErrUnexpectedEOF && rerr != io.EOF {
		return false, rerr
	}
	return isArchiveMagic(buf[:n]), nil
}
