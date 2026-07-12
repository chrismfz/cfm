package core

import (
	"bufio"
	"errors"
)

// maxLineDrain bounds how much of a single un-terminated line readBoundedLine
// will discard before giving up. 8 MB ≫ any real log line but small enough that
// a hostile stream can't spin a reader forever.
const maxLineDrain = 8 * 1024 * 1024

// errOversizedLine is returned when a single line has no newline within
// maxLineDrain bytes — a pathological/hostile source. Callers surface it as a
// read error (which resets the source) rather than reading forever.
var errOversizedLine = errors.New("core: log line exceeded the bounded read limit")

// readBoundedLine reads one '\n'-terminated line from r, bounding memory to r's
// buffer size.
//
// It exists because bufio.ReadString/ReadBytes accumulate an un-delimited stream
// WITHOUT bound: collectFragments grows a []byte until it finds the delimiter or
// EOF, and the NewReaderSize buffer only limits a single fill. A log source that
// emits a very long line with no newline (a compromised container's stdout, a
// crafted journald record) could therefore OOM the daemon. ReadSlice instead
// caps each read at the buffer and returns bufio.ErrBufferFull, so an over-long
// line is DROPPED (resynced at the next newline) with memory bounded.
//
// The returned line has its trailing '\n' stripped; callers do any extra '\r'
// trimming. A dropped oversized line returns ("", nil) — callers treat the empty
// line as a skip. A line longer than maxLineDrain returns ("", errOversizedLine).
// EOF or a read error is returned as-is.
//
// (The FileTailer in source.go has its own inline variant because it must also
// advance the file offset per chunk for resume; this helper serves the docker /
// journal readers, which have no offset to track.)
func readBoundedLine(r *bufio.Reader) (string, error) {
	slice, err := r.ReadSlice('\n')
	switch err {
	case nil:
		if n := len(slice); n > 0 && slice[n-1] == '\n' {
			slice = slice[:n-1]
		}
		// ReadSlice's slice points into r's buffer (invalidated by the next
		// read) — copy to a string before returning.
		return string(slice), nil
	case bufio.ErrBufferFull:
		// Oversized line: drain to the next newline, bounded by maxLineDrain.
		dropped := len(slice)
		for err == bufio.ErrBufferFull {
			if dropped > maxLineDrain {
				return "", errOversizedLine
			}
			slice, err = r.ReadSlice('\n')
			dropped += len(slice)
		}
		if err != nil {
			return "", err // EOF or read error while draining
		}
		return "", nil // resynced at a newline; the oversized line was dropped
	default:
		return "", err // EOF or read error
	}
}
