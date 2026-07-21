package clam

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// clamd INSTREAM client — the inline (blocking) scan path. The daemon reads
// the spooled upload itself and streams the bytes to clamd, so clamd never
// needs filesystem access to nginx-owned spool files, and there is no extra
// pending-dir copy on the latency-critical path.
//
// Protocol: "zINSTREAM\x00", then length-prefixed chunks (4-byte big-endian
// size + data), terminated by a zero-length chunk; clamd answers one line:
// "stream: OK" | "stream: <sig> FOUND" | "... ERROR".

const instreamChunkSize = 64 << 10

// errStreamRejected marks a clamd-side ERROR reply (e.g. INSTREAM size limit
// exceeded) — a scan FAILURE, never a clean verdict. Callers fail open and
// fall back to the async path.
var errStreamRejected = errors.New("clam: clamd rejected stream")

// ScanStream scans r via INSTREAM, bounded by d (dial + whole exchange).
func (c *Client) ScanStream(r io.Reader, d time.Duration) (*Result, error) {
	if d <= 0 {
		d = c.cfg.Timeout
	}
	conn, err := c.dialTimeout(d)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(d))

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return nil, err
	}
	buf := make([]byte, instreamChunkSize)
	var hdr [4]byte
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(hdr[:], uint32(n)) //nolint:gosec // n <= instreamChunkSize
			if _, err := conn.Write(hdr[:]); err != nil {
				return nil, err
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return nil, err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
	}
	binary.BigEndian.PutUint32(hdr[:], 0)
	if _, err := conn.Write(hdr[:]); err != nil {
		return nil, err
	}

	respBytes, err := io.ReadAll(io.LimitReader(conn, 4096))
	if err != nil && len(respBytes) == 0 {
		return nil, err
	}
	resp := strings.TrimRight(string(respBytes), "\x00\n ")
	if strings.HasSuffix(resp, " ERROR") || strings.HasSuffix(resp, "ERROR") {
		return nil, fmt.Errorf("%w: %s", errStreamRejected, resp)
	}
	body := resp
	if _, after, found := strings.Cut(resp, ": "); found {
		body = after
	}
	body = strings.TrimSpace(body)
	res := &Result{Path: "stream", Raw: resp}
	switch {
	case body == "OK" || strings.HasSuffix(body, " OK"):
		return res, nil
	case strings.HasSuffix(body, " FOUND"):
		res.Infected = true
		res.Signature = strings.TrimSpace(strings.TrimSuffix(body, " FOUND"))
		return res, nil
	default:
		// Unrecognised reply — treat as failure, not as clean (fail open at
		// the caller, but never fabricate a verdict).
		return nil, fmt.Errorf("clam: unrecognised INSTREAM reply %q", resp)
	}
}

// ScanFileStream opens path and INSTREAMs its content.
func (c *Client) ScanFileStream(path string, d time.Duration) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return c.ScanStream(f, d)
}
