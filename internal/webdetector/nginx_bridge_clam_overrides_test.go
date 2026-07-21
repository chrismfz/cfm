package webdetector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// The edge reader (cfm_clamav.lua fetch_overrides) is a minimal HTTP parser:
// it splits on CRLFCRLF and cjson.decode's the remainder, which only works on a
// Content-Length-delimited body. net/http auto-chunks a response once it exceeds
// its ~2KB write buffer (~25 excludeEntry rows), and the edge parser cannot
// decode chunk framing — so handleClamExcludes marshals first and sets an
// explicit Content-Length. This pins that guarantee for a list well past the
// chunking threshold (the failure mode was: opt-out silently stops taking effect
// past ~25 vhosts on a busy shared server).
func TestHandleClamExcludes_ContentLengthSetForLargeList(t *testing.T) {
	const tok = "tok"
	b := NewNginxBridge("/tmp/cfm-test.sock", tok, time.Minute, time.Minute)

	const n = 200 // ~200 rows ≫ the ~25-row chunking threshold
	b.ListClamScanOverrides = func() []excludeEntry {
		out := make([]excludeEntry, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, excludeEntry{
				Type:      "host",
				Value:     fmt.Sprintf("vhost-%03d.example.com", i),
				CreatedAt: time.Unix(int64(1_700_000_000+i), 0).UTC(),
			})
		}
		return out
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nginx/clam/overrides", nil)
	req.Header.Set("X-CFM-Token", tok)
	b.handleClamExcludes(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.Bytes()

	// Explicit Content-Length matching the body is what keeps net/http from
	// chunking on a real connection.
	cl := rr.Header().Get("Content-Length")
	if cl == "" {
		t.Fatal("no Content-Length header — a large response will be chunked and the edge parser cannot decode it")
	}
	if got, _ := strconv.Atoi(cl); got != len(body) {
		t.Fatalf("Content-Length = %s, want %d (body len)", cl, len(body))
	}
	if rr.Result().TransferEncoding != nil {
		t.Fatalf("unexpected Transfer-Encoding %v — must be identity/Content-Length", rr.Result().TransferEncoding)
	}

	// And the payload is intact: all n host entries survive the round-trip.
	var decoded struct {
		Entries []excludeEntry `json:"entries"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode entries: %v", err)
	}
	if len(decoded.Entries) != n {
		t.Fatalf("entries = %d, want %d", len(decoded.Entries), n)
	}
}

// A scoped/edge token is still required; an unauthenticated poll is refused.
func TestHandleClamExcludes_RequiresToken(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	b.ListClamScanOverrides = func() []excludeEntry { return nil }

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nginx/clam/overrides", nil) // no token
	b.handleClamExcludes(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (missing token)", rr.Code)
	}
}
