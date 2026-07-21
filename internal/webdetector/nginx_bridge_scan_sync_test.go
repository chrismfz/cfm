package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"cfm/internal/clam"
)

// fakeSyncScanner satisfies clam.Enqueuer + the bridge's clamSyncScanner
// assertion with a canned verdict.
type fakeSyncScanner struct {
	pending string
	verdict clam.SyncVerdict
	lastJob clam.Job
	scanned bool
}

func (f *fakeSyncScanner) Enqueue(clam.Job) bool { return true }
func (f *fakeSyncScanner) Enabled() bool         { return true }
func (f *fakeSyncScanner) PendingDir() string    { return f.pending }
func (f *fakeSyncScanner) InfectedDir() string   { return "" }
func (f *fakeSyncScanner) ScanUploadSync(j clam.Job) clam.SyncVerdict {
	f.scanned = true
	f.lastJob = j
	return f.verdict
}

// The sync endpoint relays the scanner's verdict with an explicit
// Content-Length, consumes an already_copied temp, and fails OPEN
// (block=false) whenever the scanner is missing or the path is invalid.
func TestHandleUploadScanSync(t *testing.T) {
	const tok = "tok"
	pending := t.TempDir()
	b := NewNginxBridge("/tmp/cfm-test.sock", tok, time.Minute, time.Minute)

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/nginx/upload/scan", strings.NewReader(body))
		req.Header.Set("X-CFM-Token", tok)
		rr := httptest.NewRecorder()
		b.handleUploadScanSync(rr, req)
		return rr
	}
	decode := func(rr *httptest.ResponseRecorder) clamSyncResponse {
		t.Helper()
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
		if cl := rr.Header().Get("Content-Length"); cl == "" {
			t.Fatal("no Content-Length — the minimal Lua parser cannot decode a chunked reply")
		} else if n, _ := strconv.Atoi(cl); n != rr.Body.Len() {
			t.Fatalf("Content-Length %s != body %d", cl, rr.Body.Len())
		}
		var out clamSyncResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	// No token → 403 (the only non-200 path; everything else fails open).
	reqNoTok := httptest.NewRequest(http.MethodPost, "/nginx/upload/scan", strings.NewReader("{}"))
	rrNoTok := httptest.NewRecorder()
	b.handleUploadScanSync(rrNoTok, reqNoTok)
	if rrNoTok.Code != http.StatusForbidden {
		t.Fatalf("missing token = %d, want 403", rrNoTok.Code)
	}

	// No scanner wired → allow.
	if out := decode(post(`{"ip":"203.0.113.1","body_file":"/x"}`)); out.Block || out.Verdict != "scanner_unavailable" {
		t.Fatalf("no-scanner verdict: %+v", out)
	}

	fake := &fakeSyncScanner{pending: pending, verdict: clam.SyncVerdict{
		Verdict: "infected", Signature: "Win.Trojan.Hide-1", Block: true, WouldBlock: true,
	}}
	b.SetClamManager(fake, pending, filepath.Join(pending, "inf"))

	// Path outside the pending dir with already_copied → rejected, allow.
	if out := decode(post(`{"ip":"1.2.3.4","body_file":"/etc/passwd","already_copied":true}`)); out.Block || out.Verdict != "bad_path" {
		t.Fatalf("bad-path verdict: %+v", out)
	}
	if fake.scanned {
		t.Fatal("scanner must not run on a rejected path")
	}

	// Happy path: temp in pending dir, verdict relayed, temp consumed.
	tmp := filepath.Join(pending, "upload_x")
	if err := os.WriteFile(tmp, []byte("PK\x03\x04data"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"ip": "203.0.113.1", "host": "Shop.Example.COM", "uri": "/up",
		"filename": "a.zip", "body_file": tmp, "already_copied": true,
	})
	out := decode(post(string(body)))
	if !out.Block || out.Signature != "Win.Trojan.Hide-1" || out.Verdict != "infected" {
		t.Fatalf("verdict not relayed: %+v", out)
	}
	if !fake.scanned || fake.lastJob.Host != "shop.example.com" || fake.lastJob.FileName != "a.zip" {
		t.Fatalf("job fields wrong: %+v", fake.lastJob)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("already_copied temp must be consumed by the endpoint")
	}
}
