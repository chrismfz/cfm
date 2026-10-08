package apiserver

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"cfm/internal/backupcheck"
)

func TestHealthBackupEndpoint(t *testing.T) {
	store, h := newSystemStatusTestServer(t)
	origStatus, origEnabled := lastBackupStatusFunc, backupCheckEnabledFunc
	t.Cleanup(func() { lastBackupStatusFunc, backupCheckEnabledFunc = origStatus, origEnabled })

	t.Run("scoped token forbidden", func(t *testing.T) {
		scoped := store.Issue([]string{"mysite.com"}, nil, nil, "viewer", "scoped", time.Hour)
		rr := doSystemStatusReq(h, http.MethodGet, "/api/v1/health/backup", scoped.Token, false)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d want 403 body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("before the first check", func(t *testing.T) {
		lastBackupStatusFunc = func() *backupcheck.Status { return nil }
		backupCheckEnabledFunc = func() bool { return true }
		rr := doSystemStatusReq(h, http.MethodGet, "/api/v1/health/backup", "admin-secret", false)
		var body healthBackupResponse
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &body) != nil {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		if body.SchemaVersion != healthBackupSchemaV1 || !body.Enabled || body.Status != nil || body.AgeSeconds != -1 || body.Findings == nil {
			t.Fatalf("unexpected body %+v", body)
		}
	})

	t.Run("latest check with findings worst first", func(t *testing.T) {
		st := &backupcheck.Status{CheckedAt: time.Now().Add(-90 * time.Second), Adapters: []backupcheck.AdapterStatus{{
			Name: "jetbackup",
			Jobs: []backupcheck.Job{{Name: "Daily", LastResult: "partial"}},
			Findings: []backupcheck.Finding{
				{Type: backupcheck.TypePartial, Severity: backupcheck.SevInfo, Key: "jb:partial:x"},
				{Type: backupcheck.TypeStale, Severity: backupcheck.SevCritical, Key: "jb:stale:x"},
			},
		}}}
		lastBackupStatusFunc = func() *backupcheck.Status { return st }
		rr := doSystemStatusReq(h, http.MethodGet, "/api/v1/health/backup", "admin-secret", false)
		var body healthBackupResponse
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &body) != nil {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		if body.Status == nil || len(body.Status.Adapters) != 1 || body.AgeSeconds < 89 || body.AgeSeconds > 120 {
			t.Fatalf("status/age wrong: %+v", body)
		}
		if len(body.Findings) != 2 || body.Findings[0].Type != backupcheck.TypeStale {
			t.Fatalf("findings must be flattened worst first: %+v", body.Findings)
		}
	})
}
