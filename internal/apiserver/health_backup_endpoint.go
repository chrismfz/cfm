package apiserver

// health_backup_endpoint.go — GET /api/v1/health/backup: the latest backup
// check of this node (docs/backup-check.md). cfm-web polls it for its fleet
// Backups table and its "this node stopped reporting backups" check; the MCP
// `backup_status` tool serves it to triage.

import (
	"encoding/json"
	"net/http"
	"time"

	"cfm/internal/backupcheck"
	"cfm/internal/detectors/health"
)

const healthBackupSchemaV1 = "health.backup.v1"

type healthBackupResponse struct {
	SchemaVersion string    `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	// Enabled: the health detector runs the backup check (BACKUP_ALERT).
	Enabled bool `json:"enabled"`
	// Status is the latest completed check; null before the first one
	// finishes (or when the check is off).
	Status *backupcheck.Status `json:"status"`
	// AgeSeconds is how old Status is; -1 when there is none.
	AgeSeconds int64 `json:"age_seconds"`
	// Findings flattens Status's findings, worst first.
	Findings []backupcheck.Finding `json:"findings"`
}

var lastBackupStatusFunc = health.LastBackupStatus
var backupCheckEnabledFunc = health.BackupCheckEnabled

func handleHealthBackup(w http.ResponseWriter, r *http.Request) {
	if !requireHealthAccess(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	now := time.Now().UTC()
	resp := healthBackupResponse{
		SchemaVersion: healthBackupSchemaV1,
		GeneratedAt:   now,
		Enabled:       backupCheckEnabledFunc(),
		AgeSeconds:    -1,
		Findings:      []backupcheck.Finding{},
	}
	if st := lastBackupStatusFunc(); st != nil {
		resp.Status = st
		resp.AgeSeconds = int64(now.Sub(st.CheckedAt).Seconds())
		if f := st.Findings(); f != nil {
			resp.Findings = f
		}
	}
	_ = json.NewEncoder(w).Encode(resp)
}
