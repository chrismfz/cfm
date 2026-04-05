// internal/apiserver/auth.go
//
// goauth integration for the cfm apiserver.
//
// Auth is the package-level goauth.Manager set by Start() and used
// by the middleware and login handlers. It is nil when AUTH_DB_PATH
// is not configured — the system falls back to token-only auth.

package apiserver

import (
	"net/http"

	"cfm/internal/logging"
	"github.com/chrismfz/goauth"
)

// Auth is the active goauth manager. Set once by Start(), read everywhere else.
// nil = goauth not configured (token-only mode).
var Auth *goauth.Manager

// SetAuth sets the package-level goauth manager.
// Called by Start() after successful goauth.New().
func SetAuth(m *goauth.Manager) {
	Auth = m
}

// sessionAllowed returns true if the request carries a valid goauth session.
// Always returns false when Auth is nil (token-only mode).
func sessionAllowed(r *http.Request) bool {
	if Auth == nil {
		return false
	}
	defer func() {
		if p := recover(); p != nil {
			logging.LogfAPI("[apiserver] session check panic recovered: %v", p)
		}
	}()
	return Auth.IsAuthenticated(r)
}
