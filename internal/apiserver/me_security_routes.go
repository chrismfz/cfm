package apiserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"cfm/internal/logging"
	"github.com/chrismfz/goauth"
)

type passwordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

var (
	authRequireAny = func(next http.Handler) http.Handler {
		if Auth == nil {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, `{"error":"auth not configured"}`, http.StatusServiceUnavailable)
			})
		}
		return Auth.Require()(next)
	}

	authUserFromContext = goauth.UserFromContext

	authValidateCurrentPassword = func(username, password string) error {
		if Auth == nil || Auth.Users == nil {
			return errors.New("auth not configured")
		}
		_, err := Auth.Users.Authenticate(username, password)
		return err
	}

	authSetPassword = func(username, newPassword string) error {
		if Auth == nil || Auth.Users == nil {
			return errors.New("auth not configured")
		}
		return Auth.Users.SetPassword(username, newPassword)
	}

	// authKeepSession keeps the caller logged in after their own password
	// change. goauth's SetPassword ends every session of the user (that is
	// what makes a password change lock out a stolen session); without this
	// the user is logged out of the tab they changed it in as well.
	authKeepSession = func(r *http.Request) error {
		if Auth == nil {
			return errors.New("auth not configured")
		}
		return Auth.KeepSession(r)
	}

	authRegisterMeSecurityRoutes = func(manager *goauth.Manager, mux *http.ServeMux) bool {
		if manager == nil || mux == nil {
			return false
		}
		method := reflect.ValueOf(manager).MethodByName("RegisterMeSecurityRoutes")
		if !method.IsValid() {
			return false
		}
		method.Call([]reflect.Value{reflect.ValueOf(mux)})
		return true
	}
)

// passwordChangeLimiter counts current-password guesses on the password-change
// route. It has the login limiter's rules but its own state: the login
// limiter's lock is account-wide and anyone can set it by failing that
// account's /login ten times, and an owner who is logged in must still be able
// to change the password while someone is doing that.
var passwordChangeLimiter = newLoginRateLimiter()

func registerMeSecurityRoutes(mux *http.ServeMux) {
	if Auth != nil {
		authRegisterMeSecurityRoutes(Auth, mux)
	}
	registerFallbackPasswordRoute(mux)
}

func registerFallbackPasswordRoute(mux *http.ServeMux) {
	mux.Handle("/api/v1/me/password", authRequireAny(http.HandlerFunc(handleMePasswordChange)))
}

func handleMePasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req passwordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if strings.TrimSpace(req.CurrentPassword) == "" || strings.TrimSpace(req.NewPassword) == "" {
		writeJSONError(w, http.StatusBadRequest, "current_password and new_password are required")
		return
	}
	if len(req.NewPassword) < 12 {
		writeJSONError(w, http.StatusBadRequest, "new_password must be at least 12 characters")
		return
	}

	user, ok := authUserFromContext(r.Context())
	if !ok || strings.TrimSpace(user.Username) == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	// The current-password check is a password guess like any other, so it is
	// limited like a login (per IP and account: backoff, throttle, lock). It
	// had no limit: a stolen session could try passwords here as fast as
	// Argon2 allowed.
	ip := normalizeChallengeIP(realIPFromRequest(r))
	account := normalizeLoginUsername(user.Username)
	attempt := authAttemptAudit{Kind: "password_change", AuthMech: "session_cookie", User: account}
	decision := passwordChangeLimiter.Evaluate(ip, account)
	if !decision.Allow {
		attempt.Result, attempt.Status = "rate_limited", http.StatusTooManyRequests
		auditAuthAttempt(r, attempt)
		w.Header().Set("Retry-After", "60")
		writeJSONError(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}
	if decision.Delay > 0 && !sleepWithContext(r.Context(), decision.Delay) {
		return
	}
	if err := authValidateCurrentPassword(user.Username, req.CurrentPassword); err != nil {
		passwordChangeLimiter.ObserveResult(ip, account, false)
		attempt.Result, attempt.Status = "fail", http.StatusUnauthorized
		auditAuthAttempt(r, attempt)
		writeJSONError(w, http.StatusUnauthorized, "current password is invalid")
		return
	}
	passwordChangeLimiter.ObserveResult(ip, account, true)
	if err := authSetPassword(user.Username, req.NewPassword); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("password update failed: %v", err))
		return
	}
	if err := authKeepSession(r); err != nil {
		// The password is changed; the worst case is that this tab has to log
		// in again with it.
		logging.LogfAPI("[apiserver] password changed for %q but the session could not be kept: %v", user.Username, err)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
