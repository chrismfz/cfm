package apiserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"

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

	if err := authValidateCurrentPassword(user.Username, req.CurrentPassword); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "current password is invalid")
		return
	}
	if err := authSetPassword(user.Username, req.NewPassword); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("password update failed: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
