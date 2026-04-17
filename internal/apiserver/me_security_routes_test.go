package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chrismfz/goauth"
)

func TestRegisterMeSecurityRoutes_RegistersFallbackPasswordEndpoint(t *testing.T) {
	origAuth := Auth
	origRegister := authRegisterMeSecurityRoutes
	t.Cleanup(func() {
		Auth = origAuth
		authRegisterMeSecurityRoutes = origRegister
	})

	Auth = nil
	called := false
	authRegisterMeSecurityRoutes = func(_ *goauth.Manager, _ *http.ServeMux) bool {
		called = true
		return true
	}

	mux := http.NewServeMux()
	registerMeSecurityRoutes(mux)

	if called {
		t.Fatalf("expected goauth me-security registrar not to run when Auth=nil")
	}

	req := httptest.NewRequest(http.MethodPost, "https://host/api/v1/me/password", bytes.NewBufferString(`{"current_password":"old","new_password":"123456789012"}`))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when auth is nil, got %d", rr.Code)
	}
}

func TestRegisterMeSecurityRoutes_CallsGoauthRegistrarWhenAvailable(t *testing.T) {
	origAuth := Auth
	origRegister := authRegisterMeSecurityRoutes
	t.Cleanup(func() {
		Auth = origAuth
		authRegisterMeSecurityRoutes = origRegister
	})

	Auth = &goauth.Manager{}
	called := false
	authRegisterMeSecurityRoutes = func(_ *goauth.Manager, _ *http.ServeMux) bool {
		called = true
		return true
	}

	mux := http.NewServeMux()
	registerMeSecurityRoutes(mux)

	if !called {
		t.Fatalf("expected goauth me-security route registrar to be called")
	}
}

func TestHandleMePasswordChange_HappyPath(t *testing.T) {
	origRequire := authRequireAny
	origUserFromContext := authUserFromContext
	origValidate := authValidateCurrentPassword
	origSet := authSetPassword
	t.Cleanup(func() {
		authRequireAny = origRequire
		authUserFromContext = origUserFromContext
		authValidateCurrentPassword = origValidate
		authSetPassword = origSet
	})

	authRequireAny = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), any("goauth_user"), &goauth.User{Username: "alice"})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	authUserFromContext = func(ctx context.Context) (*goauth.User, bool) {
		u, ok := ctx.Value(any("goauth_user")).(*goauth.User)
		return u, ok
	}
	authValidateCurrentPassword = func(username, password string) error {
		if username != "alice" || password != "old-password" {
			t.Fatalf("unexpected validation inputs username=%q password=%q", username, password)
		}
		return nil
	}
	authSetPassword = func(username, newPassword string) error {
		if username != "alice" || newPassword != "new-password-123" {
			t.Fatalf("unexpected set password inputs username=%q new=%q", username, newPassword)
		}
		return nil
	}

	mux := http.NewServeMux()
	registerFallbackPasswordRoute(mux)
	body := map[string]string{"current_password": "old-password", "new_password": "new-password-123"}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "https://host/api/v1/me/password", bytes.NewReader(b))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleMePasswordChange_RejectsUnauthorized(t *testing.T) {
	origRequire := authRequireAny
	t.Cleanup(func() { authRequireAny = origRequire })

	authRequireAny = func(_ http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		})
	}

	mux := http.NewServeMux()
	registerFallbackPasswordRoute(mux)
	req := httptest.NewRequest(http.MethodPost, "https://host/api/v1/me/password", bytes.NewBufferString(`{"current_password":"old-password","new_password":"new-password-123"}`))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}
