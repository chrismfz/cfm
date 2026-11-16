package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	origKeep := authKeepSession
	origLimiter := passwordChangeLimiter
	passwordChangeLimiter = newLoginRateLimiter()
	t.Cleanup(func() {
		authRequireAny = origRequire
		authUserFromContext = origUserFromContext
		authValidateCurrentPassword = origValidate
		authSetPassword = origSet
		authKeepSession = origKeep
		passwordChangeLimiter = origLimiter
	})
	// goauth ends every session of the user on a password change; the one
	// that made the change must be kept.
	kept := false
	authKeepSession = func(*http.Request) error { kept = true; return nil }

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
	if !kept {
		t.Fatalf("the session that changed the password was not kept")
	}
}

// The current-password check is a password guess: it runs out like a login's
// does, and a refused guess neither sets a password nor touches the session.
func TestHandleMePasswordChange_LimitsWrongGuesses(t *testing.T) {
	origRequire := authRequireAny
	origUserFromContext := authUserFromContext
	origValidate := authValidateCurrentPassword
	origSet := authSetPassword
	origKeep := authKeepSession
	origLimiter := passwordChangeLimiter
	limiter := newLoginRateLimiter()
	// Each read of the clock is six minutes on: past the adaptive backoff's
	// 5-minute memory (so the test does not sleep) and inside the 10-minute
	// lock that the tenth failure sets. The failure count alone decides.
	clock := time.Now()
	limiter.now = func() time.Time { clock = clock.Add(6 * time.Minute); return clock }
	passwordChangeLimiter = limiter
	t.Cleanup(func() {
		authRequireAny = origRequire
		authUserFromContext = origUserFromContext
		authValidateCurrentPassword = origValidate
		authSetPassword = origSet
		authKeepSession = origKeep
		passwordChangeLimiter = origLimiter
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
	guesses := 0
	authValidateCurrentPassword = func(string, string) error { guesses++; return errors.New("wrong") }
	authSetPassword = func(string, string) error { t.Fatal("password set after a wrong guess"); return nil }
	authKeepSession = func(*http.Request) error { t.Fatal("session touched after a wrong guess"); return nil }

	mux := http.NewServeMux()
	registerFallbackPasswordRoute(mux)
	post := func() int {
		req := httptest.NewRequest(http.MethodPost, "https://host/api/v1/me/password",
			bytes.NewBufferString(`{"current_password":"a guess","new_password":"new-password-123"}`))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr.Code
	}
	for i := 0; i < loginLockThreshold; i++ {
		if code := post(); code != http.StatusUnauthorized {
			t.Fatalf("guess %d: status %d, want 401", i, code)
		}
	}
	if code := post(); code != http.StatusTooManyRequests {
		t.Fatalf("guess past the lock threshold: status %d, want 429", code)
	}
	if guesses != loginLockThreshold {
		t.Fatalf("password checked %d times, want %d (none once locked)", guesses, loginLockThreshold)
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
