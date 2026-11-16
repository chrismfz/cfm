package apiserver

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/chrismfz/goauth"
)

// End to end against a real goauth manager: changing your own password in
// Settings keeps the tab you did it in and logs every other session out.
func TestMePasswordChange_KeepsThisSessionEndsOthers(t *testing.T) {
	const oldPassword, newPassword = "the old password!", "the new password!"

	mgr, err := goauth.New(goauth.Config{
		DBPath:           filepath.Join(t.TempDir(), "auth.db"),
		MFAEncryptionKey: "0123456789abcdef",
		CookieName:       "sid",
	})
	if err != nil {
		t.Fatalf("goauth.New: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	if err := mgr.Users.Create("alice", oldPassword, []string{"admin"}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	origAuth, origLimiter, origLogin := Auth, passwordChangeLimiter, globalLoginRateLimiter
	Auth, passwordChangeLimiter, globalLoginRateLimiter = mgr, newLoginRateLimiter(), newLoginRateLimiter()
	t.Cleanup(func() { Auth, passwordChangeLimiter, globalLoginRateLimiter = origAuth, origLimiter, origLogin })

	mux := http.NewServeMux()
	mux.Handle("/login", mgr.LoginHandler())
	registerFallbackPasswordRoute(mux)
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		if !sessionAllowed(r) {
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	srv := mgr.LoadAndSave(mux)

	type browser struct{ cookie *http.Cookie }
	do := func(b *browser, method, path, body string) int {
		req := httptest.NewRequest(method, "https://host"+path, bytes.NewBufferString(body))
		if b.cookie != nil {
			req.AddCookie(b.cookie)
		}
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		for _, c := range rr.Result().Cookies() {
			if c.Name == "sid" {
				b.cookie = c
			}
		}
		return rr.Code
	}
	login := func(password string) *browser {
		b := &browser{}
		if code := do(b, http.MethodPost, "/login", `{"username":"alice","password":"`+password+`"}`); code != http.StatusOK {
			t.Fatalf("login with %q: status %d", password, code)
		}
		return b
	}

	here, elsewhere := login(oldPassword), login(oldPassword)

	// Someone failing alice's /login until the account is locked there must
	// not stop alice, who is logged in, from changing the password.
	for i := 0; i < loginLockThreshold; i++ {
		globalLoginRateLimiter.ObserveResult("203.0.113.9", "alice", false)
	}
	if d := globalLoginRateLimiter.Evaluate("203.0.113.9", "alice"); d.Allow {
		t.Fatalf("test setup: the login limiter did not lock the account")
	}
	if code := do(here, http.MethodPost, "/api/v1/me/password",
		`{"current_password":"`+oldPassword+`","new_password":"`+newPassword+`"}`); code != http.StatusOK {
		t.Fatalf("password change: status %d", code)
	}
	if code := do(here, http.MethodGet, "/whoami", ""); code != http.StatusOK {
		t.Fatalf("the session that changed the password: status %d, want 200", code)
	}
	if code := do(elsewhere, http.MethodGet, "/whoami", ""); code != http.StatusUnauthorized {
		t.Fatalf("another session after the password change: status %d, want 401", code)
	}
	login(newPassword)
}
