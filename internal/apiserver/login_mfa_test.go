package apiserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func stubAuthHandlers(t *testing.T, login func() http.HandlerFunc, verify func() http.HandlerFunc) {
	t.Helper()
	origLogin := authLoginHandler
	origVerify := authLoginMFAVerifyHandler
	authLoginHandler = login
	authLoginMFAVerifyHandler = verify
	t.Cleanup(func() {
		authLoginHandler = origLogin
		authLoginMFAVerifyHandler = origVerify
	})
}

func withMFALoginVerifyEnabled(t *testing.T, enabled bool) {
	t.Helper()
	orig := activeMFARolloutPolicy
	activeMFARolloutPolicy.loginVerifyEnabled = enabled
	t.Cleanup(func() { activeMFARolloutPolicy = orig })
}

func TestHandleLoginPostPasswordOnlySuccess(t *testing.T) {
	stubAuthHandlers(t,
		func() http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"username":"alice","roles":["admin"]}`))
			}
		},
		nil,
	)

	req := httptest.NewRequest(http.MethodPost, "https://host/login", strings.NewReader(`{"username":"alice","password":"pw"}`))
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()

	handleLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d got %d", http.StatusOK, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"username":"alice"`) {
		t.Fatalf("expected passthrough body, got %q", rr.Body.String())
	}
}

func TestHandleLoginPostMFARequiredBrowserRedirectsToVerify(t *testing.T) {
	withMFALoginVerifyEnabled(t, true)
	stubAuthHandlers(t,
		func() http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"mfa_required":true}`))
			}
		},
		nil,
	)

	req := httptest.NewRequest(http.MethodPost, "https://host/login?next=%2Fcfm-admin%2Flogin", strings.NewReader(`{"username":"alice","password":"pw"}`))
	req.RemoteAddr = "127.0.0.1:2345"
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Forwarded-Prefix", "/cfm-admin")
	rr := httptest.NewRecorder()

	handleLogin(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected %d got %d", http.StatusSeeOther, rr.Code)
	}
	if got, want := rr.Header().Get("Location"), "/cfm-admin/login/verify?next=%2Fcfm-admin%2F"; got != want {
		t.Fatalf("location mismatch\ngot:  %s\nwant: %s", got, want)
	}
}

func TestHandleLoginPostMFARequiredBrowserNoRedirectWhenVerifyRolloutDisabled(t *testing.T) {
	withMFALoginVerifyEnabled(t, false)
	stubAuthHandlers(t,
		func() http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"mfa_required":true}`))
			}
		},
		nil,
	)

	req := httptest.NewRequest(http.MethodPost, "https://host/login", strings.NewReader(`{"username":"alice","password":"pw"}`))
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()

	handleLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d got %d body=%s", http.StatusOK, rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Location"); got != "" {
		t.Fatalf("unexpected redirect location: %q", got)
	}
}

func TestHandleLoginVerifyPostValidMFACodeSuccess(t *testing.T) {
	withMFALoginVerifyEnabled(t, true)
	stubAuthHandlers(t,
		nil,
		func() http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				if string(b) != `{"method":"totp","code":"123456"}` {
					t.Fatalf("unexpected verify body: %q", string(b))
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"ok":true}`))
			}
		},
	)

	req := httptest.NewRequest(http.MethodPost, "https://host/login/verify", strings.NewReader(`{"method":"totp","code":"123456"}`))
	rr := httptest.NewRecorder()

	handleLoginVerify(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d got %d", http.StatusOK, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"ok":true`) {
		t.Fatalf("expected verify success body, got %q", rr.Body.String())
	}
}

func TestHandleLoginVerifyPostInvalidMFACodeFailure(t *testing.T) {
	withMFALoginVerifyEnabled(t, true)
	stubAuthHandlers(t,
		nil,
		func() http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, `{"error":"invalid mfa code"}`, http.StatusUnauthorized)
			}
		},
	)

	req := httptest.NewRequest(http.MethodPost, "https://host/login/verify", strings.NewReader(`{"method":"recovery_code","code":"bad"}`))
	rr := httptest.NewRecorder()

	handleLoginVerify(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d got %d", http.StatusUnauthorized, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `invalid mfa code`) {
		t.Fatalf("expected invalid mfa response, got %q", rr.Body.String())
	}
}

func TestHandleLoginVerifyDisabledByRollout(t *testing.T) {
	withMFALoginVerifyEnabled(t, false)

	getReq := httptest.NewRequest(http.MethodGet, "https://host/login/verify", nil)
	getRR := httptest.NewRecorder()
	handleLoginVerify(getRR, getReq)
	if getRR.Code != http.StatusNotFound {
		t.Fatalf("expected GET 404, got %d", getRR.Code)
	}

	postReq := httptest.NewRequest(http.MethodPost, "https://host/login/verify", strings.NewReader(`{"method":"totp","code":"123456"}`))
	postRR := httptest.NewRecorder()
	handleLoginVerify(postRR, postReq)
	if postRR.Code != http.StatusNotFound {
		t.Fatalf("expected POST 404, got %d", postRR.Code)
	}
}
