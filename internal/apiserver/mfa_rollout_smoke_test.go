package apiserver

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	cfgpkg "cfm/internal/config"
	"github.com/chrismfz/goauth"
)

func TestSmoke_AdminLoginAndVerifyRoutesUnderCFMAdminPrefix(t *testing.T) {
	origPolicy := activeMFARolloutPolicy
	t.Cleanup(func() { activeMFARolloutPolicy = origPolicy })
	activeMFARolloutPolicy.loginVerifyEnabled = true

	m := http.NewServeMux()
	RegisterLoginRoutes(m)
	m.HandleFunc("/cfm-admin/", func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		r2.URL.Path = strings.TrimPrefix(r.URL.Path, "/cfm-admin")
		if r2.URL.Path == "" {
			r2.URL.Path = "/"
		}
		m.ServeHTTP(w, r2)
	})

	loginReq := httptest.NewRequest(http.MethodGet, "https://host/cfm-admin/login", nil)
	loginRR := httptest.NewRecorder()
	m.ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("expected login GET 200, got %d", loginRR.Code)
	}

	verifyReq := httptest.NewRequest(http.MethodGet, "https://host/cfm-admin/login/verify", nil)
	verifyRR := httptest.NewRecorder()
	m.ServeHTTP(verifyRR, verifyReq)
	if verifyRR.Code != http.StatusOK {
		t.Fatalf("expected verify GET 200, got %d", verifyRR.Code)
	}
}

func TestSmoke_BearerTokenAPIUnaffectedByMFARollout(t *testing.T) {
	store := NewTokenStore()
	m := http.NewServeMux()
	m.HandleFunc("/api/v1/system/status", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	origPolicy := activeMFARolloutPolicy
	t.Cleanup(func() { activeMFARolloutPolicy = origPolicy })
	activeMFARolloutPolicy = mfaRolloutPolicy{loginVerifyEnabled: false}

	h := TokenMiddleware("admin-token", store)(m)

	req := httptest.NewRequest(http.MethodGet, "https://host/api/v1/system/status", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected bearer route success, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSetMFARolloutPolicyFromConfig(t *testing.T) {
	origPolicy := activeMFARolloutPolicy
	t.Cleanup(func() { activeMFARolloutPolicy = origPolicy })

	cfg := &cfgpkg.Config{}
	cfg.Debug.AuthMFALoginVerifyEnabled = false
	setMFARolloutPolicyFromConfig(cfg)
	if mfaLoginVerifyEnabled() {
		t.Fatal("expected login verify disabled from config")
	}
	cfg.Debug.AuthMFALoginVerifyEnabled = true
	setMFARolloutPolicyFromConfig(cfg)
	if !mfaLoginVerifyEnabled() {
		t.Fatal("expected login verify enabled from config")
	}
}

// The enrollment gate is retired: whatever the two old keys say, enrollment
// answers. (It never did anything else: the gate matched paths enrollment is
// not served at. This pins that the keys now change nothing on purpose.)
func TestRetiredTOTPEnrollKeysDoNotGateEnrollment(t *testing.T) {
	const password = "a long enough password"
	mgr, err := goauth.New(goauth.Config{
		DBPath:           filepath.Join(t.TempDir(), "auth.db"),
		MFAEncryptionKey: "0123456789abcdef",
		CookieName:       "sid",
	})
	if err != nil {
		t.Fatalf("goauth.New: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	if err := mgr.Users.Create("alice", password, nil); err != nil {
		t.Fatalf("create user: %v", err)
	}
	origAuth, origPolicy := Auth, activeMFARolloutPolicy
	Auth = mgr
	t.Cleanup(func() { Auth, activeMFARolloutPolicy = origAuth, origPolicy })

	// As a node that kept the shipped defaults: enrollment "off", and a
	// pilot list alice is not on.
	cfg := &cfgpkg.Config{}
	cfg.Debug.AuthMFALoginVerifyEnabled = true
	cfg.Debug.AuthMFATOTPEnrollEnabled = false
	cfg.Debug.AuthMFATOTPPilotUsers = []string{"somebody-else"}
	cfg.Debug.AuthMFATOTPEnrollKeysSet = true
	setMFARolloutPolicyFromConfig(cfg)

	mux := http.NewServeMux()
	mux.Handle("/login", mgr.LoginHandler())
	registerMeSecurityRoutes(mux)
	srv := mgr.LoadAndSave(mux)

	var cookie *http.Cookie
	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "https://host"+path, strings.NewReader(body))
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		for _, c := range rr.Result().Cookies() {
			if c.Name == "sid" {
				cookie = c
			}
		}
		return rr
	}
	if rr := post("/login", `{"username":"alice","password":"`+password+`"}`); rr.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rr.Code, rr.Body.String())
	}
	if rr := post(totpEnrollStartPath, `{"password":"`+password+`"}`); rr.Code != http.StatusOK {
		t.Fatalf("enrollment start with the retired keys set against it: %d %s, want 200", rr.Code, rr.Body.String())
	}
}
