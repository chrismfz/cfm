package apiserver

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chrismfz/goauth"
)

// Through the real goauth routes as cfm mounts them: starting an enrollment
// answers with a QR image made on the node.
func TestTOTPEnrollStart_AnswersWithALocalQRCode(t *testing.T) {
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
	origAuth := Auth
	Auth = mgr
	t.Cleanup(func() { Auth = origAuth })

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

	// A refusal passes through untouched.
	if rr := post(totpEnrollStartPath, `{}`); rr.Code != http.StatusUnauthorized || strings.Contains(rr.Body.String(), "qr_data_url") {
		t.Fatalf("start without the password: %d %s, want goauth's 401", rr.Code, rr.Body.String())
	}

	rr := post(totpEnrollStartPath, `{"password":"`+password+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("start: %d %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store (the body carries the secret)", got)
	}
	var resp struct {
		URI string `json:"otpauth_uri"`
		QR  string `json:"qr_data_url"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v: %s", err, rr.Body.String())
	}
	if !strings.HasPrefix(resp.URI, "otpauth://totp/") {
		t.Fatalf("otpauth_uri = %q", resp.URI)
	}
	raw, ok := strings.CutPrefix(resp.QR, "data:image/png;base64,")
	if !ok {
		t.Fatalf("qr_data_url = %.40q, want a PNG data URL", resp.QR)
	}
	pngBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("qr_data_url is not base64: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatalf("qr_data_url is not a PNG: %v", err)
	}
	want, px, err := totpQRImage(resp.URI)
	if err != nil {
		t.Fatalf("totpQRImage: %v", err)
	}
	if img.Bounds() != want.Bounds() {
		t.Fatalf("QR image is %v, want %v", img.Bounds(), want.Bounds())
	}
	side, margin := img.Bounds().Dx(), totpQRQuietModules*px
	// White quiet zone all round, the dark corner of a finder pattern just
	// inside it at three corners (and not at the fourth).
	isDark := func(x, y int) bool {
		r, g, b, _ := color.RGBAModel.Convert(img.At(x, y)).RGBA()
		return r+g+b < 3*0x8000
	}
	for i := 0; i < side; i++ {
		if isDark(i, margin-1) || isDark(margin-1, i) || isDark(i, side-margin) || isDark(side-margin, i) {
			t.Fatalf("the quiet zone is not white at offset %d", i)
		}
	}
	in, far := margin+px/2, side-margin-1-px/2
	if !isDark(in, in) || !isDark(far, in) || !isDark(in, far) {
		t.Fatal("finder patterns are not at the three corners of the code")
	}
	if out := os.Getenv("CFM_TEST_QR_OUT"); out != "" { // for a manual scan of the result
		_ = os.WriteFile(out, pngBytes, 0o600)
		_ = os.WriteFile(out+".uri", []byte(resp.URI), 0o600)
	}
}

func TestTOTPQRDataURL_RefusesAnythingButAnOTPAuthURI(t *testing.T) {
	for _, in := range []string{"", "https://example.com/", "otpauth://totp/x?secret=" + strings.Repeat("A", 2000)} {
		if _, err := totpQRDataURL(in); err == nil {
			t.Errorf("totpQRDataURL(%.30q) = nil error, want a refusal", in)
		}
	}
}

// The other account-security routes still answer through the mount.
func TestMeSecurityMount_PassesOtherRoutesThrough(t *testing.T) {
	routes := http.NewServeMux()
	routes.HandleFunc("GET /me/security/factors", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"has_totp":false}`))
	})
	rr := httptest.NewRecorder()
	meSecurityHandler(routes).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://host/me/security/factors", nil))
	if rr.Code != http.StatusOK || rr.Body.String() != `{"has_totp":false}` {
		t.Fatalf("factors through the mount: %d %s", rr.Code, rr.Body.String())
	}
}
