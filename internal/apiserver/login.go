// internal/apiserver/login.go
//
// Login, logout, and MFA route handlers for the cfm admin UI.
//
// Routes registered (all public — no auth guard):
//   GET  /login                   → login form HTML
//   POST /login                   → goauth credential check → session → redirect/JSON
//   GET  /logout                  → destroy session → redirect /login
//   POST /logout                  → same
//   GET  /login/verify            → MFA verification form HTML
//   POST /login/verify            → goauth MFA verify handler
//   POST /login/webauthn/begin    → optional passkey begin
//   POST /login/webauthn/finish   → optional passkey finish

package apiserver

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
)

// Matches the admin UI theme in internal/webui/static/assets/style.css
// (dark palette; the login page deliberately stays single-theme).
const loginCSS = `
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:#141b2d;color:#e9eef6;font-family:Inter,system-ui,-apple-system,'Segoe UI',sans-serif;
  display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#1a2338;border:1px solid #2c3b58;border-radius:12px;padding:2rem;
  width:100%;max-width:380px;box-shadow:0 10px 30px rgba(4,10,25,.35)}
.logo{text-align:center;margin-bottom:1.5rem}
.logo .mark{display:inline-grid;place-items:center;width:44px;height:44px;border-radius:10px;
  background:rgba(77,163,255,.14);color:#6db4ff;font-size:1.5rem;margin-bottom:.6rem}
.logo h1{font-size:1.25rem;color:#e9eef6;letter-spacing:.04em;font-weight:700}
.logo p{font-size:.75rem;color:#9aa9c0;margin-top:.25rem;letter-spacing:.06em}
label{display:block;font-size:.8rem;color:#9aa9c0;margin-bottom:.35rem}
input[type=text],input[type=password],select{width:100%;background:#0f1626;
  border:1px solid #2c3b58;border-radius:8px;color:#e9eef6;font-family:inherit;
  font-size:.9rem;padding:.55rem .75rem;margin-bottom:1rem;outline:none;
  transition:border-color .15s}
input:focus,select:focus{border-color:#4da3ff}
button{width:100%;background:#4da3ff;border:none;border-radius:8px;color:#fff;
  cursor:pointer;font-family:inherit;font-size:.9rem;font-weight:600;padding:.6rem;
  transition:filter .15s}
button:hover{filter:brightness(1.08)}
button:disabled{cursor:default;opacity:.6;filter:none}
.err{background:rgba(229,100,127,.13);border:1px solid #e5647f;border-radius:8px;color:#e5647f;
  font-size:.8rem;margin-bottom:1rem;padding:.5rem .75rem;display:none}
.err.on{display:block}
a{color:#6db4ff;text-decoration:none}
a:hover{text-decoration:underline}
.note{color:#9aa9c0;font-size:.85rem;text-align:center;margin-bottom:1rem}
`

const loginFaviconLink = `<link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20viewBox=%270%200%2032%2032%27%3E%3Crect%20width=%2732%27%20height=%2732%27%20rx=%277%27%20fill=%27%23141b2d%27/%3E%3Cpath%20d=%27M16%206l8.7%205v10L16%2026l-8.7-5V11z%27%20fill=%27none%27%20stroke=%27%234da3ff%27%20stroke-width=%272.4%27/%3E%3C/svg%3E" />`

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CFM — Sign in</title>
`+loginFaviconLink+`
<style>` + loginCSS + `</style>
</head>
<body>
<div class="card">
  <div class="logo"><span class="mark">⬡</span><h1>CFM</h1><p>FIREWALL MANAGER</p></div>
  <div class="err" id="err"></div>
  <form id="loginForm">
    <label for="u">Username</label>
    <input type="text" id="u" name="username" autocomplete="username" autofocus>
    <label for="p">Password</label>
    <input type="password" id="p" name="password" autocomplete="current-password">
    <button id="btn" type="submit">Sign in</button>
  </form>
</div>
<script>
const basePath=__BASE_PATH__;
const mfaVerifyEnabled=__MFA_VERIFY_ENABLED__;
const defaultNext=(basePath&&basePath!=='/')?(basePath+'/'):'/';
const next=new URLSearchParams(location.search).get('next')||defaultNext;
function showErr(m){const e=document.getElementById('err');e.textContent=m;e.classList.add('on')}
async function go(){
  const btn=document.getElementById('btn');
  btn.disabled=true;btn.textContent='Signing in…';
  document.getElementById('err').classList.remove('on');
  try{
    const r=await fetch(basePath+'/login',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:document.getElementById('u').value,
                           password:document.getElementById('p').value})});
    if(r.ok){
      const d=await r.json().catch(()=>({}));
      if((d.requires_2fa||d.mfa_required) && mfaVerifyEnabled){location.href=basePath+'/login/verify?next='+encodeURIComponent(next);return}
      location.href=next;return;
    }
    const d=await r.json().catch(()=>({}));
    showErr(r.status===429?'Too many attempts. Try again later.':(d.error||'Invalid credentials.'));
  }catch(e){showErr('Connection error.');}
  btn.disabled=false;btn.textContent='Sign in';
}
document.getElementById('loginForm').addEventListener('submit',e=>{e.preventDefault();go()});
</script>
</body>
</html>`

const verifyHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CFM — Two-Factor Auth</title>
`+loginFaviconLink+`
<style>` + loginCSS + `</style>
</head>
<body>
<div class="card">
  <div class="logo"><span class="mark">⬡</span><h1>CFM</h1><p>TWO-FACTOR AUTHENTICATION</p></div>
  <div class="err" id="err"></div>
  <label for="method">Method</label>
  <select id="method">
    <option value="totp">Authenticator app (TOTP)</option>
    <option value="recovery_code">Recovery code</option>
  </select>
  <label for="code">Code</label>
  <input type="text" id="code" autocomplete="one-time-code" autofocus>
  <button id="btn" onclick="verify()">Verify</button>
  <p class="note" style="margin-top:1rem"><a href="__LOGOUT_PATH__">Sign out</a></p>
</div>
<script>
const basePath=__BASE_PATH__;
const next=__NEXT__;
function showErr(m){const e=document.getElementById('err');e.textContent=m;e.classList.add('on')}
async function verify(){
  const btn=document.getElementById('btn');
  btn.disabled=true;btn.textContent='Verifying…';
  document.getElementById('err').classList.remove('on');
  try{
    const r=await fetch(basePath+'/login/verify',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({method:document.getElementById('method').value,code:document.getElementById('code').value})});
    if(r.ok){location.href=next;return}
    const d=await r.json().catch(()=>({}));
    showErr(d.error||'Invalid verification code.');
  }catch(e){showErr('Connection error.');}
  btn.disabled=false;btn.textContent='Verify';
}
document.addEventListener('keydown',e=>{if(e.key==='Enter')verify()});
</script>
</body>
</html>`

var (
	authLoginHandler = func() http.HandlerFunc {
		if Auth == nil {
			return nil
		}
		return Auth.LoginHandler()
	}
	authLoginMFAVerifyHandler = func() http.HandlerFunc { return authHandlerByName("LoginMFAVerifyHandler") }
	authLoginWebAuthnBegin    = func() http.HandlerFunc { return authHandlerByName("LoginWebAuthnBeginHandler") }
	authLoginWebAuthnFinish   = func() http.HandlerFunc { return authHandlerByName("LoginWebAuthnFinishHandler") }
)

// RegisterLoginRoutes adds all public auth routes to the mux.
// Must be called before any auth middleware wraps the mux.
func RegisterLoginRoutes(m *http.ServeMux) {
	m.HandleFunc("/login", handleLogin)
	m.HandleFunc("/logout", handleLogout)
	m.HandleFunc("/login/verify", handleLoginVerify)
	m.HandleFunc("/login/webauthn/begin", handleLoginWebAuthnBegin)
	m.HandleFunc("/login/webauthn/finish", handleLoginWebAuthnFinish)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		base := cfmBase(r)
		baseJSON, err := json.Marshal(base)
		if err != nil {
			baseJSON = []byte(`""`)
		}
		page := strings.ReplaceAll(loginHTML, "__BASE_PATH__", string(baseJSON))
		page = strings.ReplaceAll(page, "__MFA_VERIFY_ENABLED__", string(mustJSON(mfaLoginVerifyEnabled())))
		_, _ = w.Write([]byte(page))

	case http.MethodPost:
		username := loginAttemptUsername(r)
		if !protectLoginAttempt(w, r, username) {
			return
		}

		h := authLoginHandler()
		if h == nil {
			http.Error(w, `{"error":"auth not configured"}`, http.StatusServiceUnavailable)
			return
		}

		rec := httptest.NewRecorder()
		h(rec, r)
		recordLoginLimiterResult(r, username, rec.Code)

		if isBrowser(r) && mfaLoginVerifyEnabled() && isMFARequiredResponse(rec.Body.Bytes()) {
			base := cfmBase(r)
			next := loginRedirectNext(r, base)
			http.Redirect(w, r, fmt.Sprintf("%s/login/verify?next=%s", base, url.QueryEscape(next)), http.StatusSeeOther)
			return
		}
		copyRecorderResponse(w, rec)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if Auth != nil {
		Auth.Destroy(r)
	}
	base := cfmBase(r)
	http.Redirect(w, r, fmt.Sprintf("%s/login", base), http.StatusSeeOther)
}

func handleLoginVerify(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !mfaLoginVerifyEnabled() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		base := cfmBase(r)
		logoutPath := html.EscapeString(fmt.Sprintf("%s/logout", base))
		nextJSON, err := json.Marshal(loginRedirectNext(r, base))
		if err != nil {
			nextJSON = []byte(`"/"`)
		}
		page := strings.ReplaceAll(verifyHTML, "__LOGOUT_PATH__", logoutPath)
		page = strings.ReplaceAll(page, "__BASE_PATH__", string(mustJSON(base)))
		page = strings.ReplaceAll(page, "__NEXT__", string(nextJSON))
		_, _ = w.Write([]byte(page))
	case http.MethodPost:
		if !mfaLoginVerifyEnabled() {
			http.Error(w, `{"error":"mfa verify disabled by rollout"}`, http.StatusNotFound)
			return
		}
		h := authLoginMFAVerifyHandler()
		if h == nil {
			http.Error(w, `{"error":"mfa verify not supported"}`, http.StatusNotFound)
			return
		}
		h(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleLoginWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	h := authLoginWebAuthnBegin()
	if h == nil {
		http.NotFound(w, r)
		return
	}
	h(w, r)
}

func handleLoginWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	h := authLoginWebAuthnFinish()
	if h == nil {
		http.NotFound(w, r)
		return
	}
	h(w, r)
}

func authHandlerByName(name string) http.HandlerFunc {
	if Auth == nil {
		return nil
	}
	method := reflect.ValueOf(Auth).MethodByName(name)
	if !method.IsValid() {
		return nil
	}
	vals := method.Call(nil)
	if len(vals) != 1 {
		return nil
	}
	h, _ := vals[0].Interface().(http.HandlerFunc)
	return h
}

func copyRecorderResponse(dst http.ResponseWriter, src *httptest.ResponseRecorder) {
	for k, vv := range src.Header() {
		for _, v := range vv {
			dst.Header().Add(k, v)
		}
	}
	dst.WriteHeader(src.Code)
	_, _ = io.Copy(dst, src.Body)
}

func isMFARequiredResponse(body []byte) bool {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	if b, ok := payload["mfa_required"].(bool); ok && b {
		return true
	}
	if b, ok := payload["requires_2fa"].(bool); ok && b {
		return true
	}
	if mfaRaw, ok := payload["mfa"].(map[string]any); ok {
		if b, ok := mfaRaw["required"].(bool); ok && b {
			return true
		}
	}
	return false
}

func loginRedirectNext(r *http.Request, base string) string {
	next := strings.TrimSpace(r.URL.Query().Get("next"))
	if next == "" {
		if ref, err := url.Parse(r.Referer()); err == nil {
			next = strings.TrimSpace(ref.Query().Get("next"))
		}
	}
	if next == "" {
		if base == "" {
			return "/"
		}
		return base + "/"
	}
	if !strings.HasPrefix(next, "/") {
		if base == "" {
			return "/"
		}
		return base + "/"
	}
	// Prevent redirect loops back into auth routes.
	if u, err := url.Parse(next); err == nil {
		p := u.Path
		if p == "/login" || p == "/login/verify" || strings.HasSuffix(p, "/login") || strings.HasSuffix(p, "/login/verify") {
			if base == "" {
				return "/"
			}
			return base + "/"
		}
	}
	return next
}

// isBrowser returns true if the request looks like a browser (not an API client).
func isBrowser(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}
