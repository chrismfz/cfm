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

const loginCSS = `
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:'SF Mono',Consolas,'Liberation Mono',monospace;
  display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:2rem;
  width:100%;max-width:360px}
.logo{text-align:center;margin-bottom:1.5rem}
.logo h1{font-size:1.4rem;color:#58a6ff;letter-spacing:.1em}
.logo p{font-size:.75rem;color:#8b949e;margin-top:.25rem}
label{display:block;font-size:.8rem;color:#8b949e;margin-bottom:.35rem}
input[type=text],input[type=password],input[type=text]{width:100%;background:#0d1117;
  border:1px solid #30363d;border-radius:4px;color:#c9d1d9;font-family:inherit;
  font-size:.9rem;padding:.5rem .75rem;margin-bottom:1rem;outline:none;
  transition:border-color .15s}
input:focus{border-color:#58a6ff}
button{width:100%;background:#238636;border:none;border-radius:4px;color:#fff;
  cursor:pointer;font-family:inherit;font-size:.9rem;padding:.6rem;
  transition:background .15s}
button:hover{background:#2ea043}
button:disabled{background:#1f6328;cursor:default;opacity:.7}
.err{background:#3d1f1f;border:1px solid #8b2020;border-radius:4px;color:#f85149;
  font-size:.8rem;margin-bottom:1rem;padding:.5rem .75rem;display:none}
.err.on{display:block}
a{color:#58a6ff;text-decoration:none}
a:hover{text-decoration:underline}
.note{color:#8b949e;font-size:.85rem;text-align:center;margin-bottom:1rem}
`

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CFM — Sign in</title>
<style>` + loginCSS + `</style>
</head>
<body>
<div class="card">
  <div class="logo"><h1>⬡ CFM</h1><p>Firewall Manager</p></div>
  <div class="err" id="err"></div>
  <label for="u">Username</label>
  <input type="text" id="u" autocomplete="username" autofocus>
  <label for="p">Password</label>
  <input type="password" id="p" autocomplete="current-password">
  <button id="btn" onclick="go()">Sign in</button>
</div>
<script>
const basePath=__BASE_PATH__;
const next=new URLSearchParams(location.search).get('next')||'/';
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
      if(d.requires_2fa||d.mfa_required){location.href=basePath+'/login/verify?next='+encodeURIComponent(next);return}
      location.href=next;return;
    }
    const d=await r.json().catch(()=>({}));
    showErr(r.status===429?'Too many attempts. Try again later.':(d.error||'Invalid credentials.'));
  }catch(e){showErr('Connection error.');}
  btn.disabled=false;btn.textContent='Sign in';
}
document.addEventListener('keydown',e=>{if(e.key==='Enter')go()});
</script>
</body>
</html>`

const verifyHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CFM — Two-Factor Auth</title>
<style>` + loginCSS + `</style>
</head>
<body>
<div class="card">
  <div class="logo"><h1>⬡ CFM</h1><p>Two-Factor Authentication</p></div>
  <div class="err" id="err"></div>
  <label for="method">Method</label>
  <select id="method" style="width:100%;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#c9d1d9;font-family:inherit;font-size:.9rem;padding:.5rem .75rem;margin-bottom:1rem;outline:none;">
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
		_, _ = w.Write([]byte(page))

	case http.MethodPost:
		h := authLoginHandler()
		if h == nil {
			http.Error(w, `{"error":"auth not configured"}`, http.StatusServiceUnavailable)
			return
		}

		rec := httptest.NewRecorder()
		h(rec, r)
		recordLoginAttemptResult(r, rec.Code)

		if isBrowser(r) && isMFARequiredResponse(rec.Body.Bytes()) {
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
