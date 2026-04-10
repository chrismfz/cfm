// internal/apiserver/login.go
//
// Login, logout, and 2FA stub route handlers for the cfm admin UI.
//
// Routes registered (all public — no auth guard):
//   GET  /login          → login form HTML
//   POST /login          → goauth credential check → session → redirect
//   GET  /logout         → destroy session → redirect /login
//   POST /logout         → same
//   GET  /login/verify   → 2FA stub (wired when goauth adds TOTP)
//   POST /login/verify   → 2FA stub
//
// The login form POSTs JSON via fetch(). On success goauth sets the session
// cookie and the JS redirects to ?next= (default /). On failure the error
// is shown inline. If the server ever returns requires_2fa:true the JS
// redirects to /login/verify (future TOTP flow).

package apiserver

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strconv"
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
      if(d.requires_2fa){location.href=basePath+'/login/verify?next='+encodeURIComponent(next);return}
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

// verifyHTML is a stub for the 2FA verification page.
// Will be replaced with a real TOTP form when goauth adds TOTP support.
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
  <p class="note">2FA is not yet configured on this server.</p>
  <p class="note"><a href="__LOGOUT_PATH__">Return to login</a></p>
</div>
</body>
</html>`

// RegisterLoginRoutes adds all public auth routes to the mux.
// Must be called before any auth middleware wraps the mux.
func RegisterLoginRoutes(m *http.ServeMux) {
	// GET /login → login form
	// POST /login → goauth credential handler
	m.HandleFunc("/login", handleLogin)

	// GET+POST /logout → destroy session
	m.HandleFunc("/logout", handleLogout)

	// GET+POST /login/verify → 2FA stub
	m.HandleFunc("/login/verify", handleLoginVerify)
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
		if Auth == nil {
			http.Error(w, `{"error":"auth not configured"}`, http.StatusServiceUnavailable)
			return
		}
		// goauth.LoginHandler() reads JSON body, validates credentials,
		// creates session, returns JSON {username, roles} on success.
		Auth.LoginHandler()(w, r)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if Auth != nil {
		Auth.Destroy(r) // destroys session, writes nothing to response
	}
	base := cfmBase(r)
	http.Redirect(w, r, fmt.Sprintf("%s/login", base), http.StatusSeeOther)
}

func handleLoginVerify(w http.ResponseWriter, r *http.Request) {
	// Stub: render 2FA page for GET, return not-implemented for POST.
	// Will be replaced with real TOTP handling when goauth adds support.
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		base := cfmBase(r)
		logoutPath := html.EscapeString(fmt.Sprintf("%s/logout", base))
		page := strings.ReplaceAll(verifyHTML, "__LOGOUT_PATH__", logoutPath)
		_, _ = w.Write([]byte(page))
	case http.MethodPost:
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"2FA not yet configured"}`, http.StatusNotImplemented)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// isBrowser returns true if the request looks like a browser (not an API client).
func isBrowser(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}
