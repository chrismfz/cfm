package mcpserver

// oauth.go turns the embedded MCP endpoint into a minimal OAuth 2.1 authorization
// server so the claude.ai WEB "custom connector" (which authenticates a remote MCP
// server via OAuth, with no header field to paste a bearer into) can reach /mcp.
//
// It implements just the subset the MCP authorization spec requires: Protected
// Resource Metadata (RFC 9728), Authorization Server Metadata (RFC 8414), Dynamic
// Client Registration (RFC 7591), and an authorization-code + PKCE (S256) flow
// with refresh. It is deliberately self-contained and STATELESS: every artifact
// (client_id, authorization code, access/refresh token) is an HMAC-signed value
// re-verified without any store, so tokens survive restarts and rotating the
// signing secret invalidates them.
//
// Two deliberate CFM adaptations vs. a root-hosted OAuth server:
//   - The public base URL is derived PER REQUEST (scheme://host + /cfm-admin) via
//     baseFn, because CFM's MCP surface lives behind the OpenResty edge under the
//     /cfm-admin prefix. Every advertised URL (metadata, endpoints, resource,
//     token audience) therefore carries that prefix, and the claude.ai connector
//     discovers it via the WWW-Authenticate resource_metadata pointer (RFC 9728
//     §5.1) — no /.well-known routing at the host root is required.
//   - Consent is proven by pasting MCP_TOKEN (constant-time compare
//     via the Authenticate hook). The minted access_token is a read-only MCP
//     credential that is inert against /api/v1 (only the /mcp bearer gate honours
//     it); neither MCP_TOKEN nor the admin token is handed to the OAuth client.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

const (
	oauthProtectedResourcePath = "/.well-known/oauth-protected-resource"
	oauthASMetadataPath        = "/.well-known/oauth-authorization-server"
	// oauthOIDCMetadataPath is served as an alias of the RFC 8414 AS metadata.
	// The MCP spec advertises authorization-server metadata via RFC 8414
	// (oauth-authorization-server), but several OAuth clients — including the
	// claude.ai remote connector — probe the OIDC discovery URL
	// (openid-configuration) first when locating the registration/authorize/
	// token endpoints. Without this alias that probe hit the daemon and fell
	// through to a 401 (not a public path), which the client read as "auth
	// required to read discovery" and aborted registration. Serving the same
	// OAuth metadata here lets the OIDC-first probe succeed directly.
	oauthOIDCMetadataPath = "/.well-known/openid-configuration"
	oauthRegisterPath     = "/mcp/oauth/register"
	oauthAuthorizePath    = "/mcp/oauth/authorize"
	oauthTokenPath        = "/mcp/oauth/token"
)

// Authenticator validates the consent-page credential and reports whether it is
// accepted. CFM binds no per-subject identity (the minted token is simply
// "read-only MCP"), so subject is always "".
type Authenticator func(credential string) (subject string, ok bool)

// oauthServer is the in-binary OAuth authorization + resource-metadata provider.
type oauthServer struct {
	baseFn    func(*http.Request) string // externally reachable origin+prefix, per request
	clientIP  func(*http.Request) string // canonical identity supplied by the embedding server
	auditAuth func(*http.Request, AuthAuditEvent)
	mcpPath   string // MCP endpoint path under the prefix, e.g. "/mcp"
	auth      Authenticator
	prompt    string
	key       []byte // HMAC signing key derived from the server secret
	tpl       *template.Template

	accessTTL  time.Duration
	refreshTTL time.Duration
	codeTTL    time.Duration
	clientTTL  time.Duration

	// consumed makes authorization codes and refresh tokens single-use despite the
	// otherwise-stateless design: their nonce is recorded on first redemption and
	// re-presentation is rejected (OAuth 2.1 single-use codes + refresh-reuse
	// detection). Bounded + self-GCing; lost on restart (acceptable — codes live
	// 2 min, and a restart is a far bigger event than a replayed code).
	consumed *nonceCache

	// consentRL throttles consent-form submissions per source IP (brute-force /
	// log-abuse defence-in-depth on top of the MCP_TOKEN entropy).
	consentRL *ipRateLimiter
}

func newOAuthServer(baseFn, clientIP func(*http.Request) string, auditAuth func(*http.Request, AuthAuditEvent), mcpPath, signingSecret string, auth Authenticator) *oauthServer {
	return &oauthServer{
		baseFn:     baseFn,
		clientIP:   clientIP,
		auditAuth:  auditAuth,
		mcpPath:    mcpPath,
		auth:       auth,
		prompt:     "Paste your MCP_TOKEN to approve read-only access.",
		key:        deriveOAuthKey(signingSecret),
		tpl:        template.Must(template.New("authorize").Parse(authorizeHTML)),
		accessTTL:  time.Hour,
		refreshTTL: 7 * 24 * time.Hour,
		codeTTL:    2 * time.Minute,
		clientTTL:  10 * 365 * 24 * time.Hour,
		consumed:   newNonceCache(),
		consentRL:  &ipRateLimiter{},
	}
}

// nonceCache is a small, self-GCing set of consumed artifact nonces, keyed by
// nonce with a unix expiry so entries drop once the artifact would have expired
// anyway.
type nonceCache struct {
	mu   sync.Mutex
	seen map[string]int64
}

func newNonceCache() *nonceCache { return &nonceCache{seen: map[string]int64{}} }

// consume records nonce (valid until exp) and reports whether this was the FIRST
// time it was seen. A false return means replay.
func (c *nonceCache) consume(nonce string, exp int64) bool {
	if nonce == "" {
		return true // no nonce to enforce (older artifacts); fail open only for absence
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().Unix()
	for k, e := range c.seen {
		if e < now {
			delete(c.seen, k)
		}
	}
	if _, ok := c.seen[nonce]; ok {
		return false
	}
	c.seen[nonce] = exp
	return true
}

// base / resource / metadata URL are all derived from the incoming request so the
// advertised values match whatever hostname the operator actually uses.
func (s *oauthServer) base(r *http.Request) string     { return strings.TrimRight(s.baseFn(r), "/") }
func (s *oauthServer) resource(r *http.Request) string { return s.base(r) + s.mcpPath }
func (s *oauthServer) resourceMetadataURL(r *http.Request) string {
	return s.base(r) + oauthProtectedResourcePath
}

// register mounts all OAuth + discovery endpoints on mux. All are unauthenticated
// (they ARE the authentication); none touch protected data.
func (s *oauthServer) register(mux *http.ServeMux) {
	mux.HandleFunc(oauthProtectedResourcePath, s.handleProtectedResource)
	mux.HandleFunc(oauthASMetadataPath, s.handleASMetadata)
	mux.HandleFunc(oauthOIDCMetadataPath, s.handleASMetadata) // OIDC-discovery alias

	mux.HandleFunc(oauthRegisterPath, s.handleRegister)
	mux.HandleFunc(oauthAuthorizePath, s.handleAuthorize)
	mux.HandleFunc(oauthTokenPath, s.handleToken)
}

// validAccessToken reports whether presented is an unexpired access token this
// server minted for the resource derived from r (audience-bound, RFC 8707).
func (s *oauthServer) validAccessToken(presented string, r *http.Request) bool {
	c, ok := s.parse(presented)
	if !ok || c.Kind != "access" || oauthExpired(c) || c.Aud != s.resource(r) {
		return false
	}
	return true
}

// ── metadata (RFC 9728 / RFC 8414) ───────────────────────────────────────────

func (s *oauthServer) handleProtectedResource(w http.ResponseWriter, r *http.Request) {
	if oauthCORS(w, r) {
		return
	}
	base := s.base(r)
	oauthWriteJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.resource(r),
		"authorization_servers":    []string{base},
		"scopes_supported":         []string{"mcp"},
		"bearer_methods_supported": []string{"header"},
	})
}

func (s *oauthServer) handleASMetadata(w http.ResponseWriter, r *http.Request) {
	if oauthCORS(w, r) {
		return
	}
	base := s.base(r)
	oauthWriteJSON(w, http.StatusOK, map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + oauthAuthorizePath,
		"token_endpoint":                        base + oauthTokenPath,
		"registration_endpoint":                 base + oauthRegisterPath,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"mcp"},
	})
}

// ── dynamic client registration (RFC 7591) ────────────────────────────────────

func (s *oauthServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	if oauthCORS(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		oauthWriteErr(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		oauthWriteErr(w, http.StatusBadRequest, "invalid_client_metadata", "bad JSON")
		return
	}
	if len(req.RedirectURIs) == 0 {
		oauthWriteErr(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris required")
		return
	}
	for _, u := range req.RedirectURIs {
		if !validRedirect(u) {
			oauthWriteErr(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris must be https or http://localhost")
			return
		}
	}
	clientID := s.sign(oauthClaims{
		Kind:      "client",
		Redirects: req.RedirectURIs,
		Exp:       time.Now().Add(s.clientTTL).Unix(),
	})
	oauthWriteJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  clientID,
		"redirect_uris":              req.RedirectURIs,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"client_id_issued_at":        time.Now().Unix(),
	})
}

// ── authorization endpoint ─────────────────────────────────────────────────────

type authView struct {
	Action        string
	ClientID      string
	RedirectURI   string
	RedirectHost  string // host the code will be delivered to — shown to the operator
	FirstParty    bool   // redirect host == this server's host (no cross-site warning)
	State         string
	CodeChallenge string
	Resource      string
	Scope         string
	Prompt        string
	Error         string
}

func (s *oauthServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		oauthWriteErr(w, http.StatusMethodNotAllowed, "invalid_request", "GET or POST")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	get := func(k string) string { return strings.TrimSpace(r.Form.Get(k)) }
	clientID := get("client_id")
	redirectURI := get("redirect_uri")

	// Validate the client + redirect_uri BEFORE trusting either; a bad pair is a
	// hard 400 (never redirect to an unvalidated URI — open-redirect guard).
	cl, ok := s.parse(clientID)
	if !ok || cl.Kind != "client" || oauthExpired(cl) || !contains(cl.Redirects, redirectURI) {
		http.Error(w, "invalid client_id or redirect_uri", http.StatusBadRequest)
		return
	}

	state := get("state")
	resource := get("resource")
	scope := get("scope")
	challenge := get("code_challenge")
	method := get("code_challenge_method")

	action := s.base(r) + oauthAuthorizePath
	redirectErr := func(code string) {
		u, _ := url.Parse(redirectURI)
		q := u.Query()
		q.Set("error", code)
		if state != "" {
			q.Set("state", state)
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	if get("response_type") != "code" {
		redirectErr("unsupported_response_type")
		return
	}
	if challenge == "" || (method != "" && method != "S256") {
		redirectErr("invalid_request") // PKCE S256 is mandatory
		return
	}
	if resource != "" && !s.hostMatches(resource, r) {
		redirectErr("invalid_target")
		return
	}

	// The operator must be able to SEE where the code is going before approving.
	// DCR is open (any client can register any https redirect), so the consent
	// page shows the redirect host and warns when it is not first-party — this is
	// the anti-phishing control, not the redirect allow-list.
	redirectHost := ""
	if ru, err := url.Parse(redirectURI); err == nil {
		redirectHost = ru.Hostname()
	}
	view := authView{
		Action: action, ClientID: clientID, RedirectURI: redirectURI,
		RedirectHost: redirectHost, FirstParty: strings.EqualFold(redirectHost, hostnameOnly(r.Host)),
		State: state, CodeChallenge: challenge, Resource: resource, Scope: scope,
	}

	if r.Method == http.MethodGet {
		s.renderAuthorize(w, view, "")
		return
	}

	// POST from here. Throttle consent submissions per source IP: the MCP_TOKEN
	// entropy (>=24 chars) is the primary defence, this is defence-in-depth
	// against brute-forcing it through the form and against mcp_oauth_consent_*
	// log spam. A legitimate operator submits once, well under the burst.
	ip := s.clientIP(r)
	if !s.consentRL.allow(ip, time.Now(), consentRLWindow, consentRLBurst) {
		if s.auditAuth != nil {
			s.auditAuth(r, AuthAuditEvent{Kind: "mcp_consent", Result: "rate_limited", AuthMech: "unknown", Status: http.StatusTooManyRequests})
		}
		logging.LogfAPI("[apiserver] event=mcp_oauth_consent_ratelimited src_ip=%s window=%s burst=%d", ip, consentRLWindow, consentRLBurst)
		w.Header().Set("Retry-After", "300")
		http.Error(w, "too many consent attempts; try again later", http.StatusTooManyRequests)
		return
	}

	// POST: the MCP_TOKEN consent credential is validated by the Authenticator.
	_, ok = s.auth(get("token"))
	if !ok {
		if s.auditAuth != nil {
			s.auditAuth(r, AuthAuditEvent{Kind: "mcp_consent", Result: "invalid", AuthMech: "mcp_static", Status: http.StatusUnauthorized})
		}
		logging.LogfAPI("[apiserver] event=mcp_oauth_consent_denied src_ip=%s", ip)
		s.renderAuthorize(w, view, "Invalid token.")
		return
	}
	if s.auditAuth != nil {
		s.auditAuth(r, AuthAuditEvent{Kind: "mcp_consent", Result: "success", AuthMech: "mcp_static", Status: http.StatusFound})
	}
	code := s.sign(oauthClaims{
		Kind:      "code",
		Redirect:  redirectURI,
		Challenge: challenge,
		Nonce:     oauthNonce(), // makes the code single-use (see grantAuthorizationCode)
		Exp:       time.Now().Add(s.codeTTL).Unix(),
	})
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *oauthServer) renderAuthorize(w http.ResponseWriter, v authView, errMsg string) {
	v.Error = errMsg
	v.Prompt = s.prompt
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The consent page must never be framed (clickjacking on the approve action).
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	status := http.StatusOK
	if errMsg != "" {
		status = http.StatusUnauthorized
	}
	w.WriteHeader(status)
	_ = s.tpl.Execute(w, v)
}

// ── token endpoint ─────────────────────────────────────────────────────────────

func (s *oauthServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if oauthCORS(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		oauthWriteErr(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := r.ParseForm(); err != nil {
		oauthWriteErr(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.grantAuthorizationCode(w, r)
	case "refresh_token":
		s.grantRefresh(w, r)
	default:
		oauthWriteErr(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

func (s *oauthServer) grantAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	code := r.PostForm.Get("code")
	verifier := r.PostForm.Get("code_verifier")
	redirectURI := r.PostForm.Get("redirect_uri")

	c, ok := s.parse(code)
	if !ok || c.Kind != "code" || oauthExpired(c) {
		oauthWriteErr(w, http.StatusBadRequest, "invalid_grant", "bad or expired code")
		return
	}
	if c.Redirect != redirectURI {
		oauthWriteErr(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if verifier == "" || !pkceMatches(verifier, c.Challenge) {
		oauthWriteErr(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	if res := r.PostForm.Get("resource"); res != "" && !s.hostMatches(res, r) {
		oauthWriteErr(w, http.StatusBadRequest, "invalid_target", "resource mismatch")
		return
	}
	// Single-use: reject a code that has already been redeemed (OAuth 2.1).
	if !s.consumed.consume(c.Nonce, c.Exp) {
		oauthWriteErr(w, http.StatusBadRequest, "invalid_grant", "authorization code already used")
		return
	}
	s.issueTokens(w, r)
}

func (s *oauthServer) grantRefresh(w http.ResponseWriter, r *http.Request) {
	c, ok := s.parse(r.PostForm.Get("refresh_token"))
	if !ok || c.Kind != "refresh" || oauthExpired(c) || c.Aud != s.resource(r) {
		oauthWriteErr(w, http.StatusBadRequest, "invalid_grant", "bad or expired refresh_token")
		return
	}
	// Rotation with reuse detection: a refresh token is single-use, so a replay of
	// an already-rotated refresh token is rejected here.
	if !s.consumed.consume(c.Nonce, c.Exp) {
		oauthWriteErr(w, http.StatusBadRequest, "invalid_grant", "refresh token already used")
		return
	}
	s.issueTokens(w, r)
}

// issueTokens mints a fresh access+refresh pair bound to this request's resource.
// Each refresh token carries a unique nonce and is single-use: redeeming it (in
// grantRefresh) consumes that nonce, so the previous refresh token is invalidated
// on rotation. Note tokens cannot be revoked individually before expiry other
// than by rotating MCP_TOKEN (which invalidates ALL artifacts); see MCP.md.
func (s *oauthServer) issueTokens(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	resource := s.resource(r)
	access := s.sign(oauthClaims{Kind: "access", Aud: resource, Exp: now.Add(s.accessTTL).Unix()})
	refresh := s.sign(oauthClaims{Kind: "refresh", Aud: resource, Exp: now.Add(s.refreshTTL).Unix(), Nonce: oauthNonce()})
	oauthWriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(s.accessTTL.Seconds()),
		"refresh_token": refresh,
		"scope":         "mcp",
	})
}

// ── signed-artifact machinery (stateless, HMAC) ────────────────────────────────

// oauthClaims is the payload of every signed artifact this package issues.
type oauthClaims struct {
	Kind      string   `json:"k"`             // "client" | "code" | "access" | "refresh"
	Exp       int64    `json:"exp"`           // unix expiry
	Aud       string   `json:"aud,omitempty"` // access/refresh: canonical resource
	Redirect  string   `json:"rd,omitempty"`  // code: bound redirect_uri
	Challenge string   `json:"cc,omitempty"`  // code: PKCE S256 challenge
	Redirects []string `json:"rds,omitempty"` // client: registered redirect_uris
	Nonce     string   `json:"n,omitempty"`   // uniqueness (refresh rotation)
}

var oauthB64 = base64.RawURLEncoding

// deriveOAuthKey derives the HMAC signing key from MCP_TOKEN. Domain-separated
// so it can never collide with any other use of that secret. Rotating MCP_TOKEN
// invalidates every issued artifact.
func deriveOAuthKey(secret string) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("cfm-mcp-oauth-signing-v1"))
	return m.Sum(nil)
}

func (s *oauthServer) sign(c oauthClaims) string {
	payload, _ := json.Marshal(c)
	m := hmac.New(sha256.New, s.key)
	m.Write(payload)
	return oauthB64.EncodeToString(payload) + "." + oauthB64.EncodeToString(m.Sum(nil))
}

func (s *oauthServer) parse(tok string) (oauthClaims, bool) {
	dot := strings.IndexByte(tok, '.')
	if dot <= 0 || dot == len(tok)-1 {
		return oauthClaims{}, false
	}
	payload, err := oauthB64.DecodeString(tok[:dot])
	if err != nil {
		return oauthClaims{}, false
	}
	sig, err := oauthB64.DecodeString(tok[dot+1:])
	if err != nil {
		return oauthClaims{}, false
	}
	m := hmac.New(sha256.New, s.key)
	m.Write(payload)
	if !hmac.Equal(sig, m.Sum(nil)) {
		return oauthClaims{}, false
	}
	var c oauthClaims
	if json.Unmarshal(payload, &c) != nil {
		return oauthClaims{}, false
	}
	return c, true
}

func oauthExpired(c oauthClaims) bool { return time.Now().Unix() > c.Exp }

// ── helpers ─────────────────────────────────────────────────────────────────────

func pkceMatches(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(oauthB64.EncodeToString(sum[:])), []byte(challenge)) == 1
}

func (s *oauthServer) hostMatches(resource string, r *http.Request) bool {
	u, err := url.Parse(resource)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), hostnameOnly(r.Host))
}

func hostnameOnly(hostport string) string {
	h := hostport
	if strings.HasPrefix(h, "[") { // IPv6 literal
		if i := strings.LastIndex(h, "]"); i > 0 {
			return strings.Trim(h[:i+1], "[]")
		}
	}
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i+1:], "]") {
		return h[:i]
	}
	return h
}

func validRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	return u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func oauthNonce() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return oauthB64.EncodeToString(b[:])
}

func oauthWriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	// The claude.ai web connector performs OAuth discovery/registration with a
	// cross-origin browser fetch, so every OAuth/well-known response is CORS-open.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthWriteErr(w http.ResponseWriter, status int, code, desc string) {
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	oauthWriteJSON(w, status, body)
}

// oauthCORS answers the permissive preflight for the JSON endpoints. Returns true
// if the request was a preflight that has been fully answered.
func oauthCORS(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Protocol-Version")
		w.Header().Set("Access-Control-Max-Age", "600")
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

const authorizeHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CFM — authorize MCP access</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:30rem;margin:4rem auto;padding:0 1rem;color:#222}
 h1{font-size:1.2rem} .err{color:#b00020;margin:.5rem 0}
 input[type=password]{width:100%;padding:.6rem;font-size:1rem;box-sizing:border-box}
 button{margin-top:1rem;padding:.6rem 1.2rem;font-size:1rem;cursor:pointer}
 .sub{color:#666;font-size:.85rem}
 .dest{margin:.75rem 0;padding:.6rem .8rem;border:1px solid #ccc;border-radius:6px;background:#f6f6f6}
 .dest code{font-weight:600}
 .warn{margin:.75rem 0;padding:.6rem .8rem;border:1px solid #b00020;border-radius:6px;background:#fff2f2;color:#b00020}
</style></head><body>
<h1>Authorize read-only access to CFM</h1>
<p class="sub">A client is requesting read-only access to this CFM node's security telemetry. {{.Prompt}}</p>
<p class="dest">This will send the access grant to: <code>{{.RedirectHost}}</code></p>
{{if not .FirstParty}}<p class="warn">⚠ This is <strong>not</strong> this server's own hostname. Only approve if you recognise <code>{{.RedirectHost}}</code> as the client you are connecting (e.g. <code>claude.ai</code>). Do not approve links sent to you by others.</p>{{end}}
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}">
 <input type="hidden" name="response_type" value="code">
 <input type="hidden" name="client_id" value="{{.ClientID}}">
 <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
 <input type="hidden" name="state" value="{{.State}}">
 <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
 <input type="hidden" name="code_challenge_method" value="S256">
 <input type="hidden" name="resource" value="{{.Resource}}">
 <input type="hidden" name="scope" value="{{.Scope}}">
 <label for="token">MCP token</label>
 <input id="token" type="password" name="token" autocomplete="off" autofocus>
 <button type="submit">Approve</button>
</form>
</body></html>`
