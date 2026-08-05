package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeDispatch records the last in-process read it was asked to perform and
// returns a canned body, so tests can assert which endpoint a tool hit.
type fakeDispatch struct {
	lastPath  string
	lastQuery url.Values
	body      []byte
	status    int
}

func (f *fakeDispatch) fn(_ context.Context, path string, q url.Values) (int, []byte, error) {
	f.lastPath = path
	f.lastQuery = q
	body := f.body
	if body == nil {
		body = []byte(`{"ok":true}`)
	}
	status := f.status
	if status == 0 {
		status = http.StatusOK
	}
	return status, body, nil
}

const testAdminToken = "ADMINTOK"

func newTestServer(t *testing.T, fd *fakeDispatch) *httptest.Server {
	t.Helper()
	if fd == nil {
		fd = &fakeDispatch{}
	}
	h := New(Deps{
		Version:       "test",
		MCPPath:       "/mcp",
		Dispatch:      fd.fn,
		BaseURL:       func(r *http.Request) string { return "https://" + r.Host + "/cfm-admin" },
		Authenticate:  func(cred string) (string, bool) { return "", cred == testAdminToken },
		SigningSecret: testAdminToken,
		StaticBearer:  func(tok string) bool { return tok == testAdminToken },
	})
	mux := http.NewServeMux()
	h.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// mcpPost sends a JSON-RPC body to the stateless streamable endpoint.
func mcpPost(t *testing.T, ts *httptest.Server, bearer, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

func TestBearerGateRejectsAndAdvertisesMetadata(t *testing.T) {
	ts := newTestServer(t, nil)
	res, _ := mcpPost(t, ts, "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-auth /mcp: status = %d, want 401", res.StatusCode)
	}
	wa := res.Header.Get("WWW-Authenticate")
	wantPtr := `resource_metadata="https://` + hostOf(ts) + `/cfm-admin/.well-known/oauth-protected-resource"`
	if !strings.Contains(wa, wantPtr) {
		t.Errorf("WWW-Authenticate = %q, want it to contain %q", wa, wantPtr)
	}
}

func TestBearerGateAcceptsAdminTokenAndListsTools(t *testing.T) {
	ts := newTestServer(t, nil)
	res, body := mcpPost(t, ts, testAdminToken, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("admin /mcp tools/list: status = %d, body %s", res.StatusCode, body)
	}
	for _, want := range []string{"security_overview", "waf_activity", "challenge_vhosts", "suspicious_hosts", "firewall_blocks", "detectors_status", "system_health"} {
		if !strings.Contains(body, `"`+want+`"`) {
			t.Errorf("tools/list missing %q: %s", want, body)
		}
	}
	// Read-only annotation must be advertised.
	if !strings.Contains(body, `"readOnlyHint":true`) {
		t.Errorf("tools/list missing readOnlyHint: %s", body)
	}
}

func TestOAuthProtectedResourceMetadata(t *testing.T) {
	ts := newTestServer(t, nil)
	res, err := ts.Client().Get(ts.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	wantResource := "https://" + hostOf(ts) + "/cfm-admin/mcp"
	if m["resource"] != wantResource {
		t.Errorf("resource = %v, want %q", m["resource"], wantResource)
	}
	if res.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("metadata missing permissive CORS header")
	}
}

func TestOAuthASMetadata(t *testing.T) {
	ts := newTestServer(t, nil)
	res, err := ts.Client().Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	base := "https://" + hostOf(ts) + "/cfm-admin"
	if m["token_endpoint"] != base+"/mcp/oauth/token" {
		t.Errorf("token_endpoint = %v", m["token_endpoint"])
	}
	if m["registration_endpoint"] != base+"/mcp/oauth/register" {
		t.Errorf("registration_endpoint = %v", m["registration_endpoint"])
	}
	if methods, _ := m["code_challenge_methods_supported"].([]any); len(methods) != 1 || methods[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v, want [S256]", m["code_challenge_methods_supported"])
	}
}

// TestOAuthOIDCMetadataAlias verifies /.well-known/openid-configuration is
// served as an alias of the RFC 8414 AS metadata. The claude.ai remote
// connector probes the OIDC discovery URL first; before the alias it hit a
// 401 and aborted dynamic client registration. It must return the same
// authorize/token/registration endpoints as oauth-authorization-server.
func TestOAuthOIDCMetadataAlias(t *testing.T) {
	ts := newTestServer(t, nil)
	res, err := ts.Client().Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("openid-configuration status = %d, want 200", res.StatusCode)
	}
	var m map[string]any
	if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	base := "https://" + hostOf(ts) + "/cfm-admin"
	if m["issuer"] != base {
		t.Errorf("issuer = %v, want %q", m["issuer"], base)
	}
	if m["authorization_endpoint"] != base+"/mcp/oauth/authorize" {
		t.Errorf("authorization_endpoint = %v", m["authorization_endpoint"])
	}
	if m["registration_endpoint"] != base+"/mcp/oauth/register" {
		t.Errorf("registration_endpoint = %v", m["registration_endpoint"])
	}
}

// TestMCPBehindProxyNonLoopbackHost pins DisableLocalhostProtection. The edge
// upstreams to the daemon over loopback (127.0.0.1) while forwarding the public
// Host header; the go-sdk DNS-rebinding guard (loopback LocalAddr + non-loopback
// Host) otherwise 403s every authenticated /mcp call — exactly what happened in
// production after a fully successful OAuth flow. A valid bearer with a
// non-loopback Host must reach the tools, not get Forbidden.
func TestMCPBehindProxyNonLoopbackHost(t *testing.T) {
	ts := newTestServer(t, nil)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Host = "titan.example.com" // non-loopback, as the edge forwards it
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusForbidden {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("got 403 — DNS-rebinding guard not disabled: %s", body)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
}

// TestOAuthFlowMintsUsableToken drives the full register → authorize → token
// (authorization_code + PKCE S256) flow and confirms the minted access token
// passes the /mcp bearer gate.
func TestOAuthFlowMintsUsableToken(t *testing.T) {
	ts := newTestServer(t, nil)
	client := ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	// 1. dynamic client registration
	redirectURI := "https://claude.ai/api/mcp/auth_callback"
	regBody, _ := json.Marshal(map[string]any{"redirect_uris": []string{redirectURI}})
	regRes, err := client.Post(ts.URL+"/mcp/oauth/register", "application/json", strings.NewReader(string(regBody)))
	if err != nil {
		t.Fatal(err)
	}
	defer regRes.Body.Close()
	if regRes.StatusCode != http.StatusCreated {
		t.Fatalf("register: status %d", regRes.StatusCode)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	json.NewDecoder(regRes.Body).Decode(&reg)
	if reg.ClientID == "" {
		t.Fatal("register: empty client_id")
	}

	// 2. PKCE material
	verifier := "verifier-0123456789-abcdefghijklmnopqrstuvwxyz"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// 3. authorize consent submit (admin token) → 302 with ?code=
	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {reg.ClientID},
		"redirect_uri":          {redirectURI},
		"state":                 {"xyz"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"token":                 {testAdminToken},
	}
	authRes, err := client.PostForm(ts.URL+"/mcp/oauth/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	defer authRes.Body.Close()
	if authRes.StatusCode != http.StatusFound {
		t.Fatalf("authorize: status %d, want 302", authRes.StatusCode)
	}
	loc, err := url.Parse(authRes.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("authorize redirect missing code: %s", authRes.Header.Get("Location"))
	}
	if loc.Query().Get("state") != "xyz" {
		t.Errorf("authorize dropped state")
	}

	// 4. token exchange (authorization_code + verifier)
	tokForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	}
	tokRes, err := client.PostForm(ts.URL+"/mcp/oauth/token", tokForm)
	if err != nil {
		t.Fatal(err)
	}
	defer tokRes.Body.Close()
	if tokRes.StatusCode != http.StatusOK {
		t.Fatalf("token: status %d", tokRes.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	json.NewDecoder(tokRes.Body).Decode(&tok)
	if tok.AccessToken == "" || tok.TokenType != "Bearer" {
		t.Fatalf("token response bad: %+v", tok)
	}

	// 5. the minted token must pass the /mcp gate
	res, body := mcpPost(t, ts, tok.AccessToken, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("minted token rejected at /mcp: status %d, body %s", res.StatusCode, body)
	}
}

func TestOAuthAuthorizeRejectsBadCredential(t *testing.T) {
	ts := newTestServer(t, nil)
	client := ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	redirectURI := "https://claude.ai/api/mcp/auth_callback"
	regBody, _ := json.Marshal(map[string]any{"redirect_uris": []string{redirectURI}})
	regRes, err := client.Post(ts.URL+"/mcp/oauth/register", "application/json", strings.NewReader(string(regBody)))
	if err != nil {
		t.Fatal(err)
	}
	defer regRes.Body.Close()
	var reg struct {
		ClientID string `json:"client_id"`
	}
	json.NewDecoder(regRes.Body).Decode(&reg)

	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {reg.ClientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {"deadbeef"},
		"code_challenge_method": {"S256"},
		"token":                 {"WRONG-TOKEN"},
	}
	res, err := client.PostForm(ts.URL+"/mcp/oauth/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	// A bad credential must NOT redirect with a code; it re-renders the form 401.
	if res.StatusCode == http.StatusFound {
		t.Fatalf("bad credential produced a redirect (possible code issuance)")
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad credential: status %d, want 401", res.StatusCode)
	}
}

func TestToolCallDispatchesToAllowlistedEndpoint(t *testing.T) {
	fd := &fakeDispatch{body: []byte(`{"blocks":[]}`)}
	ts := newTestServer(t, fd)

	// firewall_blocks → /api/v1/firewall/list
	_, body := mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"firewall_blocks","arguments":{}}}`)
	if fd.lastPath != "/api/v1/firewall/list" {
		t.Errorf("firewall_blocks dispatched to %q, want /api/v1/firewall/list", fd.lastPath)
	}
	if !strings.Contains(body, `blocks`) {
		t.Errorf("tool result missing dispatched body: %s", body)
	}

	// waf_activity with hours → /api/v1/waf/engine/summary?enrich=1&hours=6
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"waf_activity","arguments":{"hours":6}}}`)
	if fd.lastPath != "/api/v1/waf/engine/summary" {
		t.Errorf("waf_activity dispatched to %q", fd.lastPath)
	}
	if fd.lastQuery.Get("hours") != "6" || fd.lastQuery.Get("enrich") != "1" {
		t.Errorf("waf_activity query = %v, want hours=6 enrich=1", fd.lastQuery)
	}
}

func TestToolCallMissingRequiredArg(t *testing.T) {
	fd := &fakeDispatch{}
	ts := newTestServer(t, fd)
	_, body := mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"host_drilldown","arguments":{}}}`)
	// The SDK enforces the required `host` field from the input schema BEFORE the
	// handler runs, so the call must error and never reach dispatch.
	if fd.lastPath != "" {
		t.Errorf("host_drilldown dispatched despite missing host (path=%q)", fd.lastPath)
	}
	if !strings.Contains(body, `"isError":true`) || !strings.Contains(body, "host") {
		t.Errorf("expected a required-field error mentioning host, got: %s", body)
	}
}

func hostOf(ts *httptest.Server) string {
	u, _ := url.Parse(ts.URL)
	return u.Host
}
