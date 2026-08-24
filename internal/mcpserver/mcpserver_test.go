package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDispatch records the last in-process read it was asked to perform and
// returns a canned body, so tests can assert which endpoint a tool hit.
type fakeDispatch struct {
	mu         sync.Mutex // guards the last*/seen fields (composed tools dispatch concurrently)
	lastPath   string
	lastQuery  url.Values
	seen       []string          // every path dispatched (composed tools hit several)
	body       []byte            // default body for any path without a bodyByPath entry
	bodyByPath map[string][]byte // optional per-path body (for composed multi-endpoint tools)
	status     int
	delay      time.Duration // if >0, fn blocks this long (honouring ctx) before returning
}

func (f *fakeDispatch) fn(ctx context.Context, path string, q url.Values) (int, []byte, error) {
	f.mu.Lock()
	f.lastPath = path
	f.lastQuery = q
	f.seen = append(f.seen, path)
	body := f.body
	if b, ok := f.bodyByPath[path]; ok {
		body = b
	}
	status := f.status
	delay := f.delay
	f.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		}
	}
	if body == nil {
		body = []byte(`{"ok":true}`)
	}
	if status == 0 {
		status = http.StatusOK
	}
	return status, body, nil
}

// sawPath reports whether path was dispatched at least once.
func (f *fakeDispatch) sawPath(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.seen {
		if p == path {
			return true
		}
	}
	return false
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
	for _, want := range []string{"security_overview", "waf_activity", "challenge_vhosts", "suspicious_hosts", "firewall_blocks", "netfilter_path", "detectors_status", "system_health"} {
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

// TestOAuthConsentRateLimited verifies the consent POST is throttled per source
// IP: after consentRLBurst submissions in the window, further attempts get 429
// (defence-in-depth against brute-forcing MCP_TOKEN through the form).
func TestOAuthConsentRateLimited(t *testing.T) {
	ts := newTestServer(t, nil)
	client := ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	// Register a client to get a valid client_id bound to redirectURI.
	redirectURI := "https://claude.ai/api/mcp/auth_callback"
	regBody, _ := json.Marshal(map[string]any{"redirect_uris": []string{redirectURI}})
	regRes, err := client.Post(ts.URL+"/mcp/oauth/register", "application/json", strings.NewReader(string(regBody)))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	_ = json.NewDecoder(regRes.Body).Decode(&reg)
	regRes.Body.Close()
	if reg.ClientID == "" {
		t.Fatal("registration returned no client_id")
	}

	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {reg.ClientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"scope":                 {"mcp"},
		"token":                 {"wrong-token"}, // always invalid → never redirects away
	}
	post := func() int {
		rr, err := client.PostForm(ts.URL+"/mcp/oauth/authorize", form)
		if err != nil {
			t.Fatal(err)
		}
		rr.Body.Close()
		return rr.StatusCode
	}

	// The first burst attempts render "Invalid token" (401), not throttled (429).
	for i := 0; i < consentRLBurst; i++ {
		if code := post(); code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d unexpectedly rate-limited (429) before burst", i+1)
		}
	}
	// The next one exceeds the burst → 429.
	if code := post(); code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d attempts, got %d", consentRLBurst, code)
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

// TestSecurityOverviewSectionBudget verifies a slow section degrades to a
// per-section timeout error instead of hanging the whole composed call past the
// client timeout. Sections run concurrently and each is capped by
// overviewSectionBudget, shrunk here so the test is fast.
func TestSecurityOverviewSectionBudget(t *testing.T) {
	orig := overviewSectionBudget
	overviewSectionBudget = 30 * time.Millisecond
	t.Cleanup(func() { overviewSectionBudget = orig })

	fd := &fakeDispatch{delay: 3 * time.Second} // far exceeds the budget
	ts := newTestServer(t, fd)
	start := time.Now()
	res, body := mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"security_overview","arguments":{}}}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if strings.Contains(body, `"isError":true`) {
		t.Fatalf("overview should stay a valid result, got isError: %s", body)
	}
	// The slow section degrades to an error object. Normally sectionBudgeted's
	// own cctx.Done() fires first ("section timed out"); if the dispatch's
	// context-deadline error races ahead it surfaces "deadline exceeded". Either
	// is a valid bounded degradation — assert on the degradation, not the wording.
	if !strings.Contains(body, "section timed out") && !strings.Contains(body, "deadline exceeded") {
		t.Fatalf("expected a degraded per-section error, got: %s", body)
	}
	// Concurrent + budgeted: must return well under the sum of five 3s delays.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("composed call took %s; sections not bounded/concurrent", elapsed)
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
	fd := &fakeDispatch{body: []byte(`{"rows":[{"ip":"1.2.3.4","country":"China","permanent":true}],"total":1,"permanent":1}`)}
	ts := newTestServer(t, fd)

	// firewall_blocks → /api/v1/firewall/list (then summarized in the tool layer)
	_, body := mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"firewall_blocks","arguments":{}}}`)
	if fd.lastPath != "/api/v1/firewall/list" {
		t.Errorf("firewall_blocks dispatched to %q, want /api/v1/firewall/list", fd.lastPath)
	}
	// The tool no longer passes the raw list through — it emits the compact summary.
	if !strings.Contains(body, `by_country`) {
		t.Errorf("firewall_blocks result missing summary (by_country): %s", body)
	}

	// waf_activity forwards combinable FP-triage filters to the summary endpoint.
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"waf_activity","arguments":{"hours":6,"country":"GR","rule":"WAF_SQLI","ip":"2001:db8::1","host":"shop.example","path":"/checkout","ua":"Mozilla"}}}`)
	if fd.lastPath != "/api/v1/waf/engine/summary" {
		t.Errorf("waf_activity dispatched to %q", fd.lastPath)
	}
	if fd.lastQuery.Get("hours") != "6" || fd.lastQuery.Get("enrich") != "1" ||
		fd.lastQuery.Get("country") != "GR" || fd.lastQuery.Get("rule") != "WAF_SQLI" ||
		fd.lastQuery.Get("ip") != "2001:db8::1" || fd.lastQuery.Get("host") != "shop.example" ||
		fd.lastQuery.Get("path") != "/checkout" || fd.lastQuery.Get("ua") != "Mozilla" {
		t.Errorf("waf_activity query = %v, filters were not forwarded", fd.lastQuery)
	}
}

func TestDetectionHistoryPassesIP(t *testing.T) {
	fd := &fakeDispatch{body: []byte(`{"rows":[]}`)}
	ts := newTestServer(t, fd)

	// detection_history ip=<addr> → /api/v1/webdet/history/events?ip=…&enrich=1
	// (the "who/why was this IP acted on" attribution lookup).
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"detection_history","arguments":{"ip":"79.130.136.88"}}}`)
	if fd.lastPath != "/api/v1/webdet/history/events" {
		t.Errorf("detection_history dispatched to %q", fd.lastPath)
	}
	if fd.lastQuery.Get("ip") != "79.130.136.88" {
		t.Errorf("detection_history ip = %q, want 79.130.136.88", fd.lastQuery.Get("ip"))
	}
	if fd.lastQuery.Get("enrich") != "1" {
		t.Errorf("detection_history should request enrich=1, got %q", fd.lastQuery.Get("enrich"))
	}
}

func TestIPLocateDispatchesToSearch(t *testing.T) {
	fd := &fakeDispatch{body: []byte(`{"ok":true,"locations":[]}`)}
	ts := newTestServer(t, fd)

	// ip_locate ip=<addr> → /search?ip=… (the `cfm which` multi-source lookup,
	// which carries the cfm.deny autoblock reason).
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ip_locate","arguments":{"ip":"79.130.136.88"}}}`)
	if fd.lastPath != "/search" {
		t.Errorf("ip_locate dispatched to %q, want /search", fd.lastPath)
	}
	if fd.lastQuery.Get("ip") != "79.130.136.88" {
		t.Errorf("ip_locate ip = %q, want 79.130.136.88", fd.lastQuery.Get("ip"))
	}

	// Missing ip must error before dispatch (schema-required + explicit guard).
	fd.lastPath = ""
	_, body := mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ip_locate","arguments":{"ip":""}}}`)
	if fd.lastPath != "" {
		t.Errorf("ip_locate dispatched despite empty ip (path=%q)", fd.lastPath)
	}
	if !strings.Contains(body, "ip") {
		t.Errorf("expected a required-field error mentioning ip, got: %s", body)
	}
}

func TestWhatsWrongEndToEnd(t *testing.T) {
	fd := &fakeDispatch{bodyByPath: map[string][]byte{
		"/api/v1/health/snapshot":   []byte(`{"disk":{"mounts":[{"mount":"/","used_pct":97}]},"runtime":{"frontend_working":"working","edge_status":"active"},"host":{"load_avg_5":1,"cpu_threads":8}}`),
		"/api/v1/health/anomalies":  []byte(`{"count":0,"anomalies":[]}`),
		"/api/v1/system/services":   []byte(`{"ok":true,"services":[{"unit":"cfm.service","load":"loaded","active":"active","sub":"running","enabled":"enabled","restarts":0}]}`),
		"/api/v1/mysql/top":         []byte(`{"error":"HTTP 404"}`), // governor off → recorded as error, not a finding
		"/api/v1/system/mail-queue": []byte(`{"available":false,"note":"no detector"}`),
		"/api/v1/mail/traffic":      []byte(`{"available":true,"traffic":{"anomalies":[]}}`),
	}}
	ts := newTestServer(t, fd)

	_, body := mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whats_wrong","arguments":{}}}`)

	// All six signal endpoints must have been consulted.
	for _, p := range []string{
		"/api/v1/health/snapshot", "/api/v1/health/anomalies", "/api/v1/system/services",
		"/api/v1/mysql/top", "/api/v1/system/mail-queue", "/api/v1/mail/traffic",
	} {
		if !fd.sawPath(p) {
			t.Errorf("whats_wrong did not dispatch %s", p)
		}
	}

	// The tool text content is itself a JSON document; decode it and assert on the
	// structured result rather than substring-matching the escaped envelope.
	var res whatsWrongResult
	if err := json.Unmarshal([]byte(toolText(t, body)), &res); err != nil {
		t.Fatalf("decode whats_wrong result: %v; body=%s", err, body)
	}
	if res.Status != "issues" {
		t.Errorf("status = %q, want issues", res.Status)
	}
	if res.Sources["mysql"] != "error: HTTP 404" { // governor off → errored, not healthy
		t.Errorf("mysql source = %q, want error: HTTP 404", res.Sources["mysql"])
	}
	if res.Sources["mail_queue"] != "unavailable" {
		t.Errorf("mail_queue source = %q, want unavailable", res.Sources["mail_queue"])
	}
	if f := findBy(res.Findings, "disk", sevCritical); f == nil {
		t.Errorf("expected a critical disk finding, got %+v", res.Findings)
	}
}

// toolText extracts result.content[0].text from a JSON-RPC tool-call response.
func toolText(t *testing.T, body string) string {
	t.Helper()
	var env struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("decode JSON-RPC envelope: %v; body=%s", err, body)
	}
	if len(env.Result.Content) == 0 {
		t.Fatalf("tool result has no content; body=%s", body)
	}
	return env.Result.Content[0].Text
}

func TestFirewallSelfTestDispatches(t *testing.T) {
	fd := &fakeDispatch{body: []byte(`{"ok":true,"available":true,"selftest":{"engine":"nftlib","samples":3}}`)}
	ts := newTestServer(t, fd)
	_, body := mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"firewall_selftest","arguments":{}}}`)
	if fd.lastPath != "/api/v1/firewall/selftest" {
		t.Errorf("firewall_selftest dispatched to %q, want /api/v1/firewall/selftest", fd.lastPath)
	}
	if !strings.Contains(body, "nftlib") {
		t.Errorf("firewall_selftest result missing payload: %s", body)
	}
}

func TestNetfilterPathDispatchesFilters(t *testing.T) {
	fd := &fakeDispatch{body: []byte(`{"ok":true,"status":"warning","chains":[]}`)}
	ts := newTestServer(t, fd)
	_, body := mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"netfilter_path","arguments":{"hook":"prerouting","proto":"tcp","dport":443}}}`)
	if fd.lastPath != "/api/v1/firewall/path" || fd.lastQuery.Get("hook") != "prerouting" || fd.lastQuery.Get("proto") != "tcp" || fd.lastQuery.Get("dport") != "443" {
		t.Errorf("netfilter_path dispatch path=%q query=%v", fd.lastPath, fd.lastQuery)
	}
	if !strings.Contains(body, "warning") {
		t.Errorf("netfilter_path result missing payload: %s", body)
	}
}

func TestNetfilterPathRejectsInvalidFilter(t *testing.T) {
	for _, port := range []int{-1, 0, 65536} {
		fd := &fakeDispatch{}
		ts := newTestServer(t, fd)
		_, body := mcpPost(t, ts, testAdminToken, fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"netfilter_path","arguments":{"dport":%d}}}`, port))
		if fd.lastPath != "" {
			t.Fatalf("port %d dispatched to %q", port, fd.lastPath)
		}
		if !strings.Contains(body, `"isError":true`) {
			t.Fatalf("port %d expected tool error: %s", port, body)
		}
		ts.Close()
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
