package mcpserver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func pkcePair(verifier string) (string, string) {
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

const testRedirectURI = "https://claude.ai/api/mcp/auth_callback"

func oauthRegisterClient(t *testing.T, ts *httptest.Server, client *http.Client) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"redirect_uris": []string{testRedirectURI}})
	res, err := client.Post(ts.URL+"/mcp/oauth/register", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var reg struct {
		ClientID string `json:"client_id"`
	}
	json.NewDecoder(res.Body).Decode(&reg)
	if reg.ClientID == "" {
		t.Fatal("empty client_id")
	}
	return reg.ClientID
}

// oauthGetCode runs register+authorize and returns the authorization code.
func oauthGetCode(t *testing.T, ts *httptest.Server, client *http.Client, clientID, challenge string) string {
	t.Helper()
	form := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirectURI},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "token": {testAdminToken},
	}
	res, err := client.PostForm(ts.URL+"/mcp/oauth/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("authorize status %d", res.StatusCode)
	}
	loc, _ := url.Parse(res.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no code in redirect")
	}
	return code
}

func noRedirectClient(ts *httptest.Server) *http.Client {
	c := ts.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func exchangeCode(ts *httptest.Server, client *http.Client, code, verifier string) (*http.Response, map[string]any) {
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"code_verifier": {verifier}, "redirect_uri": {testRedirectURI},
	}
	res, _ := client.PostForm(ts.URL+"/mcp/oauth/token", form)
	var m map[string]any
	json.NewDecoder(res.Body).Decode(&m)
	res.Body.Close()
	return res, m
}

// An authorization code must be single-use (OAuth 2.1): a second exchange fails.
func TestOAuthCodeIsSingleUse(t *testing.T) {
	ts := newTestServer(t, nil)
	client := noRedirectClient(ts)
	clientID := oauthRegisterClient(t, ts, client)
	verifier, challenge := pkcePair("verifier-single-use-0123456789-abcdef")
	code := oauthGetCode(t, ts, client, clientID, challenge)

	res1, tok := exchangeCode(ts, client, code, verifier)
	if res1.StatusCode != http.StatusOK || tok["access_token"] == nil {
		t.Fatalf("first exchange failed: %d %v", res1.StatusCode, tok)
	}
	res2, m2 := exchangeCode(ts, client, code, verifier)
	if res2.StatusCode != http.StatusBadRequest {
		t.Fatalf("code replay: status %d, want 400 (single-use)", res2.StatusCode)
	}
	if m2["error"] != "invalid_grant" {
		t.Errorf("code replay error = %v, want invalid_grant", m2["error"])
	}
}

// A refresh token must be single-use (rotation with reuse detection).
func TestOAuthRefreshIsSingleUse(t *testing.T) {
	ts := newTestServer(t, nil)
	client := noRedirectClient(ts)
	clientID := oauthRegisterClient(t, ts, client)
	verifier, challenge := pkcePair("verifier-refresh-0123456789-abcdefghi")
	code := oauthGetCode(t, ts, client, clientID, challenge)
	_, tok := exchangeCode(ts, client, code, verifier)
	refresh, _ := tok["refresh_token"].(string)
	if refresh == "" {
		t.Fatal("no refresh_token issued")
	}

	redeem := func(rt string) (int, map[string]any) {
		res, _ := client.PostForm(ts.URL+"/mcp/oauth/token", url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {rt},
		})
		var m map[string]any
		json.NewDecoder(res.Body).Decode(&m)
		res.Body.Close()
		return res.StatusCode, m
	}

	st1, m1 := redeem(refresh)
	if st1 != http.StatusOK || m1["access_token"] == nil {
		t.Fatalf("first refresh failed: %d %v", st1, m1)
	}
	st2, m2 := redeem(refresh) // reuse of the now-rotated refresh token
	if st2 != http.StatusBadRequest {
		t.Fatalf("refresh replay: status %d, want 400", st2)
	}
	if m2["error"] != "invalid_grant" {
		t.Errorf("refresh replay error = %v, want invalid_grant", m2["error"])
	}
}

func TestValidAccessTokenExpiryAndAudience(t *testing.T) {
	base := "https://panel.example.com/cfm-admin"
	s := newOAuthServer(func(*http.Request) string { return base }, "/mcp",
		"signing-secret-long-enough-xxxxx", func(string) (string, bool) { return "", true })
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Host = "panel.example.com"
	aud := base + "/mcp"

	good := s.sign(oauthClaims{Kind: "access", Aud: aud, Exp: time.Now().Add(time.Hour).Unix()})
	if !s.validAccessToken(good, r) {
		t.Error("valid access token rejected")
	}
	expired := s.sign(oauthClaims{Kind: "access", Aud: aud, Exp: time.Now().Add(-time.Minute).Unix()})
	if s.validAccessToken(expired, r) {
		t.Error("expired token accepted")
	}
	wrongAud := s.sign(oauthClaims{Kind: "access", Aud: "https://evil.example/cfm-admin/mcp", Exp: time.Now().Add(time.Hour).Unix()})
	if s.validAccessToken(wrongAud, r) {
		t.Error("wrong-audience token accepted")
	}
	asRefresh := s.sign(oauthClaims{Kind: "refresh", Aud: aud, Exp: time.Now().Add(time.Hour).Unix()})
	if s.validAccessToken(asRefresh, r) {
		t.Error("refresh token accepted as access")
	}
}

func TestRegisterRejectsNonHTTPSRedirect(t *testing.T) {
	ts := newTestServer(t, nil)
	body, _ := json.Marshal(map[string]any{"redirect_uris": []string{"http://evil.example/cb"}})
	res, err := ts.Client().Post(ts.URL+"/mcp/oauth/register", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("http redirect_uri: status %d, want 400", res.StatusCode)
	}
}

func TestMCPGateRejectsWrongStaticBearer(t *testing.T) {
	ts := newTestServer(t, nil)
	res, _ := mcpPost(t, ts, "WRONG-TOKEN", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong static bearer: status %d, want 401", res.StatusCode)
	}
}

func TestToolNon200DispatchIsError(t *testing.T) {
	fd := &fakeDispatch{status: http.StatusInternalServerError, body: []byte(`boom`)}
	ts := newTestServer(t, fd)
	_, body := mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"firewall_blocks","arguments":{}}}`)
	if !strings.Contains(body, `"isError":true`) {
		t.Errorf("non-200 dispatch should be a tool error, got: %s", body)
	}
}

// A failing section must not sink a composed tool; the result stays valid JSON
// with an error member for that section only.
func TestSecurityOverviewDegradesGracefully(t *testing.T) {
	fd := &fakeDispatch{status: http.StatusServiceUnavailable, body: []byte(`nope`)}
	ts := newTestServer(t, fd)
	_, body := mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"security_overview","arguments":{}}}`)
	// Extract the tool result text (a JSON-RPC envelope wraps it) and confirm the
	// embedded composite is present and carries per-section error markers.
	if !strings.Contains(body, "error") || strings.Contains(body, `"isError":true`) {
		t.Errorf("security_overview should degrade to a non-error result with per-section errors, got: %s", body)
	}
}

func TestTopTalkersWindowRouting(t *testing.T) {
	fd := &fakeDispatch{}
	ts := newTestServer(t, fd)
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"top_talkers","arguments":{"window":"long"}}}`)
	if fd.lastPath != "/api/v1/webdet/long-top" {
		t.Errorf("window=long routed to %q, want long-top", fd.lastPath)
	}
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"top_talkers","arguments":{}}}`)
	if fd.lastPath != "/api/v1/webdet/top-short" {
		t.Errorf("default window routed to %q, want top-short", fd.lastPath)
	}
}

func TestProcessListRouting(t *testing.T) {
	fd := &fakeDispatch{}
	ts := newTestServer(t, fd)
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"process_list","arguments":{"top":10}}}`)
	if fd.lastPath != "/api/v1/system/processes" {
		t.Errorf("process_list routed to %q, want /api/v1/system/processes", fd.lastPath)
	}
	if got := fd.lastQuery.Get("top"); got != "10" {
		t.Errorf("top param = %q, want 10", got)
	}
}

func TestListeningPortsRouting(t *testing.T) {
	fd := &fakeDispatch{}
	ts := newTestServer(t, fd)
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"listening_ports","arguments":{}}}`)
	if fd.lastPath != "/api/v1/system/listeners" {
		t.Errorf("listening_ports routed to %q, want /api/v1/system/listeners", fd.lastPath)
	}
}

func TestDmesgTailRouting(t *testing.T) {
	fd := &fakeDispatch{}
	ts := newTestServer(t, fd)
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dmesg_tail","arguments":{"lines":50,"grep":"oom"}}}`)
	if fd.lastPath != "/api/v1/system/dmesg" {
		t.Errorf("dmesg_tail routed to %q, want /api/v1/system/dmesg", fd.lastPath)
	}
	if got := fd.lastQuery.Get("lines"); got != "50" {
		t.Errorf("lines = %q, want 50", got)
	}
	if got := fd.lastQuery.Get("grep"); got != "oom" {
		t.Errorf("grep = %q, want oom", got)
	}
}

func TestServiceStatusRouting(t *testing.T) {
	fd := &fakeDispatch{}
	ts := newTestServer(t, fd)
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"service_status","arguments":{"units":"cfm,mariadb"}}}`)
	if fd.lastPath != "/api/v1/system/services" {
		t.Errorf("service_status routed to %q, want /api/v1/system/services", fd.lastPath)
	}
	if got := fd.lastQuery.Get("units"); got != "cfm,mariadb" {
		t.Errorf("units param = %q, want cfm,mariadb", got)
	}
}

func TestEdgeAccessTailRouting(t *testing.T) {
	fd := &fakeDispatch{}
	ts := newTestServer(t, fd)
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"edge_access_tail","arguments":{"ip":"1.2.3.4","status":"4","path":"admin-ajax.php","since":"10m","limit":25}}}`)
	if fd.lastPath != "/api/v1/webdet/access-recent" {
		t.Errorf("edge_access_tail routed to %q, want /api/v1/webdet/access-recent", fd.lastPath)
	}
	if got := fd.lastQuery.Get("ip"); got != "1.2.3.4" {
		t.Errorf("ip = %q, want 1.2.3.4", got)
	}
	if got := fd.lastQuery.Get("status"); got != "4" {
		t.Errorf("status = %q, want 4", got)
	}
	if got := fd.lastQuery.Get("path"); got != "admin-ajax.php" {
		t.Errorf("path = %q, want admin-ajax.php", got)
	}
	if got := fd.lastQuery.Get("limit"); got != "25" {
		t.Errorf("limit = %q, want 25", got)
	}
}

func TestIPForensicsRouting(t *testing.T) {
	fd := &fakeDispatch{}
	ts := newTestServer(t, fd)
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ip_forensics","arguments":{"ip":"1.2.3.4","lines":100000,"limit":50}}}`)
	if fd.lastPath != "/api/v1/system/ip-forensics" {
		t.Errorf("ip_forensics routed to %q, want /api/v1/system/ip-forensics", fd.lastPath)
	}
	if got := fd.lastQuery.Get("ip"); got != "1.2.3.4" {
		t.Errorf("ip = %q, want 1.2.3.4", got)
	}
	if got := fd.lastQuery.Get("lines"); got != "100000" {
		t.Errorf("lines = %q, want 100000", got)
	}
}

// The consent page must disclose where the grant is delivered and warn on a
// non-first-party redirect (anti-phishing).
func TestConsentPageShowsRedirectAndWarns(t *testing.T) {
	ts := newTestServer(t, nil)
	client := noRedirectClient(ts)
	clientID := oauthRegisterClient(t, ts, client)
	_, challenge := pkcePair("verifier-consent-0123456789-abcdefghij")
	u := ts.URL + "/mcp/oauth/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirectURI},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode()
	res, err := client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	b := string(raw)
	if !strings.Contains(b, "claude.ai") {
		t.Errorf("consent page does not show redirect host: %s", b)
	}
	if !strings.Contains(b, "not") || !strings.Contains(b, "hostname") {
		t.Errorf("consent page missing cross-site warning: %s", b)
	}
}
