package blocklists

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAPIAuthTokenForOnlyOnAPIOrigin(t *testing.T) {
	a := APIAuth{BaseURL: "https://cfm.myip.gr", Token: "sekrit"}
	cases := []struct {
		url  string
		want bool
	}{
		{"https://cfm.myip.gr/blacklist.txt", true},
		{"https://CFM.myip.gr:443/whitelist.txt", true},
		{"http://cfm.myip.gr/blacklist.txt", false},           // never downgrade to cleartext
		{"https://cfm.myip.gr:8443/blacklist.txt", false},     // other port
		{"https://evil.cfm.myip.gr/blacklist.txt", false},     // subdomain
		{"https://cfm.myip.gr.evil.tld/blacklist.txt", false}, // suffix trick
		{"https://www.spamhaus.org/drop/drop.txt", false},     // third-party feed
	}
	for _, c := range cases {
		u, _ := url.Parse(c.url)
		if got := a.tokenFor(u) != ""; got != c.want {
			t.Errorf("tokenFor(%s) = %v, want %v", c.url, got, c.want)
		}
	}

	// An http API_URL may be upgraded to https on the same host.
	h := APIAuth{BaseURL: "http://cfm.myip.gr", Token: "sekrit"}
	u, _ := url.Parse("https://cfm.myip.gr/blacklist.txt")
	if h.tokenFor(u) == "" {
		t.Errorf("http API_URL should allow the https upgrade")
	}

	for _, empty := range []APIAuth{{}, {BaseURL: "https://cfm.myip.gr"}, {Token: "x"}, {BaseURL: "::bad", Token: "x"}} {
		u, _ := url.Parse("https://cfm.myip.gr/blacklist.txt")
		if empty.tokenFor(u) != "" {
			t.Errorf("incomplete auth %+v must send no token", empty)
		}
	}
}

func TestFetchSendsTokenToAPIOriginOnly(t *testing.T) {
	var gotAPI, gotOther string
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOther = r.Header.Get("Token")
		_, _ = w.Write([]byte("5.6.7.8\n"))
	}))
	defer other.Close()
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPI = r.Header.Get("Token")
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, other.URL+"/list.txt", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("1.2.3.4\n"))
	}))
	defer api.Close()

	auth := APIAuth{BaseURL: api.URL, Token: "sekrit"}
	client := api.Client() // trusts the test cert; other shares the same CA

	res, err := FetchAndParseAuth(context.Background(), client, Feed{Name: "MYBLOCK", URL: api.URL + "/blacklist.txt"}, auth)
	if err != nil || len(res.V4) != 1 {
		t.Fatalf("fetch: %v %+v", err, res)
	}
	if gotAPI != "sekrit" {
		t.Fatalf("API origin feed got Token %q, want the AUTH_TOKEN", gotAPI)
	}

	if _, err := FetchAndParseAuth(context.Background(), client, Feed{Name: "EXT", URL: other.URL + "/list.txt"}, auth); err != nil {
		t.Fatal(err)
	}
	if gotOther != "" {
		t.Fatalf("third-party feed received the token")
	}

	// A redirect off the API origin must drop the token.
	gotOther = "unset"
	if _, err := FetchAndParseAuth(context.Background(), client, Feed{Name: "R", URL: api.URL + "/redirect"}, auth); err != nil {
		t.Fatal(err)
	}
	if gotOther != "" {
		t.Fatalf("redirect carried the token off the API origin: %q", gotOther)
	}
	if client.CheckRedirect != nil {
		t.Fatalf("FetchAndParseAuth mutated the shared client")
	}
}

func TestFetch401NamesMissingToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()
	_, err := FetchAndParseAuth(context.Background(), nil, Feed{URL: ts.URL + "/blacklist.txt"},
		APIAuth{BaseURL: "https://cfm.example", Token: "x"})
	if err == nil || !strings.Contains(err.Error(), "no Token sent") {
		t.Fatalf("want a 'no Token sent' hint, got %v", err)
	}
}

func TestManagerUsesAPIAuth(t *testing.T) {
	var got string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Token")
		_, _ = w.Write([]byte("1.2.3.4\n"))
	}))
	defer ts.Close()
	m := NewManager(applierFunc(func(context.Context, Feed, *FetchResult) error { return nil }))
	m.SetAPIAuth(ts.URL, "sekrit")
	m.fetchOnce(context.Background(), &runner{feed: Feed{Name: "MYBLOCK", URL: ts.URL + "/blacklist.txt"}})
	if got != "sekrit" {
		t.Fatalf("manager fetch sent Token %q", got)
	}
}

func TestAPIAuthSchemelessMeansHTTPS(t *testing.T) {
	a := APIAuth{BaseURL: "cfm.myip.gr", Token: "sekrit"}
	u, _ := url.Parse("https://cfm.myip.gr/blacklist.txt")
	if a.tokenFor(u) == "" {
		t.Fatalf("schemeless API_URL must match its https feeds, as the agent client does")
	}
	h, _ := url.Parse("http://cfm.myip.gr/blacklist.txt")
	if a.tokenFor(h) != "" {
		t.Fatalf("schemeless API_URL is https: an http feed must not get the token")
	}
}

func TestAPIAuthMismatchReason(t *testing.T) {
	a := APIAuth{BaseURL: "https://cfm.myip.gr", Token: "sekrit"}
	for raw, want := range map[string]string{
		"http://cfm.myip.gr/blacklist.txt":  "scheme or port",
		"https://cfm.myip.gr:8443/x":        "scheme or port",
		"https://www.spamhaus.org/drop.txt": `only feeds on the API_URL host "cfm.myip.gr"`,
		"https://cfm.myip.gr/blacklist.txt": "",
	} {
		u, _ := url.Parse(raw)
		got := a.mismatch(u)
		if (want == "" && got != "") || !strings.Contains(got, want) {
			t.Errorf("mismatch(%s) = %q, want containing %q", raw, got, want)
		}
	}
}

func TestStatusRedactsURLInLastError(t *testing.T) {
	m := NewManager(applierFunc(func(context.Context, Feed, *FetchResult) error { return nil }))
	// Port 1 on loopback: connection refused, so the error is a *url.Error
	// carrying the request URL.
	r := &runner{feed: Feed{Name: "EXT", URL: "http://bob@127.0.0.1:1/list.txt?key=APIKEY123"}}
	m.runs["EXT"] = r
	m.fetchOnce(context.Background(), r)
	st := m.Status()
	if len(st) != 1 || st[0].LastErr == "" {
		t.Fatalf("want one failing feed, got %+v", st)
	}
	for _, leak := range []string{"APIKEY123", "bob"} {
		if strings.Contains(st[0].LastErr, leak) || strings.Contains(st[0].URL, leak) {
			t.Errorf("status leaks %q: url=%q err=%q", leak, st[0].URL, st[0].LastErr)
		}
	}
}

// cfm-web answers a refused token on the header path only (it never falls back
// to the IP there): the node must keep its lists by retrying without the token
// while the IP fallback exists, and say why the token was refused.
func TestManagerRetriesWithoutRejectedToken(t *testing.T) {
	var calls, withToken int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Token") != "" {
			withToken++
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"IP address mismatch"}`))
			return
		}
		_, _ = w.Write([]byte("1.2.3.4\n"))
	}))
	defer ts.Close()
	m := NewManager(applierFunc(func(context.Context, Feed, *FetchResult) error { return nil }))
	m.SetAPIAuth(ts.URL, "stale")
	r := &runner{feed: Feed{Name: "MYBLOCK", URL: ts.URL + "/blacklist.txt"}}
	m.runs["MYBLOCK"] = r
	m.fetchOnce(context.Background(), r)
	if calls != 2 || withToken != 1 {
		t.Fatalf("want one tokened try then one retry without, got calls=%d withToken=%d", calls, withToken)
	}
	st := m.Status()[0]
	if st.LastErr != "" || st.LastV4 != 1 || st.TokenSent {
		t.Fatalf("retry should have refreshed the list without the token: %+v", st)
	}
	if !strings.Contains(st.TokenRejected, "IP address mismatch") || !strings.Contains(st.TokenRejected, "403") {
		t.Fatalf("token_rejected should carry cfm-web's reason, got %q", st.TokenRejected)
	}
}

func TestNoTokenHintForThirdPartyFeed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()
	_, err := FetchAndParseAuth(context.Background(), nil, Feed{URL: ts.URL + "/drop.txt"},
		APIAuth{BaseURL: "https://cfm.example", Token: "x"})
	if err == nil || strings.Contains(err.Error(), "Token") {
		t.Fatalf("a third party's 403 must not mention the token, got %v", err)
	}
}

func TestRedactErrStripsAnyQuery(t *testing.T) {
	err := redactErr(errors.New(`Get "https://a/x": failed to parse Location header "https://b/y?key=SECRET x": bad`), "https://a/x")
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("query leaked: %v", err)
	}
}
