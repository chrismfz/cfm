package blocklists

import (
	"context"
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
