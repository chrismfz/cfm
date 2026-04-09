// internal/clihttp/client.go
//
// Shared HTTP client for all cfm CLI subcommands (cfm webtop, cfm mysqltop, etc.).
//
// Usage:
//   // In main.go, before calling RunWebTop / RunMySQLTop:
//   clihttp.SetToken(apiAuthToken())
//
//   // In CLI packages, replace http.Get/http.Post/http.DefaultClient.Do with:
//   clihttp.Get(url)
//   clihttp.Post(url, contentType, body)
//   clihttp.Do(req)
//
// When AUTH_TOKEN is set, every outgoing request carries:
//   Authorization: Bearer <token>
//
// When AUTH_TOKEN is empty (not configured) the behaviour is identical to
// bare http.Get / http.Post — no header is added, loopback bypass still works.

package clihttp

import (
	"io"
	"net/http"
	"sync/atomic"
)

var _token atomic.Value // stores string

// SetToken stores the AUTH_TOKEN to be sent on every CLI API request.
// Call once from main.go before any CLI command runs.
// Safe to call from multiple goroutines (though in practice called once).
func SetToken(tok string) {
	_token.Store(tok)
}

// Token returns the currently configured CLI auth token.
func Token() string {
	if v := _token.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// Do executes req via http.DefaultClient, injecting the Bearer token when set.
// Drop-in replacement for http.DefaultClient.Do(req).
func Do(req *http.Request) (*http.Response, error) {
	if tok := Token(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return http.DefaultClient.Do(req)
}

// Get issues a GET request with the Bearer token injected.
// Drop-in replacement for http.Get(url).
func Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return Do(req)
}

// Post issues a POST request with the Bearer token injected.
// Drop-in replacement for http.Post(url, contentType, body).
func Post(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return Do(req)
}
