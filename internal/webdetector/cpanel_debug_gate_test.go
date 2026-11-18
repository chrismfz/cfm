package webdetector

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Failure detail on /api/v1/cpanel/user-info is for the plugin's own direct
// loopback call that asks for it, nothing else.
func TestCfmDebugEnabledForRequest(t *testing.T) {
	mk := func(remote string, hdr map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/cpanel/user-info", nil)
		r.RemoteAddr = remote
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}
	cases := []struct {
		name string
		r    *http.Request
		want bool
	}{
		{"loopback, asked", mk("127.0.0.1:5000", map[string]string{"X-CFM-Debug": "1"}), true},
		{"loopback v6, asked", mk("[::1]:5000", map[string]string{"X-CFM-Debug": "1"}), true},
		{"loopback, not asked", mk("127.0.0.1:5000", nil), false},
		{"via edge, asked", mk("127.0.0.1:5000", map[string]string{"X-CFM-Debug": "1", "X-Real-IP": "203.0.113.9", "X-Forwarded-For": "203.0.113.9"}), false},
		{"remote, asked", mk("203.0.113.9:5000", map[string]string{"X-CFM-Debug": "1"}), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := cfmDebugEnabledForRequest(c.r); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
