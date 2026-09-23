// internal/webdetector/cli_site_cache_test.go
package webdetector

import (
	"encoding/json"
	"strings"
	"testing"
)

// `set` sends ONLY the flags given (a merge patch), so a retune never resets
// the omitted tier or the cookie settings.
func TestParseSiteCacheSetFlags(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags []string
		want  string // the JSON the CLI sends
	}{
		{"micro ttl only", []string{"--micro-ttl", "30s"},
			`{"host":"a.com","micro":{"ttl":"30s"}}`},
		{"enable static", []string{"--static", "static_lean", "--static-ttl=7d"},
			`{"host":"a.com","static":{"enabled":true,"recipe":"static_lean","ttl":"7d"}}`},
		{"static off keeps recipe", []string{"--static", "off"},
			`{"host":"a.com","static":{"enabled":false}}`},
		{"micro=OFF", []string{"--micro=OFF"},
			`{"host":"a.com","micro":{"enabled":false}}`},
		{"no strict", []string{"--no-strict-cookies"},
			`{"host":"a.com","strict_cookies":false}`},
		{"strict", []string{"--strict-cookies"},
			`{"host":"a.com","strict_cookies":true}`},
		{"auth cookies replace", []string{"--auth-cookies", "a, b"},
			`{"host":"a.com","auth_cookies":["a","b"]}`},
		{"auth cookies clear", []string{"--no-auth-cookies"},
			`{"host":"a.com","auth_cookies":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parseSiteCacheSetFlags("a.com", tc.flags)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			b, _ := json.Marshal(p)
			if string(b) != tc.want {
				t.Fatalf("sent %s\nwant %s", b, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		flags []string
		err   string
	}{
		{"no flags", nil, "nothing to change"},
		{"missing value", []string{"--micro"}, "missing value"},
		{"value is a flag", []string{"--micro", "--strict-cookies"}, "missing value"},
		{"empty value", []string{"--static-ttl="}, "empty value"},
		{"empty auth list", []string{"--auth-cookies=,"}, "--no-auth-cookies"},
		{"switch with value", []string{"--strict-cookies=1"}, "takes no value"},
		{"unknown", []string{"--bogus"}, "unknown flag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseSiteCacheSetFlags("a.com", tc.flags); err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.err)
			}
		})
	}
}
