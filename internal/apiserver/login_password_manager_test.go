package apiserver

import (
	"strings"
	"testing"
)

func TestLoginHTMLPasswordManagerSemantics(t *testing.T) {
	checks := []string{
		`<form id="loginForm">`,
		`name="username"`,
		`autocomplete="username"`,
		`name="password"`,
		`autocomplete="current-password"`,
		`type="submit"`,
		`getElementById('loginForm').addEventListener('submit'`,
	}

	for _, want := range checks {
		if !strings.Contains(loginHTML, want) {
			t.Fatalf("login HTML missing password-manager semantic %q", want)
		}
	}
}
