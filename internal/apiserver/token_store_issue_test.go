package apiserver

import (
	"testing"
	"time"
)

func TestIssue_FailsClosedOnEmptyScope(t *testing.T) {
	store := NewTokenStore()

	// A scoped (non-admin) token with no vhosts / db-users / databases has no
	// boundary and must be refused.
	if tok := store.Issue(nil, nil, nil, "viewer", "no-scope", time.Hour); tok != nil {
		t.Fatalf("expected nil for scoped token with empty scope, got id=%s", tok.ID)
	}
	if tok := store.Issue([]string{}, []string{}, []string{}, "viewer", "empty-slices", time.Hour); tok != nil {
		t.Fatalf("expected nil for scoped token with empty-slice scope, got id=%s", tok.ID)
	}

	// Any one scope dimension is enough.
	if tok := store.Issue([]string{"mysite.com"}, nil, nil, "viewer", "vhost", time.Hour); tok == nil {
		t.Fatalf("expected a token when vhost scope is present")
	}
	if tok := store.Issue(nil, []string{"chris_wp"}, nil, "viewer", "dbuser", time.Hour); tok == nil {
		t.Fatalf("expected a token when db_users scope is present")
	}
	if tok := store.Issue(nil, nil, []string{"chris_db"}, "viewer", "database", time.Hour); tok == nil {
		t.Fatalf("expected a token when databases scope is present")
	}

	// Admin-role tokens are intentionally unscoped and remain allowed.
	if tok := store.Issue(nil, nil, nil, "admin", "admin", time.Hour); tok == nil {
		t.Fatalf("expected admin-role token to be allowed without scope")
	}
}
