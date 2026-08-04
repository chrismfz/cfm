package webdetector

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestIsAdminRequestRequiresExplicitAuthMarkers(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if IsAdminRequest(req) {
		t.Fatalf("expected unauthenticated request to be non-admin")
	}

	ctxAuthnOnly := context.WithValue(req.Context(), CtxAuthnKey{}, true)
	if IsAdminRequest(req.WithContext(ctxAuthnOnly)) {
		t.Fatalf("expected authn-only request to be non-admin")
	}

	ctxRoleOnly := context.WithValue(req.Context(), CtxRoleKey{}, CtxRoleAdmin)
	if IsAdminRequest(req.WithContext(ctxRoleOnly)) {
		t.Fatalf("expected role-only request to be non-admin")
	}
}

func TestIsAdminRequestAcceptsOnlyAdminRole(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)

	ctxScoped := context.WithValue(req.Context(), CtxAuthnKey{}, true)
	ctxScoped = context.WithValue(ctxScoped, CtxRoleKey{}, CtxRoleScoped)
	if IsAdminRequest(req.WithContext(ctxScoped)) {
		t.Fatalf("expected scoped role to be non-admin")
	}

	ctxAdmin := context.WithValue(req.Context(), CtxAuthnKey{}, true)
	ctxAdmin = context.WithValue(ctxAdmin, CtxRoleKey{}, CtxRoleAdmin)
	if !IsAdminRequest(req.WithContext(ctxAdmin)) {
		t.Fatalf("expected admin role to be admin")
	}
}

// vhostScopeFromContext must return nil (the "no restriction" sentinel) ONLY
// for admin/loopback. A scoped role with no scope map must get a non-nil EMPTY
// set so every nil==admin caller fails closed for a vhost-less scoped token.
func TestVhostScopeFromContext_ScopedNilYieldsEmptyNotNil(t *testing.T) {
	// Admin (role admin, no scope) → nil = no restriction.
	adminCtxVal := context.WithValue(context.Background(), CtxRoleKey{}, CtxRoleAdmin)
	if s := vhostScopeFromContext(adminCtxVal); s != nil {
		t.Fatalf("admin: expected nil scope, got %v", s)
	}

	// No role at all (e.g. internal/loopback) → nil, unchanged.
	if s := vhostScopeFromContext(context.Background()); s != nil {
		t.Fatalf("no-role: expected nil scope, got %v", s)
	}

	// Scoped role with NO scope map → non-nil empty set (fails closed).
	scopedNil := context.WithValue(context.Background(), CtxRoleKey{}, CtxRoleScoped)
	got := vhostScopeFromContext(scopedNil)
	if got == nil {
		t.Fatalf("vhost-less scoped: expected non-nil empty set, got nil (would read as admin)")
	}
	if len(got) != 0 {
		t.Fatalf("vhost-less scoped: expected empty set, got %v", got)
	}
	if vhostAllowed("victim.com", got) {
		t.Fatalf("empty scope must not allow any host")
	}

	// Scoped role WITH a scope map → returned as-is.
	scopedSet := map[string]struct{}{"a.com": {}}
	ctxSet := context.WithValue(context.Background(), CtxRoleKey{}, CtxRoleScoped)
	ctxSet = context.WithValue(ctxSet, CtxScopeKey{}, scopedSet)
	if s := vhostScopeFromContext(ctxSet); len(s) != 1 || !vhostAllowed("a.com", s) {
		t.Fatalf("scoped-with-hosts: expected {a.com}, got %v", s)
	}
}
