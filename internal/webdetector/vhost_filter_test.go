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
