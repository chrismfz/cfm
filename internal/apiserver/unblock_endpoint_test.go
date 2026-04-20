package apiserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUnblockRejectsNonPOSTMethods(t *testing.T) {
	h := makeUnblockHandler(nil, "/tmp")
	req := httptest.NewRequest(http.MethodGet, "/unblock?ip=192.0.2.10", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
	if allow := rr.Header().Get("Allow"); allow != http.MethodPost {
		t.Fatalf("expected Allow POST, got %q", allow)
	}
}
