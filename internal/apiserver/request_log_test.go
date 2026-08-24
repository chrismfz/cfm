package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestLogPathNeverIncludesQueryCredentials(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://host/api/v1/embed/bootstrap?code=live-secret&next=%2F", nil)
	got := requestLogPath(r)
	if got != "/api/v1/embed/bootstrap" || strings.Contains(got, "live-secret") {
		t.Fatalf("requestLogPath=%q, want path without query", got)
	}
}
