package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	webdet "cfm/internal/webdetector"
)

func adminContext(role string) context.Context {
	ctx := context.WithValue(context.Background(), webdet.CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, role)
	return ctx
}

func writeFakeCFM(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	name := "cfm"
	if runtime.GOOS == "windows" {
		name = "cfm.bat"
	}
	path := filepath.Join(dir, name)
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"dnat\" ]; then\n" +
		"  printf 'dnat-ok\\n'\n" +
		"  exit 0\n" +
		"fi\n" +
		"if [ \"$1\" = \"ssl\" ] && [ \"$2\" = \"stats\" ]; then\n" +
		"  printf '{\"issuer\":\"ok\"}'\n" +
		"  exit 0\n" +
		"fi\n" +
		"printf 'unexpected args: %s %s %s\\n' \"$1\" \"$2\" \"$3\" >&2\n" +
		"exit 1\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake cfm: %v", err)
	}
	return dir
}

func TestSystemStatusEndpoints_AdminOnlyAndPayload(t *testing.T) {
	cmdCache = sync.Map{}
	fakeDir := writeFakeCFM(t)
	oldPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", fakeDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatalf("set PATH: %v", err)
	}
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })

	mux := http.NewServeMux()
	RegisterSystemStatus(mux)

	t.Run("scoped token forbidden dnat", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/system/dnat", nil).WithContext(adminContext(webdet.CtxRoleScoped))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
		}
	})

	t.Run("admin dnat payload unchanged", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/system/dnat?cache_ttl=0", nil).WithContext(adminContext(webdet.CtxRoleAdmin))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if ok, _ := body["ok"].(bool); !ok {
			t.Fatalf("expected ok=true, got body=%v", body)
		}
		if _, ok := body["duration_ms"]; !ok {
			t.Fatalf("missing duration_ms field: %v", body)
		}
		if output, _ := body["output"].(string); output != "dnat-ok\n" {
			t.Fatalf("unexpected output: %q", output)
		}
	})

	t.Run("scoped token forbidden ssl stats", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/system/ssl/stats", nil).WithContext(adminContext(webdet.CtxRoleScoped))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
		}
	})

	t.Run("admin ssl stats payload unchanged", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/system/ssl/stats?cache_ttl=0", nil).WithContext(adminContext(webdet.CtxRoleAdmin))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if ok, _ := body["ok"].(bool); !ok {
			t.Fatalf("expected ok=true, got body=%v", body)
		}
		if _, ok := body["duration_ms"]; !ok {
			t.Fatalf("missing duration_ms field: %v", body)
		}
		stats, ok := body["stats"].(map[string]any)
		if !ok {
			t.Fatalf("expected stats object, got %T (%v)", body["stats"], body["stats"])
		}
		if issuer, _ := stats["issuer"].(string); issuer != "ok" {
			t.Fatalf("unexpected stats payload: %v", stats)
		}
	})
}
