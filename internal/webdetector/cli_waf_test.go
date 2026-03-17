package webdetector

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunWAFEngineSummary(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/waf/engine/summary" {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("hours"); got != "12" {
			t.Fatalf("expected hours=12 got %q", got)
		}
		if got := r.URL.Query().Get("limit"); got != "5" {
			t.Fatalf("expected limit=5 got %q", got)
		}
		if got := r.URL.Query().Get("top"); got != "3" {
			t.Fatalf("expected top=3 got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hours":12,"total_events":1,"blocked_events":1,"unique_hosts":1,"unique_ips":1,"top_rule_bases":[{"key":"WAF_AUTH_BURST","count":1}],"top_rules":[{"key":"WAF_AUTH_BURST:AUTH_WP_LOGIN","count":1}],"top_hosts":[{"key":"example.com","count":1}],"top_ips":[{"key":"1.2.3.4","count":1}],"rows":[{"ts_unix":1710000000,"host":"example.com","ip":"1.2.3.4","uri":"/wp-login.php","method":"get","status":403,"reason":"WAF_AUTH_BURST:AUTH_WP_LOGIN"}]}`))
	}))
	defer ts.Close()

	if err := runWAFEngineSummary(ts.URL, []string{"--hours", "12", "--limit", "5", "--top", "3"}); err != nil {
		t.Fatalf("runWAFEngineSummary returned error: %v", err)
	}
}
