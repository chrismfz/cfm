package mcpserver

import (
	"strings"
	"testing"
)

// alerts / alerts_summary pass every filter (from the embedded input struct)
// through as query params to their fixed endpoints.
func TestAlertsToolsDispatchFilters(t *testing.T) {
	fd := &fakeDispatch{body: []byte(`{"rows":[]}`)}
	ts := newTestServer(t, fd)

	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"alerts","arguments":{"hours":168,"category":"WAF","country":"GR","asn":"6799","q":"sqli","limit":20,"cursor":"1730000000.5"}}}`)
	if fd.lastPath != "/api/v1/alerts" {
		t.Fatalf("alerts dispatched to %q", fd.lastPath)
	}
	for k, want := range map[string]string{"hours": "168", "category": "WAF", "country": "GR", "asn": "6799", "q": "sqli", "limit": "20", "cursor": "1730000000.5"} {
		if got := fd.lastQuery.Get(k); got != want {
			t.Errorf("alerts %s = %q, want %q", k, got, want)
		}
	}

	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"alerts_summary","arguments":{"country":"GR","group_by":"kind,asn","top":10}}}`)
	if fd.lastPath != "/api/v1/alerts/summary" {
		t.Fatalf("alerts_summary dispatched to %q", fd.lastPath)
	}
	if fd.lastQuery.Get("group_by") != "kind,asn" || fd.lastQuery.Get("country") != "GR" || fd.lastQuery.Get("top") != "10" {
		t.Errorf("alerts_summary query = %v", fd.lastQuery)
	}

	_, body := mcpPost(t, ts, testAdminToken, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	for _, want := range []string{`"alerts"`, `"alerts_summary"`, `"group_by"`, `"min_severity"`} {
		if !strings.Contains(body, want) {
			t.Errorf("tools/list missing %s", want)
		}
	}
}
