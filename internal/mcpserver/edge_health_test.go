package mcpserver

import "testing"

func TestEdgeHealthRouting(t *testing.T) {
	fd := &fakeDispatch{}
	ts := newTestServer(t, fd)
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"edge_health","arguments":{"window":1234}}}`)
	if fd.lastPath != "/api/v1/system/edge-health" {
		t.Errorf("edge_health routed to %q, want /api/v1/system/edge-health", fd.lastPath)
	}
	if got := fd.lastQuery.Get("window"); got != "1234" {
		t.Errorf("window = %q, want 1234", got)
	}
}
