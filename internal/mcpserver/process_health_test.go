package mcpserver

import "testing"

func TestProcessHealthRouting(t *testing.T) {
	fd := &fakeDispatch{}
	ts := newTestServer(t, fd)
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"process_health","arguments":{}}}`)

	if fd.lastPath != "/api/v1/system/process-health" {
		t.Fatalf("process_health routed to %q, want /api/v1/system/process-health", fd.lastPath)
	}
	if len(fd.lastQuery) != 0 {
		t.Fatalf("process_health unexpectedly sent query params: %v", fd.lastQuery)
	}
}
