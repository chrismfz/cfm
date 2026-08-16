package mcpserver

import "testing"

func TestProcessListDetailRouting(t *testing.T) {
	fd := &fakeDispatch{}
	ts := newTestServer(t, fd)
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"process_list","arguments":{"top":10,"match":"spamd","pid":1234,"details":true}}}`)

	if fd.lastPath != "/api/v1/system/processes" {
		t.Fatalf("process_list routed to %q, want /api/v1/system/processes", fd.lastPath)
	}
	want := map[string]string{
		"top":     "10",
		"match":   "spamd",
		"pid":     "1234",
		"details": "1",
	}
	for key, value := range want {
		if got := fd.lastQuery.Get(key); got != value {
			t.Errorf("%s param = %q, want %q", key, got, value)
		}
	}
}

func TestProcessListLegacyCallDoesNotOptIntoDetails(t *testing.T) {
	fd := &fakeDispatch{}
	ts := newTestServer(t, fd)
	mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"process_list","arguments":{"top":10}}}`)

	if got := fd.lastQuery.Get("top"); got != "10" {
		t.Fatalf("top param = %q, want 10", got)
	}
	for _, key := range []string{"match", "pid", "details"} {
		if got := fd.lastQuery.Get(key); got != "" {
			t.Errorf("legacy call unexpectedly set %s=%q", key, got)
		}
	}
}
