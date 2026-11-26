package webdetector

import (
	"testing"

	"cfm/internal/proxyipfilter"
)

func TestProxiedIPFilterBlock403IsNotCounted(t *testing.T) {
	proxyipfilter.ResetForTest()
	t.Cleanup(proxyipfilter.ResetForTest)
	proxyipfilter.SetFeed("MYBLOCK", false, []string{"62.74.54.70", "45.138.12.0/24"}, nil)
	proxyipfilter.SetFeed("MYALLOW", true, []string{"45.138.12.99"}, nil)

	rec := func(ip string, status int, up string) LogRec {
		return LogRec{IP: ip, Status: status, UpstreamName: up}
	}
	// Defaults: FEED enforces, so the edge's refusal of a listed client is skipped.
	if !skip403(rec("62.74.54.70", 403, "cfm_block")) {
		t.Fatal("a 403 cfm_block for a client the filter enforces on must not count")
	}
	if !skip403(rec("45.138.12.7", 403, "cfm_block")) {
		t.Fatal("a listed subnet counts as listed")
	}
	for _, c := range []struct {
		name string
		r    LogRec
	}{
		{"an unlisted client", rec("203.0.113.5", 403, "cfm_block")},
		{"an allow cancels the block", rec("45.138.12.99", 403, "cfm_block")},
		{"the origin's own 403", rec("62.74.54.70", 403, "cfm_apache")},
		{"not a 403", rec("62.74.54.70", 404, "cfm_block")},
	} {
		if skip403(c.r) {
			t.Fatalf("%s: must still count", c.name)
		}
	}
	// Log mode refuses nothing, so nothing is skipped.
	proxyipfilter.SetModes("log", "log")
	if skip403(rec("62.74.54.70", 403, "cfm_block")) {
		t.Fatal("log mode: the client was not refused by the filter, the 403 counts")
	}
}
