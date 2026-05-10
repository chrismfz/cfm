package outbound

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRenderPeerSlicePrintableSamples(t *testing.T) {
	peers := []string{
		string([]byte{45, 1, 2, 3}) + ":443",
		string([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) + ":587",
	}

	got := renderPeerSlice(peers)
	want := []string{"45.1.2.3:443", "[::1]:587"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("renderPeerSlice() = %#v, want %#v", got, want)
	}
}

func TestRenderPeersUsesPrintableSamples(t *testing.T) {
	peers := []string{
		string([]byte{127, 0, 0, 1}) + ":25",
		"malformed",
	}

	got := renderPeers(peers)
	want := "127.0.0.1:25,malformed"
	if got != want {
		t.Fatalf("renderPeers() = %q, want %q", got, want)
	}
}

func TestAlerterHTTPNotifyEventIncludesDestinationEndpoint(t *testing.T) {
	rt := newTestRuntime()
	a := NewAlerter(rt)
	v := Verdict{
		When:       time.Unix(1700000000, 0),
		UID:        2002,
		GID:        1000,
		Signal:     SignalHTTP,
		Count:      3,
		Threshold:  3,
		Window:     rt.Window,
		UniqueDsts: 2,
		Severity:   "warning",
	}

	ev := a.buildNotifyEvent(v, "siteuser", "sitegroup", "php", 1234, "/home/site", "php worker.php", "203.0.113.10", 443, EnrichInfo{}, EximSnap{})

	if ev.Extra["dst_ip"] != "203.0.113.10" {
		t.Fatalf("expected dst_ip in Extra, got %q", ev.Extra["dst_ip"])
	}
	if ev.Extra["dst_port"] != "443" {
		t.Fatalf("expected dst_port in Extra, got %q", ev.Extra["dst_port"])
	}
	if ev.Extra["dst_endpoint"] != "203.0.113.10:443" {
		t.Fatalf("expected dst_endpoint in Extra, got %q", ev.Extra["dst_endpoint"])
	}
	if !strings.Contains(ev.Reason, "outbound_dst=203.0.113.10:443") {
		t.Fatalf("expected outbound destination in reason, got %q", ev.Reason)
	}
	if ev.SrcIP != "" {
		t.Fatalf("outbound alerts should not overload SrcIP with destination IP, got %q", ev.SrcIP)
	}
}
