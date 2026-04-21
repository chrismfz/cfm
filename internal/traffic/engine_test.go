package traffic

import "testing"

func TestNormalizeProtocol(t *testing.T) {
	tcs := map[string]string{
		"tcp":       "TCP",
		"6":         "TCP",
		"udp6":      "UDP",
		"17":        "UDP",
		"icmp6":     "ICMP",
		"58":        "ICMP",
		"":          "unknown",
		"sctp":      "sctp",
		"something": "something",
	}
	for in, want := range tcs {
		if got := normalizeProtocol(in); got != want {
			t.Fatalf("normalizeProtocol(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestServiceBucketHeuristic(t *testing.T) {
	f := FlowSample{Protocol: "TCP", SrcPort: 54321, DstPort: 443}
	if got, want := serviceBucket(f), "https/TCP/443"; got != want {
		t.Fatalf("serviceBucket=%q, want %q", got, want)
	}

	f = FlowSample{Protocol: "UDP", SrcPort: 5353, DstPort: 60000}
	if got, want := serviceBucket(f), "port/UDP/5353"; got != want {
		t.Fatalf("serviceBucket=%q, want %q", got, want)
	}
}

func TestProcessCapabilities(t *testing.T) {
	flows := map[string]FlowSample{
		"a": {FlowID: "a", ProcessName: "nginx", PID: 1024},
		"b": {FlowID: "b", ProcessName: "unknown"},
	}
	if !processSupported(flows) {
		t.Fatal("expected processSupported true")
	}
	if !processPartial(flows) {
		t.Fatal("expected processPartial true")
	}

	flows = map[string]FlowSample{
		"c": {FlowID: "c", ProcessName: "unknown"},
	}
	if processSupported(flows) {
		t.Fatal("expected processSupported false")
	}
	if processPartial(flows) {
		t.Fatal("expected processPartial false")
	}
}
