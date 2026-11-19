package dnat

import "testing"

func TestDnatTargetLabel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		label string
	}{
		{name: "no service", input: "", label: "CFM edge proxy ports"},
		{name: "with service", input: "angie", label: "CFM edge proxy ports (angie)"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := dnatTargetLabel(tc.input); got != tc.label {
				t.Fatalf("dnatTargetLabel(%q) = %q, want %q", tc.input, got, tc.label)
			}
		})
	}
}

func TestNormalizeEdgeService(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "", want: ""},
		{input: "openresty: worker process", want: "openresty"},
		{input: "/usr/local/openresty/nginx/sbin/nginx", want: "openresty"},
		{input: "angie: master process", want: "angie"},
		{input: "nginx: worker process", want: "nginx"},
		{input: "cfm-edge", want: "cfm-edge"}, // comm
		{input: "nginx: master process /usr/sbin/cfm-edge", want: "cfm-edge"},
		// Processes that only mention cfm-edge are not the edge: CFM's own
		// pre-start script runs on every OpenResty / Angie node.
		{input: "/bin/sh /usr/share/cfm/scripts/cfm-edge-listen-v6.sh prestart", want: ""},
		{input: "tail -f /var/log/cfm-edge/error.log", want: ""},
		{input: "less /etc/cfm-edge/trusted_proxies.conf", want: ""},
		{input: "apache2", want: ""},
	}

	for _, tc := range tests {
		if got := normalizeEdgeService(tc.input); got != tc.want {
			t.Fatalf("normalizeEdgeService(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
