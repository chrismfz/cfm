package healthmodel

import "testing"

func TestResolveFrontendDeterministically_DNATOwnerActiveWins(t *testing.T) {
	candidates := []frontendSignal{
		{name: "angie", ownsDNATPorts: true, active: true, binaryPresent: true, configHits: 1},
		{name: "openresty", ownsDNATPorts: true, active: false, binaryPresent: true, configHits: 1},
		{name: "nginx", ownsDNATPorts: false, active: false, binaryPresent: true, configHits: 1},
	}
	frontend, confidence := resolveFrontendDeterministically(candidates, true)
	if frontend != "angie" || confidence != "high" {
		t.Fatalf("got (%s,%s), want (angie,high)", frontend, confidence)
	}
}

func TestResolveFrontendDeterministically_StrongConfiguredFallback(t *testing.T) {
	candidates := []frontendSignal{
		{name: "angie", binaryPresent: false, configHits: 1},
		{name: "openresty", binaryPresent: true, configHits: 2},
		{name: "nginx", binaryPresent: false, configHits: 0},
	}
	frontend, confidence := resolveFrontendDeterministically(candidates, false)
	if frontend != "openresty" || confidence != "medium" {
		t.Fatalf("got (%s,%s), want (openresty,medium)", frontend, confidence)
	}
}

func TestNormalizeFrontendProcessToken(t *testing.T) {
	cases := map[string]string{
		"angie: master process /usr/sbin/angie": "angie",
		"angie: worker process":                 "angie",
		"nginx: master process /usr/sbin/nginx": "nginx",
		"nginx: worker process":                 "nginx",
		"openresty":                             "openresty",
		"openresty: worker process":             "openresty",
		"/usr/local/openresty/nginx/sbin/nginx": "openresty",
		"/usr/sbin/nginx":                       "nginx",
	}
	for in, want := range cases {
		got := normalizeFrontendProcessToken(in)
		if got != want {
			t.Fatalf("normalizeFrontendProcessToken(%q)=%q want %q", in, got, want)
		}
	}
}

func TestResolveFrontendDeterministically_DNATOnIgnoresPublicPortOnlyOwners(t *testing.T) {
	candidates := []frontendSignal{
		{name: "angie", ownsPublicPorts: true, active: true, binaryPresent: true, configHits: 1},
		{name: "openresty", ownsPublicPorts: false, active: true, binaryPresent: true, configHits: 1},
	}
	frontend, confidence := resolveFrontendDeterministically(candidates, true)
	if frontend != "" || confidence != "" {
		t.Fatalf("got (%s,%s), want empty deterministic result when no DNAT target owners", frontend, confidence)
	}
}

func TestParseSocketOwnerEntries_NormalizesListenerAndEstablishedOwners(t *testing.T) {
	listener := `LISTEN 0 511 0.0.0.0:9080 0.0.0.0:* users:(("nginx: master process /usr/sbin/nginx",pid=11,fd=7))`
	established := `ESTAB 0 0 127.0.0.1:9080 127.0.0.1:51234 users:(("nginx: worker process",pid=12,fd=14))`

	l := parseSocketOwnerEntries(listener)
	e := parseSocketOwnerEntries(established)
	if len(l) != 1 || len(e) != 1 {
		t.Fatalf("expected one parsed entry for listener and established, got %d and %d", len(l), len(e))
	}
	if l[0].name != "nginx" || e[0].name != "nginx" {
		t.Fatalf("expected normalized nginx ownership, got listener=%q established=%q", l[0].name, e[0].name)
	}
	if l[0].port != 9080 || e[0].port != 9080 {
		t.Fatalf("expected parsed local port 9080, got listener=%d established=%d", l[0].port, e[0].port)
	}
	if l[0].established {
		t.Fatalf("expected LISTEN entry to not be marked established")
	}
	if !e[0].established {
		t.Fatalf("expected ESTAB entry to be marked established")
	}
}

func TestFrontendListenerSnapshotDebugForOwners(t *testing.T) {
	s := frontendListenerSnapshot{
		listeners: []listenerEntry{
			{name: "nginx", port: 9080},
			{name: "openresty", port: 9043},
		},
		flows: []listenerEntry{
			{name: "nginx", port: 9043, established: true},
		},
	}

	debug := s.debugForOwners([]string{"nginx"}, 9080, 9043)
	if len(debug.CheckedPorts) != 2 || debug.CheckedPorts[0] != 9080 || debug.CheckedPorts[1] != 9043 {
		t.Fatalf("unexpected checked ports: %#v", debug.CheckedPorts)
	}
	if len(debug.PortOwners) != 2 {
		t.Fatalf("expected 2 port owner entries, got %d", len(debug.PortOwners))
	}
	if got := debug.PortOwners[0]; got.Port != 9080 || len(got.ListenerOwners) != 1 || got.ListenerOwners[0] != "nginx" || len(got.FlowOwners) != 0 {
		t.Fatalf("unexpected owners for :9080: %#v", got)
	}
	if got := debug.PortOwners[1]; got.Port != 9043 || len(got.ListenerOwners) != 0 || len(got.FlowOwners) != 1 || got.FlowOwners[0] != "nginx" {
		t.Fatalf("unexpected owners for :9043: %#v", got)
	}
}

func TestDetectUpstreamFromPublicPortOwnership_NginxBothPorts(t *testing.T) {
	listeners := frontendListenerSnapshot{listeners: []listenerEntry{{name: "nginx", port: 80}, {name: "nginx", port: 443}}}
	got, ok := detectUpstreamFromPublicPortOwnership(listeners)
	if !ok || got.service != "nginx" || got.reasonCode != "ports_80_443" {
		t.Fatalf("unexpected result: ok=%v got=%#v", ok, got)
	}
}

func TestDetectUpstreamFromPublicPortOwnership_HttpdBothPorts(t *testing.T) {
	listeners := frontendListenerSnapshot{listeners: []listenerEntry{{name: "httpd", port: 80}, {name: "apache", port: 443}}}
	got, ok := detectUpstreamFromPublicPortOwnership(listeners)
	if !ok || got.service != "httpd" || got.reasonCode != "ports_80_443" {
		t.Fatalf("unexpected result: ok=%v got=%#v", ok, got)
	}
}

func TestDetectUpstreamFromPublicPortOwnership_LshttpdOnePort(t *testing.T) {
	listeners := frontendListenerSnapshot{listeners: []listenerEntry{{name: "lshttpd", port: 443}}}
	got, ok := detectUpstreamFromPublicPortOwnership(listeners)
	if !ok || got.service != "lshttpd" || got.reasonCode != "ports_443_only" {
		t.Fatalf("unexpected result: ok=%v got=%#v", ok, got)
	}
}

func TestDetectUpstreamFromPublicPortOwnership_MixedOwners(t *testing.T) {
	listeners := frontendListenerSnapshot{listeners: []listenerEntry{{name: "nginx", port: 80}, {name: "httpd", port: 443}}}
	got, ok := detectUpstreamFromPublicPortOwnership(listeners)
	if !ok || got.service != "mixed" || got.reasonCode != "mixed_80_443:nginx_httpd" {
		t.Fatalf("unexpected result: ok=%v got=%#v", ok, got)
	}
}

func TestDetectUpstreamFromPublicPortOwnership_NoListener(t *testing.T) {
	listeners := frontendListenerSnapshot{}
	_, ok := detectUpstreamFromPublicPortOwnership(listeners)
	if ok {
		t.Fatalf("expected no ownership decision")
	}
}
