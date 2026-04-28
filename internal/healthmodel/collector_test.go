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
		"angie: master process /usr/sbin/angie":  "angie",
		"angie: worker process":                  "angie",
		"nginx: master process /usr/sbin/nginx":  "nginx",
		"nginx: worker process":                  "nginx",
		"openresty":                              "openresty",
		"openresty: worker process":              "openresty",
		"/usr/local/openresty/nginx/sbin/nginx": "openresty",
		"/usr/sbin/nginx":                        "nginx",
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
}
