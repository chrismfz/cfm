package healthmodel

import "testing"

func TestResolveFrontendDeterministically_DNATOwnerActiveWins(t *testing.T) {
	candidates := []frontendSignal{
		{name: "angie", ownsDNATPorts: true, active: true, binaryPresent: true, configHits: 1},
		{name: "openresty", ownsDNATPorts: true, active: false, binaryPresent: true, configHits: 1},
		{name: "nginx", ownsDNATPorts: false, active: false, binaryPresent: true, configHits: 1},
	}
	frontend, confidence := resolveFrontendDeterministically(candidates)
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
	frontend, confidence := resolveFrontendDeterministically(candidates)
	if frontend != "openresty" || confidence != "medium" {
		t.Fatalf("got (%s,%s), want (openresty,medium)", frontend, confidence)
	}
}

