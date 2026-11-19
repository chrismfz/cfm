package dnat

import (
	"reflect"
	"testing"
)

// The dnat edge lists take their values from edgeengine.Profiles; these pin
// what they held as literals before.
func TestDNATEdgeListsUnchangedByTheEdgeRegistry(t *testing.T) {
	if want := []string{
		"/etc/angie/cfm-panel-listeners.conf",
		"/usr/local/openresty/nginx/conf/cfm-panel-listeners.conf",
		"configs/cfm-panel-listeners.conf.in",
	}; !reflect.DeepEqual(panelListenerChallengeConfigPaths, want) {
		t.Errorf("panelListenerChallengeConfigPaths = %v, want %v", panelListenerChallengeConfigPaths, want)
	}
	if want := []string{"angie", "openresty"}; !reflect.DeepEqual(edgeCommands(), want) {
		t.Errorf("edgeCommands() = %v, want %v", edgeCommands(), want)
	}
	for path, want := range map[string]string{
		"/etc/angie/cfm-panel-listeners.conf":                            "angie",
		"/usr/local/openresty/nginx/conf/cfm-panel-listeners.conf":       "openresty",
		"/tmp/x/etc/angie/cfm-panel-listeners.conf":                      "angie",
		"/tmp/x/usr/local/openresty/nginx/conf/cfm-panel-listeners.conf": "openresty",
		"configs/cfm-panel-listeners.conf.in":                            "",
	} {
		if got := panelListenerConfigPathService(path); got != want {
			t.Errorf("panelListenerConfigPathService(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestWorkerUserConfsUnchangedByTheEdgeRegistry(t *testing.T) {
	want := []string{"/etc/nginx/nginx.conf", "/usr/local/openresty/nginx/conf/nginx.conf", "/etc/angie/angie.conf"}
	if !reflect.DeepEqual(workerUserConfs(), want) {
		t.Fatalf("workerUserConfs() = %v, want %v", workerUserConfs(), want)
	}
}
