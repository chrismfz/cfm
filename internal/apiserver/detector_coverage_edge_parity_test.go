package apiserver

import (
	"reflect"
	"testing"
)

func TestWebdetectorCoverageUnitsUnchangedByTheEdgeRegistry(t *testing.T) {
	want := []string{"angie", "openresty", "cfm-edge", "nginx", "httpd", "apache2", "lsws"}
	if got := detectorUnits["webdetector"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("webdetector units = %v, want %v", got, want)
	}
}
