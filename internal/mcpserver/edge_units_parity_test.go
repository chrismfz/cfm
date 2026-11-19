package mcpserver

import (
	"reflect"
	"testing"
)

func TestEdgeEngineUnitsUnchangedByTheEdgeRegistry(t *testing.T) {
	want := map[string]bool{"angie": true, "openresty": true, "cfm-edge": true, "nginx": true}
	if !reflect.DeepEqual(edgeEngineUnits, want) {
		t.Fatalf("edgeEngineUnits = %v, want %v", edgeEngineUnits, want)
	}
}
