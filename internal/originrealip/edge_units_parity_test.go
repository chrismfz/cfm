package originrealip

import (
	"reflect"
	"testing"
)

func TestEdgeUnitsUnchangedByTheEdgeRegistry(t *testing.T) {
	if want := []string{"angie", "openresty", "cfm-edge"}; !reflect.DeepEqual(edgeUnits, want) {
		t.Fatalf("edgeUnits = %v, want %v", edgeUnits, want)
	}
}
