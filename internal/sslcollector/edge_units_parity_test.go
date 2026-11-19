package sslcollector

import (
	"reflect"
	"testing"
)

func TestEdgeServiceNamesUnchangedByTheEdgeRegistry(t *testing.T) {
	if want := []string{"angie", "openresty"}; !reflect.DeepEqual(edgeServiceNames, want) {
		t.Fatalf("edgeServiceNames = %v, want %v", edgeServiceNames, want)
	}
}
