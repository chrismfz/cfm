package main

import (
	"reflect"
	"testing"
)

// The first readable file wins, so the order is behaviour: pin the list it
// held as a literal before the edge registry.
func TestEdgeBanTrustedProxyFilesUnchangedByTheEdgeRegistry(t *testing.T) {
	want := []string{
		"/usr/local/openresty/nginx/conf/trusted_proxies.conf",
		"/etc/angie/trusted_proxies.conf",
		"/etc/cfm-edge/trusted_proxies.conf",
		"/usr/share/cfm/configs/trusted_proxies.conf",
	}
	if !reflect.DeepEqual(edgeBanTrustedProxyFiles, want) {
		t.Fatalf("edgeBanTrustedProxyFiles = %v, want %v", edgeBanTrustedProxyFiles, want)
	}
}
