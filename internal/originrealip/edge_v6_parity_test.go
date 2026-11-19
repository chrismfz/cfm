package originrealip

import (
	"reflect"
	"testing"
)

func TestEdgeV6ListenFilesUnchangedByTheEdgeRegistry(t *testing.T) {
	want := []string{
		"/usr/local/openresty/nginx/conf/cfm-listen-v6-http.conf",
		"/usr/local/openresty/nginx/conf/cfm-listen-v6-https.conf",
		"/etc/angie/cfm-listen-v6-http.conf",
		"/etc/angie/cfm-listen-v6-https.conf",
	}
	if !reflect.DeepEqual(edgeV6ListenFiles(), want) {
		t.Fatalf("edgeV6ListenFiles() = %v, want %v", edgeV6ListenFiles(), want)
	}
}
