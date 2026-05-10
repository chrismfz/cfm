package outbound

import (
	"reflect"
	"testing"
)

func TestRenderPeerSlicePrintableSamples(t *testing.T) {
	peers := []string{
		string([]byte{45, 1, 2, 3}) + ":443",
		string([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) + ":587",
	}

	got := renderPeerSlice(peers)
	want := []string{"45.1.2.3:443", "[::1]:587"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("renderPeerSlice() = %#v, want %#v", got, want)
	}
}

func TestRenderPeersUsesPrintableSamples(t *testing.T) {
	peers := []string{
		string([]byte{127, 0, 0, 1}) + ":25",
		"malformed",
	}

	got := renderPeers(peers)
	want := "127.0.0.1:25,malformed"
	if got != want {
		t.Fatalf("renderPeers() = %q, want %q", got, want)
	}
}
