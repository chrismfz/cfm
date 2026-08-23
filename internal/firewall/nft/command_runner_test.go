package nft

import "testing"

func TestLimitedBufferCapsStoredOutputWithoutShortWrite(t *testing.T) {
	b := limitedBuffer{max: 4}
	n, err := b.Write([]byte("abcdefgh"))
	if err != nil || n != 8 {
		t.Fatalf("write n=%d err=%v", n, err)
	}
	if b.String() != "abcd" || !b.truncated {
		t.Fatalf("buffer=%q truncated=%v", b.String(), b.truncated)
	}
}

func TestTailBufferKeepsActualEnd(t *testing.T) {
	b := tailBuffer{max: 5}
	for _, chunk := range []string{"abc", "def", "ghij"} {
		n, err := b.Write([]byte(chunk))
		if err != nil || n != len(chunk) {
			t.Fatalf("write %q n=%d err=%v", chunk, n, err)
		}
	}
	if got := b.String(); got != "fghij" {
		t.Fatalf("tail=%q, want fghij", got)
	}
}
