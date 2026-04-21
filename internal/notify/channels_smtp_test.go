package notify

import "testing"

func TestSanitizeHeaderValueRejectsCRLF(t *testing.T) {
	if _, err := sanitizeHeaderValue("ok\r\nBcc: x@example.test"); err == nil {
		t.Fatal("expected CRLF header injection to be rejected")
	}
}

func TestSanitizeAddressRejectsCRLF(t *testing.T) {
	if _, err := sanitizeAddress("victim@example.test\r\nCc: pwn@example.test"); err == nil {
		t.Fatal("expected address CRLF injection to be rejected")
	}
}

func TestSanitizeAddressAcceptsValidAddress(t *testing.T) {
	got, err := sanitizeAddress(" Ops Team <ops@example.test> ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "ops@example.test" {
		t.Fatalf("unexpected normalized address %q", got)
	}
}
