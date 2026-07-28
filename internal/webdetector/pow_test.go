package webdetector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"
)

const testPowBind = "Mozilla/5.0 (X11; Linux x86_64) Chrome/118.0.0.0|cookievalue"

func testPowSecret() []byte { return []byte("test-secret-not-a-real-key") }

func testNonce() []byte {
	n := make([]byte, 16)
	for i := range n {
		n[i] = byte(i * 7)
	}
	return n
}

// issuePowChallengeSeconds mints a token exactly the way the pre-upgrade binary
// did: an issue timestamp in whole seconds. Used to prove such a token still
// verifies, so a rolling upgrade does not fail every in-flight solve.
func issuePowChallengeSeconds(secret []byte, now time.Time, difficulty int, nonce16 []byte, bind string) string {
	buf := make([]byte, 8+2+16)
	binary.BigEndian.PutUint64(buf[0:8], uint64(now.Unix()))
	binary.BigEndian.PutUint16(buf[8:10], uint16(difficulty))
	copy(buf[10:26], nonce16)

	mac := hmac.New(sha256.New, secret)
	mac.Write(buf)
	mac.Write([]byte{0})
	mac.Write([]byte(bind))
	return base64.RawURLEncoding.EncodeToString(append(buf, mac.Sum(nil)...))
}

func TestPowChallengeMillisRoundTrip(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 500_000_000, time.UTC)
	tok, err := issuePowChallenge(testPowSecret(), now, 16, testNonce(), testPowBind)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	issued, diff, nonce, ok := verifyPowChallenge(testPowSecret(), tok, testPowBind, defaultPowConfig(), now.Add(1200*time.Millisecond))
	if !ok {
		t.Fatal("token minted in milliseconds failed verification")
	}
	if diff != 16 {
		t.Errorf("difficulty = %d, want 16", diff)
	}
	if string(nonce) != string(testNonce()) {
		t.Error("nonce did not round-trip")
	}
	// Sub-second precision is the whole point of the ms encoding.
	if !issued.Equal(now) {
		t.Errorf("issued = %v, want %v (millisecond precision lost)", issued, now)
	}
}

// A token minted by the previous binary (seconds) must keep verifying, otherwise
// upgrading takes down every solve in flight for the length of the PoW TTL.
func TestPowChallengeAcceptsLegacySecondsToken(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	tok := issuePowChallengeSeconds(testPowSecret(), now, 16, testNonce(), testPowBind)

	issued, diff, _, ok := verifyPowChallenge(testPowSecret(), tok, testPowBind, defaultPowConfig(), now.Add(2*time.Second))
	if !ok {
		t.Fatal("legacy seconds-encoded token rejected; rolling upgrade would break in-flight solves")
	}
	if diff != 16 {
		t.Errorf("difficulty = %d, want 16", diff)
	}
	if !issued.Equal(now) {
		t.Errorf("issued = %v, want %v", issued, now)
	}
}

func TestPowChallengeRejectsTamperedAndStale(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	tok, err := issuePowChallenge(testPowSecret(), now, 16, testNonce(), testPowBind)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	t.Run("wrong bind", func(t *testing.T) {
		if _, _, _, ok := verifyPowChallenge(testPowSecret(), tok, "other-ua|other-cookie", defaultPowConfig(), now); ok {
			t.Error("token verified against a different bind")
		}
	})
	t.Run("wrong secret", func(t *testing.T) {
		if _, _, _, ok := verifyPowChallenge([]byte("different-secret"), tok, testPowBind, defaultPowConfig(), now); ok {
			t.Error("token verified under a different secret")
		}
	})
	t.Run("expired", func(t *testing.T) {
		if _, _, _, ok := verifyPowChallenge(testPowSecret(), tok, testPowBind, defaultPowConfig(), now.Add(defaultPowTTL+time.Second)); ok {
			t.Error("expired token verified")
		}
	})
	t.Run("issued in the future", func(t *testing.T) {
		if _, _, _, ok := verifyPowChallenge(testPowSecret(), tok, testPowBind, defaultPowConfig(), now.Add(-time.Minute)); ok {
			t.Error("token from the future verified")
		}
	})
	t.Run("flipped byte", func(t *testing.T) {
		raw, err := base64.RawURLEncoding.DecodeString(tok)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		raw[12] ^= 0xFF // inside the nonce, covered by the MAC
		bad := base64.RawURLEncoding.EncodeToString(raw)
		if _, _, _, ok := verifyPowChallenge(testPowSecret(), bad, testPowBind, defaultPowConfig(), now); ok {
			t.Error("token with a flipped nonce byte verified")
		}
	})
}

func TestPowSolveLatencyMS(t *testing.T) {
	issued := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		issued time.Time
		now    time.Time
		want   int64
	}{
		{"sub-second resolution", issued, issued.Add(640 * time.Millisecond), 640},
		{"multi-second", issued, issued.Add(3 * time.Second), 3000},
		{"same instant", issued, issued, 0},
		{"zero issue time is unknown", time.Time{}, issued, -1},
		{"clock went backwards is unknown", issued, issued.Add(-time.Second), -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := powSolveLatencyMS(tc.issued, tc.now); got != tc.want {
				t.Errorf("powSolveLatencyMS = %d, want %d", got, tc.want)
			}
		})
	}
}

// The measured honest-browser solve time at the default difficulty is ~1.3s on a
// desktop CPU, so second-granularity timestamps rounded almost every real solve
// to 0 and made the signal useless. Guard the property that made it useless.
func TestPowIssuedTimestampHasMillisecondResolution(t *testing.T) {
	base := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	a, err := issuePowChallenge(testPowSecret(), base, 16, testNonce(), testPowBind)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	b, err := issuePowChallenge(testPowSecret(), base.Add(250*time.Millisecond), 16, testNonce(), testPowBind)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if a == b {
		t.Fatal("tokens issued 250ms apart are identical; sub-second resolution is lost")
	}

	_, issuedA, _, _, _, _ := parsePowChallenge(a)
	_, issuedB, _, _, _, _ := parsePowChallenge(b)
	if got := issuedB.Sub(issuedA); got != 250*time.Millisecond {
		t.Errorf("issue delta = %v, want 250ms", got)
	}
}
