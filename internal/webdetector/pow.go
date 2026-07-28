// internal/webdetector/pow.go
package webdetector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// POW params (μπορείς αργότερα να τα κάνεις config/env)
const (
	defaultPowEnabled    = true
	defaultPowDifficulty = 16              // bits of leading zeros (18–22 είναι “ok”)
	defaultPowTTL        = 2 * time.Minute // challenge must be solved quickly
	maxPowSolutionLen    = 64
)

// powEpochMillisMin separates a millisecond issue timestamp from a second one.
// Unix *seconds* stay below it until the year ~5138 and Unix *milliseconds*
// passed it in 1973, so the two encodings are unambiguous for any timestamp CFM
// will ever mint or verify. Tokens are minted in milliseconds (needed to measure
// real solve latency — see challenge_server.go), but a token minted by an older
// binary carries seconds and must keep verifying across a rolling upgrade,
// otherwise every in-flight solve fails for the length of the PoW TTL.
const powEpochMillisMin = int64(1e11)

// PowConfig: έτοιμο για επέκταση (π.χ. ανά vhost, ανά method, κλπ)
type PowConfig struct {
	Enabled    bool
	Difficulty int
	TTL        time.Duration
}

func defaultPowConfig() PowConfig {
	return PowConfig{
		Enabled:    defaultPowEnabled,
		Difficulty: defaultPowDifficulty,
		TTL:        defaultPowTTL,
	}
}

// powChallenge is a compact token we embed in HTML.
// Format: base64url( ts_unix_ms(8 bytes) || difficulty(2 bytes) || nonce(16 bytes) || mac(32 bytes) )
//
// The issue timestamp is in milliseconds so that verify can measure the real
// client-side solve latency (issue → submit) without keeping any server-side
// state: the token itself is the clock. Second granularity was useless for that
// — an honest browser solves the default difficulty in ~1s, which rounds to 0.
func issuePowChallenge(secret []byte, now time.Time, difficulty int, nonce16 []byte, bind string) (string, error) {
	if len(nonce16) != 16 {
		return "", fmt.Errorf("nonce must be 16 bytes")
	}
	if difficulty < 8 || difficulty > 30 {
		return "", fmt.Errorf("bad difficulty: %d", difficulty)
	}

	// Refuse to mint a token the decoder would read back as seconds. A host with
	// no RTC and no NTP yet boots at the Unix epoch, and 30 seconds of uptime
	// later every minted token carries a millisecond value below the threshold —
	// so it decodes as a far-future seconds timestamp, fails its freshness check,
	// and every correctly-solved challenge is rejected with no clue why. Failing
	// the issue is loud; failing every verify is not.
	if now.UnixMilli() < powEpochMillisMin {
		return "", fmt.Errorf("system clock is before %s; refusing to mint a PoW token",
			time.UnixMilli(powEpochMillisMin).UTC().Format(time.RFC3339))
	}

	ts := uint64(now.UnixMilli())
	buf := make([]byte, 8+2+16)
	binary.BigEndian.PutUint64(buf[0:8], ts)
	binary.BigEndian.PutUint16(buf[8:10], uint16(difficulty))
	copy(buf[10:26], nonce16)

	// MAC binds challenge to (ua|cookie) here so the browser can reproduce bind for PoW hashing.
	mac := hmac.New(sha256.New, secret)
	mac.Write(buf)
	mac.Write([]byte{0})
	mac.Write([]byte(bind))
	sum := mac.Sum(nil)

	full := append(buf, sum...)
	return base64.RawURLEncoding.EncodeToString(full), nil
}

// parsePowChallenge splits a token into its fields. It returns the raw 26-byte
// header verbatim: the MAC covers those exact bytes, so verification must
// re-MAC them rather than re-encode a decoded timestamp — otherwise a token
// minted in seconds by an older binary would fail its own MAC here.
func parsePowChallenge(tok string) (hdr []byte, issued time.Time, difficulty int, nonce16 []byte, mac []byte, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(tok))
	if err != nil || len(raw) != 8+2+16+32 {
		return nil, time.Time{}, 0, nil, nil, false
	}
	h := make([]byte, 26)
	copy(h, raw[0:26])
	tsu := int64(binary.BigEndian.Uint64(raw[0:8]))
	diff := int(binary.BigEndian.Uint16(raw[8:10]))
	nonce := make([]byte, 16)
	copy(nonce, raw[10:26])
	m := make([]byte, 32)
	copy(m, raw[26:58])
	return h, powDecodeIssued(tsu), diff, nonce, m, true
}

// powDecodeIssued reads an issue timestamp that may be encoded in either
// milliseconds (current) or seconds (pre-upgrade tokens still inside their TTL).
func powDecodeIssued(tsu int64) time.Time {
	if tsu >= powEpochMillisMin {
		return time.UnixMilli(tsu).UTC()
	}
	return time.Unix(tsu, 0).UTC()
}

// verifyPowChallenge validates a token's MAC and freshness. It also returns the
// issue time so the caller can derive the real solve latency (now - issued).
func verifyPowChallenge(secret []byte, tok string, bind string, cfg PowConfig, now time.Time) (issued time.Time, difficulty int, nonce16 []byte, ok bool) {
	hdr, ts, diff, nonce, macWant, okp := parsePowChallenge(tok)
	if !okp {
		return time.Time{}, 0, nil, false
	}
	// time window
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = defaultPowTTL
	}
	if now.Sub(ts) > ttl || now.Before(ts.Add(-10*time.Second)) {
		return time.Time{}, 0, nil, false
	}
	// difficulty clamp
	if diff < 8 || diff > 30 {
		return time.Time{}, 0, nil, false
	}

	// recompute mac over the header bytes exactly as they were signed
	mac := hmac.New(sha256.New, secret)
	mac.Write(hdr)
	mac.Write([]byte{0})
	mac.Write([]byte(bind))
	sum := mac.Sum(nil)

	if !hmac.Equal(sum, macWant) {
		return time.Time{}, 0, nil, false
	}
	return ts, diff, nonce, true
}

// powSolveLatencyMS returns the wall-clock milliseconds a client took to solve,
// measured from the issue timestamp carried inside the PoW token.
//
// Returns -1 for "unknown" whenever the number would be a fiction: a zero issue
// time, or a value outside [0, ttl]. The bound matters in both directions and
// neither is hypothetical — the two timestamps come from two readings of the
// wall clock, so any NTP step or VM migration between issue and verify lands
// here. A backward step makes fast solves negative, and dropping only those
// would silently truncate the distribution at its low end — precisely the end
// this measurement exists to observe. A forward step inflates the latency, and
// reporting that as fact is the same error mirrored. Verification has already
// rejected anything genuinely older than the TTL, so a latency beyond it means
// the clock moved, not that the client was slow.
//
// Callers must treat -1 as unknown and never score on it.
func powSolveLatencyMS(issued, now time.Time, ttl time.Duration) int64 {
	if issued.IsZero() {
		return -1
	}
	if ttl <= 0 {
		ttl = defaultPowTTL
	}
	d := now.Sub(issued)
	if d < 0 || d > ttl {
		return -1
	}
	return d.Milliseconds()
}

// verifyPowSolution checks: sha256( nonce16 || 0 || bind || 0 || solution ) has N leading zero bits.
func verifyPowSolution(nonce16 []byte, bind string, solution string, difficulty int) bool {
	solution = strings.TrimSpace(solution)
	if solution == "" || len(solution) > maxPowSolutionLen {
		return false
	}
	// allow only digits (fast + avoids weird payloads)
	for _, ch := range solution {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	// normalize (strip leading zeros ok)
	if _, err := strconv.ParseUint(solution, 10, 64); err != nil {
		return false
	}

	h := sha256.New()
	h.Write(nonce16)
	h.Write([]byte{0})
	h.Write([]byte(bind))
	h.Write([]byte{0})
	h.Write([]byte(solution))
	sum := h.Sum(nil)

	return hasLeadingZeroBits(sum, difficulty)
}

func hasLeadingZeroBits(digest []byte, bits int) bool {
	// bits 0..256
	if bits <= 0 {
		return true
	}
	full := bits / 8
	rem := bits % 8

	for i := 0; i < full; i++ {
		if digest[i] != 0 {
			return false
		}
	}
	if rem == 0 {
		return true
	}
	// top rem bits of next byte must be zero
	mask := byte(0xFF) << (8 - rem)
	return (digest[full] & mask) == 0
}
