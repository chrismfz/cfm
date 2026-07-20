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
	defaultPowEnabled     = true
	defaultPowDifficulty  = 16               // bits of leading zeros (18–22 είναι “ok”)
	defaultPowTTL         = 2 * time.Minute  // challenge must be solved quickly
	maxPowSolutionLen     = 64
)

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
// Format: base64url( ts_unix(8 bytes) || difficulty(2 bytes) || nonce(16 bytes) || mac(32 bytes) )
func issuePowChallenge(secret []byte, now time.Time, difficulty int, nonce16 []byte, bind string) (string, error) {
	if len(nonce16) != 16 {
		return "", fmt.Errorf("nonce must be 16 bytes")
	}
	if difficulty < 8 || difficulty > 30 {
		return "", fmt.Errorf("bad difficulty: %d", difficulty)
	}

	ts := uint64(now.Unix())
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

func parsePowChallenge(tok string) (ts time.Time, difficulty int, nonce16 []byte, mac []byte, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(tok))
	if err != nil || len(raw) != 8+2+16+32 {
		return time.Time{}, 0, nil, nil, false
	}
	tsu := int64(binary.BigEndian.Uint64(raw[0:8]))
	diff := int(binary.BigEndian.Uint16(raw[8:10]))
	nonce := make([]byte, 16)
	copy(nonce, raw[10:26])
	m := make([]byte, 32)
	copy(m, raw[26:58])
	return time.Unix(tsu, 0).UTC(), diff, nonce, m, true
}

func verifyPowChallenge(secret []byte, tok string, bind string, cfg PowConfig, now time.Time) (difficulty int, nonce16 []byte, ok bool) {
	ts, diff, nonce, macWant, okp := parsePowChallenge(tok)
	if !okp {
		return 0, nil, false
	}
	// time window
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = defaultPowTTL
	}
	if now.Sub(ts) > ttl || now.Before(ts.Add(-10*time.Second)) {
		return 0, nil, false
	}
	// difficulty clamp
	if diff < 8 || diff > 30 {
		return 0, nil, false
	}

	// recompute mac
	buf := make([]byte, 8+2+16)
	binary.BigEndian.PutUint64(buf[0:8], uint64(ts.Unix()))
	binary.BigEndian.PutUint16(buf[8:10], uint16(diff))
	copy(buf[10:26], nonce)

	mac := hmac.New(sha256.New, secret)
	mac.Write(buf)
	mac.Write([]byte{0})
	mac.Write([]byte(bind))
	sum := mac.Sum(nil)

	if !hmac.Equal(sum, macWant) {
		return 0, nil, false
	}
	return diff, nonce, true
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
