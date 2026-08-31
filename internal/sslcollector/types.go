package sslcollector

import (
	"crypto/tls"
	"sync/atomic"
	"time"
)

type Source string

const (
	SrcLetsEncrypt Source = "lets_encrypt"
	SrcMailcow     Source = "mailcow"
	SrcCPanel      Source = "cpanel"
	SrcDirectAdmin Source = "directadmin"
	SrcVirtualmin  Source = "virtualmin"
	SrcWebmin      Source = "webmin"
	SrcGeneric     Source = "generic"
)

type Entry struct {
	Source    Source
	Names     []string // normalized, may include "*.example.com"
	CertPath  string
	KeyPath   string
	ChainPath string // optional

	NotBefore   time.Time
	NotAfter    time.Time
	SelfSigned  bool
	Fingerprint string // sha256 of leaf cert raw

	// file change tracking
	CertMTime  time.Time
	KeyMTime   time.Time
	ChainMTime time.Time // zero when ChainPath == ""
	CertSize   int64
	KeySize    int64
	ChainSize  int64

	LastSeen time.Time

	// runtime-only negative cache
	lastErr       atomic.Value // string
	negativeUntil atomic.Int64 // unix seconds
}

type cachedCert struct {
	cert       *tls.Certificate
	certMTime  time.Time
	keyMTime   time.Time
	chainMTime time.Time
	fp         string
	loadedAt   time.Time
}

type fileSig struct {
	mtime time.Time
	size  int64
}
