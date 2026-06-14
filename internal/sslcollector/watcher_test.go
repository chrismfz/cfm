package sslcollector

import (
	"path/filepath"
	"testing"
)

// TestUnderCertRoot verifies that only paths inside a known pure-cert root
// are classified as recursively-watchable, and that a sibling-prefix trap
// (e.g. /etc/letsencryptX) is not mistaken for being under /etc/letsencrypt.
func TestUnderCertRoot(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/etc/letsencrypt", true},
		{"/etc/letsencrypt/live/example.com", true},
		{"/var/cpanel/ssl/apache_tls/example.com", true},
		{"/usr/local/directadmin/data/users/bob/domains", true},
		{"/etc/ssl/virtualmin", true},
		{"/etc/letsencryptX/live", false}, // sibling-prefix trap
		{"/home/bob/ssl", false},
		{"/home/bob/public_html", false},
		{"/var/cpanel", false},
	}
	for _, c := range cases {
		if got := underCertRoot(c.path); got != c.want {
			t.Errorf("underCertRoot(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// TestIsCertDirName pins the set of per-user directory basenames that hold
// cert material and should escalate to a recursive watch.
func TestIsCertDirName(t *testing.T) {
	for _, base := range []string{"ssl", "certs", "letsencrypt"} {
		if !isCertDirName(base) {
			t.Errorf("isCertDirName(%q) = false, want true", base)
		}
	}
	for _, base := range []string{"public_html", "mail", "domains", "example.com", ""} {
		if isCertDirName(base) {
			t.Errorf("isCertDirName(%q) = true, want false", base)
		}
	}
}

// TestHandleNewDirClassification documents, via the same predicates
// handleNewDir switches on, which new directories get a recursive watch,
// a shallow watch, or are ignored. Keeping this as a table guards against
// a future refactor accidentally re-introducing the dir-create blind spot
// (a per-domain dir named after the domain being dropped) or the inverse
// regression (recursively watching whole home trees).
func TestHandleNewDirClassification(t *testing.T) {
	const (
		recursive = "recursive"
		shallow   = "shallow"
		ignore    = "ignore"
	)
	classify := func(path string) string {
		base := filepath.Base(path)
		parentBase := filepath.Base(filepath.Dir(path))
		switch {
		case underCertRoot(path) || isCertDirName(base):
			return recursive
		case homeMountTopRE.MatchString(filepath.Dir(path)),
			base == "domains",
			parentBase == "domains":
			return shallow
		default:
			return ignore
		}
	}

	cases := []struct {
		path string
		want string
	}{
		// The original bug: a per-domain dir named after the domain, with
		// no cert/key/pem substring, under an already-watched cert root.
		{"/etc/letsencrypt/live/nantiavs-handmade.gr", recursive},
		{"/etc/letsencrypt/archive/luxurybowscrowns.com", recursive},
		{"/var/cpanel/ssl/apache_tls/mokascandles.gr", recursive},
		{"/usr/local/directadmin/data/users/bob/domains/site.gr", recursive},
		// Per-user cert dirs anywhere.
		{"/home/bob/ssl", recursive},
		{"/home2/alice/letsencrypt", recursive},
		// Brand-new reseller account home + virtualmin-style containers.
		{"/home/newreseller", shallow},
		{"/home5/newreseller", shallow},
		{"/home/bob/domains", shallow},
		{"/home/bob/domains/site.gr", shallow},
		// Noise that must NOT be watched/rescanned.
		{"/home/bob/public_html", ignore},
		{"/home/bob/mail", ignore},
		{"/home/bob/public_html/wp-content", ignore},
	}
	for _, c := range cases {
		if got := classify(c.path); got != c.want {
			t.Errorf("classify(%q) = %s, want %s", c.path, got, c.want)
		}
	}
}
