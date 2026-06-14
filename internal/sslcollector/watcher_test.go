package sslcollector

import (
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

// TestClassifyNewDir exercises the REAL classifyNewDir decision function
// (not a copy of its switch) so a future refactor that re-introduces the
// dir-create blind spot — a per-domain dir named after the domain being
// dropped — or the inverse regression — recursively watching whole home
// trees — is caught here.
func TestClassifyNewDir(t *testing.T) {
	cases := []struct {
		path string
		want newDirAction
	}{
		// The original bug: a per-domain dir named after the domain, with
		// no cert/key/pem substring, under an already-watched cert root.
		{"/etc/letsencrypt/live/nantiavs-handmade.gr", actionRecursive},
		{"/etc/letsencrypt/archive/luxurybowscrowns.com", actionRecursive},
		{"/var/cpanel/ssl/apache_tls/mokascandles.gr", actionRecursive},
		{"/usr/local/directadmin/data/users/bob/domains/site.gr", actionRecursive},
		// Per-user cert dirs anywhere.
		{"/home/bob/ssl", actionRecursive},
		{"/home2/alice/letsencrypt", actionRecursive},
		// Brand-new reseller account home + virtualmin-style containers.
		{"/home/newreseller", actionShallow},
		{"/home5/newreseller", actionShallow},
		{"/home/bob/domains", actionShallow},
		{"/home/bob/domains/site.gr", actionShallow},
		// Noise that must NOT be watched/rescanned.
		{"/home/bob/public_html", actionIgnore},
		{"/home/bob/mail", actionIgnore},
		{"/home/bob/public_html/wp-content", actionIgnore},
	}
	for _, c := range cases {
		if got := classifyNewDir(c.path); got != c.want {
			t.Errorf("classifyNewDir(%q) = %d, want %d", c.path, got, c.want)
		}
	}
}
