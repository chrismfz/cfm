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
		// Brand-new reseller account home + virtualmin-style containers
		// (the only supported home cert layout: domains/<domain>/ssl.*).
		{"/home/newreseller", actionShallow},
		{"/home5/newreseller", actionShallow},
		{"/home/bob/domains", actionShallow},
		{"/home/bob/domains/site.gr", actionShallow},
		// Mailcow: immediate SNI host dirs are watched shallowly; account
		// material, backups, and deeper backup snapshots stay excluded.
		{defaultMailcowSSLRoot + "/mymail.myip.gr", actionShallow},
		{defaultMailcowSSLRoot + "/acme", actionIgnore},
		{defaultMailcowSSLRoot + "/backups", actionIgnore},
		{defaultMailcowSSLRoot + "/backups/mymail.myip.gr", actionIgnore},
		// Per-user ~/ssl, ~/certs, ~/letsencrypt are NOT escalated: no
		// scanner reads them, so watching them would only burn inotify
		// watches and fire no-op rescans.
		{"/home/bob/ssl", actionIgnore},
		{"/home2/alice/letsencrypt", actionIgnore},
		{"/home/bob/certs", actionIgnore},
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
