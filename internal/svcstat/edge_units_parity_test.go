package svcstat

import (
	"reflect"
	"testing"
)

// DefaultUnits takes its edge engines from edgeengine.Profiles; this pins the
// list it produced as a literal before, so the move changed nothing.
func TestDefaultUnitsUnchangedByTheEdgeRegistry(t *testing.T) {
	want := []string{"cfm", "angie", "openresty", "cfm-edge", "nginx", "httpd", "apache2", "lsws", "lshttpd",
		"mariadb", "mysql", "mysqld", "postgresql", "exim", "dovecot", "postfix",
		"named", "bind9", "pdns", "redis", "memcached", "pure-ftpd", "proftpd", "vsftpd",
		"sshd", "ssh", "crond", "cron", "fail2ban", "cpanel", "cpsrvd", "imunify360"}
	if !reflect.DeepEqual(DefaultUnits, want) {
		t.Fatalf("DefaultUnits changed:\n got  %v\n want %v", DefaultUnits, want)
	}
}
