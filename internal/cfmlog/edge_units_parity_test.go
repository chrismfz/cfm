package cfmlog

import (
	"reflect"
	"sort"
	"testing"
)

// journalUnits takes its edge engines from edgeengine.Profiles; this pins the
// set it held as a literal before.
func TestJournalUnitsUnchangedByTheEdgeRegistry(t *testing.T) {
	want := []string{"cfm", "angie", "openresty", "nginx", "httpd", "apache2", "mysql", "mysqld",
		"mariadb", "exim", "dovecot", "postfix", "sshd", "clamd", "named"}
	var got []string
	for k, v := range journalUnits {
		if v {
			got = append(got, k)
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("journalUnits changed:\n got  %v\n want %v", got, want)
	}
}
