package edgelog

import (
	"reflect"
	"testing"
)

// The candidate lists take their edge log paths from edgeengine.Profiles; this
// pins the lists (order included: it is the equal-mtime tiebreak) they held as
// literals before.
func TestLogCandidatesUnchangedByTheEdgeRegistry(t *testing.T) {
	cases := []struct {
		name      string
		got, want []string
	}{
		{"accessLogCandidates", accessLogCandidates, []string{
			"/usr/local/openresty/nginx/logs/access.log",
			"/var/log/angie/access.log",
			"/usr/local/openresty/nginx/logs/access.cfm.log",
			"/var/log/angie/access.cfm.log",
			"/var/log/nginx/access.log",
		}},
		{"errorLogCandidates", errorLogCandidates, []string{
			"/usr/local/openresty/nginx/logs/error.log",
			"/var/log/angie/error.log",
			"/var/log/nginx/error.log",
		}},
		{"fullAccessLogCandidates", fullAccessLogCandidates, []string{
			"/usr/local/openresty/nginx/logs/access.log",
			"/var/log/angie/access.log",
		}},
	}
	for _, tc := range cases {
		if !reflect.DeepEqual(tc.got, tc.want) {
			t.Errorf("%s changed:\n got  %v\n want %v", tc.name, tc.got, tc.want)
		}
	}
}
