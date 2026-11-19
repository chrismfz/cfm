package healthmodel

import (
	"reflect"
	"testing"
)

// These lists take their edge engines from edgeengine.Profiles; the tests pin
// what they held as literals before (order included: the service-status
// order is output, and the frontend candidates' order is the scoring tiebreak).
// cfm-edge is appended after the old entries in each, so it never wins a tie.
func TestHealthEdgeListsUnchangedByTheEdgeRegistry(t *testing.T) {
	if want := []string{"cfm.service", "nginx.service", "openresty.service", "angie.service", "cfm-edge.service"}; !reflect.DeepEqual(serviceStatusUnits(), want) {
		t.Errorf("serviceStatusUnits() = %v, want %v", serviceStatusUnits(), want)
	}
	want := []frontendSignal{
		{
			name:            "angie",
			serviceUnit:     "angie.service",
			processAliases:  []string{"angie", "nginx"},
			configHookPaths: []string{"/etc/angie/conf.d/cfm.conf", "/etc/angie/conf.d/nginx-cfm.conf", "/etc/angie/angie.conf"},
			binaryPaths:     []string{"/usr/sbin/angie", "/usr/bin/angie"},
			binaryCommands:  []string{"angie"},
		},
		{
			name:            "openresty",
			serviceUnit:     "openresty.service",
			processAliases:  []string{"openresty", "nginx"},
			configHookPaths: []string{"/usr/local/openresty/nginx/conf/nginx-cfm.conf", "/usr/local/openresty/nginx/conf/openresty-cfm-tsv.conf", "/usr/local/openresty/nginx/conf/nginx.conf"},
			binaryPaths:     []string{"/usr/local/openresty/nginx/sbin/nginx", "/opt/openresty/nginx/sbin/nginx"},
			binaryCommands:  []string{"openresty"},
		},
		{
			name:            "cfm-edge",
			serviceUnit:     "cfm-edge.service",
			processAliases:  []string{"cfm-edge", "nginx"},
			configHookPaths: []string{"/etc/cfm-edge/trusted_proxies.conf"},
			binaryPaths:     []string{"/usr/sbin/cfm-edge"},
			binaryCommands:  []string{"cfm-edge"},
		},
		{
			name:            "nginx",
			serviceUnit:     "nginx.service",
			processAliases:  []string{"nginx"},
			configHookPaths: []string{"/etc/nginx/conf.d/nginx-cfm.conf", "/etc/nginx/nginx.conf"},
			binaryPaths:     []string{"/usr/sbin/nginx", "/usr/bin/nginx"},
			binaryCommands:  []string{"nginx"},
		},
	}
	if got := dnatFrontendCandidates(); !reflect.DeepEqual(got, want) {
		t.Errorf("dnatFrontendCandidates() changed:\n got  %+v\n want %+v", got, want)
	}
	for svc, want := range map[string][]string{
		"angie": {"angie", "nginx"}, "Angie ": {"angie", "nginx"}, "openresty": {"openresty", "nginx"},
		"cfm-edge": {"cfm-edge", "nginx"}, "nginx": {"nginx"}, "httpd": nil,
	} {
		if got := frontendAliases(svc); !reflect.DeepEqual(got, want) {
			t.Errorf("frontendAliases(%q) = %v, want %v", svc, got, want)
		}
	}
}
