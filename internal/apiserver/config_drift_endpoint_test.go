package apiserver

import (
	"reflect"
	"testing"

	"cfm/internal/detconf"
)

func TestDiffDetectorsConfigIgnoresOptionalCFMEndpointsFamily(t *testing.T) {
	stock := detconf.Sections{ByName: map[string]detconf.KV{
		"global":                 {},
		"cfm_endpoints":          {"ENABLED": "1"},
		"cfm_endpoints:site":     {"WINDOW": "2m"},
		"cfm_endpoints.leniency": {"BLOCK": "15m"},
		"required_detector":      {"ENABLED": "1"},
	}}
	live := detconf.Sections{ByName: map[string]detconf.KV{
		"global":                 {},
		"api_abuse":              {"ENABLED": "1"},
		"api_abuse:old":          {"WINDOW": "9m"},
		"api_abuse:old.leniency": {"BLOCK": "5m"},
		"operator_extra":         {"ENABLED": "1"},
	}}
	rep := diffDetectorsConfig(stock, live)
	if !reflect.DeepEqual(rep.MissingSections, []string{"required_detector"}) {
		t.Fatalf("MissingSections=%v, want required_detector only", rep.MissingSections)
	}
	if !reflect.DeepEqual(rep.ExtraSections, []string{"operator_extra"}) {
		t.Fatalf("ExtraSections=%v, want operator_extra only", rep.ExtraSections)
	}
}
