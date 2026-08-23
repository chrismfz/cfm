package mcpserver

import (
	"encoding/json"
	"testing"
)

func TestWhatsWrong_DisabledFailedServiceSuppressed(t *testing.T) {
	got := evalServices(json.RawMessage(`{"services":[
		{"unit":"memcached.service","load":"loaded","active":"failed","sub":"failed","enabled":"disabled","restarts":0}
	]}`), "")
	if n := countCat(got, "service"); n != 0 {
		t.Fatalf("disabled failed service must not be treated as a current fault, got %d finding(s): %+v", n, got)
	}
}

func TestWhatsWrong_EnabledFailedServiceStillCritical(t *testing.T) {
	got := evalServices(json.RawMessage(`{"services":[
		{"unit":"memcached.service","load":"loaded","active":"failed","sub":"failed","enabled":"enabled","restarts":0}
	]}`), "")
	if n := countCat(got, "service"); n != 1 {
		t.Fatalf("enabled failed service must still produce exactly one finding, got %d: %+v", n, got)
	}
	f := findBy(got, "service", sevCritical)
	if f == nil || f.Args["units"] != "memcached.service" {
		t.Fatalf("enabled failed service must remain critical, got %+v", got)
	}
}
