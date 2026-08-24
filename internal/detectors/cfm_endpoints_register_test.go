package detectors

import (
	"context"
	"testing"
	"time"

	core "cfm/internal/detectors/core"
)

func TestApplyBuiltinCFMEndpointsCreatesDefaultOnSyntheticSection(t *testing.T) {
	secs := Sections{
		Global: map[string]string{},
		ByName: map[string]KV{"global": {}},
		ByType: map[string][]string{},
	}
	applyBuiltinCFMEndpoints(&secs)

	kv, ok := secs.ByName[cfmEndpointsType]
	if !ok {
		t.Fatal("implicit cfm_endpoints section was not created")
	}
	if !kvBool(kv, "ENABLED", false) {
		t.Fatal("implicit cfm_endpoints must be enabled")
	}
	if got := kvStrClean(kv, "BLOCK", ""); got != "15m" {
		t.Fatalf("implicit BLOCK=%q, want 15m", got)
	}
	if got, ok := kv["ALLOW_NETS"]; !ok || got != "" {
		t.Fatalf("implicit ALLOW_NETS=%q present=%t, want an empty override", got, ok)
	}
	if !kvBool(kv, cfmEndpointsSyntheticKey, false) {
		t.Fatal("implicit section must be marked synthetic for runtime status")
	}
}

func TestApplyBuiltinCFMEndpointsMergesOverridesAndMigratesAlias(t *testing.T) {
	secs := Sections{
		Global: map[string]string{},
		ByName: map[string]KV{
			"global":                             {},
			cfmEndpointsLegacyType:               {"STAGE3_THRESHOLD": "30", "BLOCK": "1h"},
			cfmEndpointsLegacyType + ".leniency": {"BLOCK": "5m"},
		},
		ByType: map[string][]string{cfmEndpointsLegacyType: {cfmEndpointsLegacyType}},
	}
	applyBuiltinCFMEndpoints(&secs)

	if _, ok := secs.ByName[cfmEndpointsLegacyType]; ok {
		t.Fatal("legacy section remained alongside canonical section")
	}
	kv := secs.ByName[cfmEndpointsType]
	if got := kvInt(kv, "STAGE3_THRESHOLD", 0); got != 30 {
		t.Fatalf("operator threshold=%d, want 30", got)
	}
	if got := kvStrClean(kv, "BLOCK", ""); got != "1h" {
		t.Fatalf("operator BLOCK=%q, want 1h", got)
	}
	if got := kvStrClean(kv, "WINDOW", ""); got != "2m" {
		t.Fatalf("built-in WINDOW=%q, want 2m", got)
	}
	if _, ok := secs.ByName[cfmEndpointsType+".leniency"]; !ok {
		t.Fatal("legacy leniency section was not migrated")
	}
}

func TestCFMEndpointsLegacyFactoryIsNotAdvertisedAsSeparateType(t *testing.T) {
	if _, ok := getFactory(cfmEndpointsLegacyType); !ok {
		t.Fatal("legacy api_abuse factory alias is not loadable")
	}
	for _, typ := range RegisteredTypes() {
		if typ == cfmEndpointsLegacyType {
			t.Fatal("legacy api_abuse alias must not appear as a second detector type")
		}
	}
}

func TestCFMEndpointsConfigSectionIsOptionalForCanonicalAndAlias(t *testing.T) {
	if !ConfigSectionOptional(cfmEndpointsType) || !ConfigSectionOptional(cfmEndpointsLegacyType) {
		t.Fatal("canonical and legacy CFM endpoint sections must both be optional")
	}
	if ConfigSectionOptional("ssh_auth") || ConfigSectionOptional("not_registered") {
		t.Fatal("ordinary and unknown detector sections must remain required")
	}
}

func TestCFMEndpointsDefaultInvalidTokenStagesAndTTLPolicy(t *testing.T) {
	kv := cfmEndpointDefaults()
	factory, ok := getFactory(cfmEndpointsType)
	if !ok {
		t.Fatal("cfm_endpoints factory is not registered")
	}
	detector, err := factory(cfmEndpointsType, kv, KV{})
	if err != nil {
		t.Fatal(err)
	}
	if shutdown, ok := detector.(core.Shutdowner); ok {
		defer shutdown.Shutdown()
	}
	enqueue, ok := detector.(interface{ Enqueue(core.InputEvent) })
	if !ok {
		t.Fatal("cfm_endpoints detector does not accept structured events")
	}
	now := time.Now()
	for i := 0; i < 16; i++ {
		enqueue.Enqueue(core.InputEvent{
			When:   now,
			Source: "apiserver",
			Reason: "AUTH_TOKEN_INVALID",
			Signal: "AUTH_TOKEN_INVALID",
			SrcIP:  "203.0.113.50",
		})
	}
	out := make(chan core.Alert, 3)
	if err := detector.RunOnce(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	close(out)
	alerts := make([]core.Alert, 0, 3)
	for alert := range out {
		alerts = append(alerts, alert)
	}
	if len(alerts) != 3 || alerts[0].Count != 10 || alerts[1].Count != 12 || alerts[2].Count != 16 {
		t.Fatalf("default stage alerts=%+v, want counts 10/12/16", alerts)
	}
	if alerts[0].Extra["enforcement"] != "observe" || alerts[1].Extra["action"] != "challenge" || alerts[2].Extra["enforcement"] != "" {
		t.Fatalf("unexpected default stage actions: %+v", alerts)
	}
	policy := parseBlockPolicy(kv)
	if policy.Mode != "ttl" || policy.TTL != 15*time.Minute {
		t.Fatalf("default stage-3 block policy=%+v, want 15m TTL", policy)
	}
}

func TestApplyBuiltinCFMEndpointsCollapsesNamedInstances(t *testing.T) {
	secs := Sections{
		Global: map[string]string{},
		ByName: map[string]KV{
			"global":                       {},
			"api_abuse:old":                {"WINDOW": "9m", "STAGE3_THRESHOLD": "20"},
			"api_abuse:old.leniency":       {"BLOCK": "5m"},
			"cfm_endpoints:site":           {"WINDOW": "4m", "STAGE3_THRESHOLD": "25"},
			"cfm_endpoints:site.leniency":  {"BLOCK": "10m"},
			cfmEndpointsType:               {"STAGE3_THRESHOLD": "30"},
			cfmEndpointsType + ".leniency": {"BLOCK": "15m"},
		},
		ByType: map[string][]string{
			cfmEndpointsLegacyType: {"api_abuse:old", "api_abuse:old.leniency"},
			cfmEndpointsType:       {"cfm_endpoints:site", "cfm_endpoints:site.leniency", cfmEndpointsType},
		},
	}

	applyBuiltinCFMEndpoints(&secs)

	if got := secs.ByType[cfmEndpointsType]; len(got) != 1 || got[0] != cfmEndpointsType {
		t.Fatalf("canonical instances = %v, want one %q", got, cfmEndpointsType)
	}
	if _, ok := secs.ByType[cfmEndpointsLegacyType]; ok {
		t.Fatal("legacy type remained in ByType")
	}
	for _, name := range []string{"api_abuse:old", "api_abuse:old.leniency", "cfm_endpoints:site", "cfm_endpoints:site.leniency"} {
		if _, ok := secs.ByName[name]; ok {
			t.Fatalf("duplicate section %q remained", name)
		}
	}
	if got := kvStrClean(secs.ByName[cfmEndpointsType], "WINDOW", ""); got != "4m" {
		t.Fatalf("canonical named WINDOW=%q, want 4m", got)
	}
	if got := kvInt(secs.ByName[cfmEndpointsType], "STAGE3_THRESHOLD", 0); got != 30 {
		t.Fatalf("exact canonical threshold=%d, want 30", got)
	}
	if got := kvStrClean(secs.ByName[cfmEndpointsType+".leniency"], "BLOCK", ""); got != "15m" {
		t.Fatalf("exact canonical leniency BLOCK=%q, want 15m", got)
	}
}

func TestApplyBuiltinCFMEndpointsRemovesHistoricalUADefaultUnlessExplicit(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ua       string
		explicit string
		wantUA   bool
	}{
		{name: "upgrade migration", ua: "uptime, healthcheck, prometheus", wantUA: false},
		{name: "inline comment migration", ua: "uptime, healthcheck, prometheus # old default", wantUA: false},
		{name: "operator opt in", ua: "uptime, healthcheck, prometheus", explicit: "1", wantUA: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secs := Sections{
				Global: map[string]string{},
				ByName: map[string]KV{
					"global":         {},
					cfmEndpointsType: {"ALLOW_UA_CONTAINS": tc.ua, "ALLOW_UA_CONTAINS_EXPLICIT": tc.explicit},
				},
				ByType: map[string][]string{cfmEndpointsType: {cfmEndpointsType}},
			}
			applyBuiltinCFMEndpoints(&secs)
			_, gotUA := secs.ByName[cfmEndpointsType]["ALLOW_UA_CONTAINS"]
			if gotUA != tc.wantUA {
				t.Fatalf("ALLOW_UA_CONTAINS present=%t, want %t", gotUA, tc.wantUA)
			}
		})
	}
}
