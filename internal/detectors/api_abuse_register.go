package detectors

import (
	"strings"
	"sync"
	"time"

	"cfm/internal/apiserver"
	"cfm/internal/detectors/apiabuse"
	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/meta"
	"cfm/internal/logging"
	"cfm/internal/webdetector"
)

const (
	cfmEndpointsType         = "cfm_endpoints"
	cfmEndpointsLegacyType   = "api_abuse"
	cfmEndpointsSyntheticKey = "__CFM_BUILTIN_SYNTHETIC"
)

var cfmEndpointsDeprecationWarning sync.Once

func init() {
	meta.Register(meta.DetectorMeta{
		TypeKey:           cfmEndpointsType,
		Title:             "CFM endpoints",
		Description:       "Protect CFM login, authentication, and API endpoints.",
		DefaultsTemplate:  cfmEndpointDefaults(),
		LeniencySupported: true,
	})
	factory := func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 2*time.Second)
		cfg := apiabuse.Config{
			Every:              kvDur(kv, "EVERY", defEvery),
			Window:             kvDur(kv, "WINDOW", 2*time.Minute),
			SampleLimit:        kvInt(kv, "SAMPLE_LIMIT", 10),
			Stage1Threshold:    kvInt(kv, "STAGE1_THRESHOLD", 10),
			Stage2Threshold:    kvInt(kv, "STAGE2_THRESHOLD", 12),
			Stage3Threshold:    kvInt(kv, "STAGE3_THRESHOLD", 16),
			Stage2ChallengeTTL: kvDur(kv, "STAGE2_CHALLENGE_TTL", 10*time.Minute),
			DryRun:             kvBool(kv, "DRY_RUN", false),
			AllowIPs:           csvKV(kv, "ALLOW_IPS"),
			AllowNets:          csvKV(kv, "ALLOW_NETS"),
			AllowUAContains:    csvKV(kv, "ALLOW_UA_CONTAINS"),
			PathExceptions:     csvKV(kv, "PATH_EXCEPTIONS"),
		}
		d := apiabuse.New(cfg)
		d.SetName(section)
		if ignore := newIPIgnoreFromGlobal(global); ignore != nil {
			d.SetBypassFunc(ignore.ShouldIgnore)
		}
		d.AddUnsubscribe(apiserver.SubscribeAPIAnomalyEvents(func(ev apiserver.APIAnomalyEvent) {
			d.Enqueue(ev.InputEvent())
		}))
		d.AddUnsubscribe(webdetector.SubscribeAPIAnomalyEvents(func(ev webdetector.APIAnomalyEvent) {
			d.Enqueue(ev.InputEvent())
		}))
		return d, nil
	}
	Register(cfmEndpointsType, factory)
	RegisterAlias(cfmEndpointsLegacyType, cfmEndpointsType, factory)
}

func cfmEndpointDefaults() KV {
	return KV{
		"ENABLED":              "1",
		"EVERY":                "2s",
		"WINDOW":               "2m",
		"SAMPLE_LIMIT":         "10",
		"STAGE1_THRESHOLD":     "10",
		"STAGE2_THRESHOLD":     "12",
		"STAGE3_THRESHOLD":     "16",
		"STAGE2_CHALLENGE_TTL": "10m",
		"BLOCK":                "15m",
		"BLOCK_COOLDOWN":       "20m",
		"DRY_RUN":              "0",
		"ALLOW_IPS":            "127.0.0.1",
		"ALLOW_NETS":           "",
		"PATH_EXCEPTIONS":      "/api/v1/embed/bootstrap, /cfm-admin/api/v1/embed/bootstrap",
	}
}

// applyBuiltinCFMEndpoints guarantees one canonical detector section. Legacy
// and named instances are merged in memory so they cannot create duplicate
// subscriptions; canonical values override legacy values and exact sections
// override named instances.
func applyBuiltinCFMEndpoints(secs *Sections) {
	if secs == nil {
		return
	}
	if secs.ByName == nil {
		secs.ByName = make(map[string]KV)
	}
	if secs.ByType == nil {
		secs.ByType = make(map[string][]string)
	}

	sectionNames := func(typ string) []string {
		seen := make(map[string]struct{})
		out := make([]string, 0, len(secs.ByType[typ])+1)
		for _, name := range secs.ByType[typ] {
			if strings.HasSuffix(name, ".leniency") {
				continue
			}
			if _, ok := secs.ByName[name]; !ok {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
		if _, ok := secs.ByName[typ]; ok {
			if _, seenExact := seen[typ]; !seenExact {
				out = append(out, typ)
			}
		}
		return out
	}

	legacyNames := sectionNames(cfmEndpointsLegacyType)
	canonicalNames := sectionNames(cfmEndpointsType)
	if len(legacyNames) > 0 {
		cfmEndpointsDeprecationWarning.Do(func() {
			logging.Logf("[detectors] WARNING: [%s] is deprecated; rename it to [%s]", cfmEndpointsLegacyType, cfmEndpointsType)
		})
	}

	merged := cfmEndpointDefaults()
	mergedLeniency := make(KV)
	mergeNames := func(names []string, exact string) {
		mergeOne := func(name string) {
			for key, value := range secs.ByName[name] {
				merged[key] = value
			}
			if leniency, ok := secs.ByName[name+".leniency"]; ok {
				for key, value := range leniency {
					mergedLeniency[key] = value
				}
			}
		}
		for _, name := range names {
			if name != exact {
				mergeOne(name)
			}
		}
		for _, name := range names {
			if name == exact {
				mergeOne(name)
				break
			}
		}
	}
	mergeNames(legacyNames, cfmEndpointsLegacyType)
	mergeNames(canonicalNames, cfmEndpointsType)
	if historicalCFMEndpointsUABypass(kvStrClean(merged, "ALLOW_UA_CONTAINS", "")) &&
		!kvBool(merged, "ALLOW_UA_CONTAINS_EXPLICIT", false) {
		delete(merged, "ALLOW_UA_CONTAINS")
	}
	if len(legacyNames) == 0 && len(canonicalNames) == 0 {
		merged[cfmEndpointsSyntheticKey] = "1"
	}

	for _, names := range [][]string{legacyNames, canonicalNames} {
		for _, name := range names {
			delete(secs.ByName, name)
			delete(secs.ByName, name+".leniency")
		}
	}

	secs.ByName[cfmEndpointsType] = merged
	if len(mergedLeniency) > 0 {
		secs.ByName[cfmEndpointsType+".leniency"] = mergedLeniency
	}
	delete(secs.ByType, cfmEndpointsLegacyType)
	secs.ByType[cfmEndpointsType] = []string{cfmEndpointsType}
}

func historicalCFMEndpointsUABypass(raw string) bool {
	parts := strings.FieldsFunc(strings.ToLower(strings.TrimSpace(raw)), func(r rune) bool {
		return r == ',' || r == ';'
	})
	if len(parts) != 3 {
		return false
	}
	want := map[string]struct{}{"uptime": {}, "healthcheck": {}, "prometheus": {}}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if _, ok := want[part]; !ok {
			return false
		}
		delete(want, part)
	}
	return len(want) == 0
}

func csvKV(kv KV, key string) []string {
	raw := strings.TrimSpace(kvStrClean(kv, key, ""))
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
