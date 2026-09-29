package webdetector

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// clearanceScope(r) reads X-CFM-Panel-Port / X-Forwarded-Port, and the verify
// scope decides whether a ChallengeV2 rung mark counts (challengeV2MarkCovers)
// and whether a solve releases the IP's bridge decision. So every edge
// location that proxies /__cfm_verify must set both headers itself: the web
// listeners clear them (web scope), the panel listeners stamp their port. A
// location that passes the client's values lets it choose its own scope.

// verifyLocations returns the body of every `location = /__cfm_verify { … }`
// block in conf, by brace depth.
func verifyLocations(t *testing.T, conf string) []string {
	t.Helper()
	var out []string
	const head = "location = /__cfm_verify {"
	for i := strings.Index(conf, head); i >= 0; {
		body := i + len(head)
		depth, j := 1, body
		for ; j < len(conf) && depth > 0; j++ {
			switch conf[j] {
			case '{':
				depth++
			case '}':
				depth--
			}
		}
		if depth != 0 {
			t.Fatalf("unterminated /__cfm_verify block at offset %d", i)
		}
		out = append(out, conf[body:j-1])
		next := strings.Index(conf[j:], head)
		if next < 0 {
			break
		}
		i = j + next
	}
	return out
}

func TestVerifyLocations_WebListenersClearTheScopeHeaders(t *testing.T) {
	clearPanel := regexp.MustCompile(`proxy_set_header\s+X-CFM-Panel-Port\s+"";`)
	clearPort := regexp.MustCompile(`proxy_set_header\s+X-Forwarded-Port\s+"";`)
	for _, f := range []string{"../../configs/openresty.conf", "../../configs/angie.conf"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		locs := verifyLocations(t, string(b))
		if len(locs) == 0 {
			t.Fatalf("%s: no /__cfm_verify location found", f)
		}
		for i, loc := range locs {
			if !clearPanel.MatchString(loc) || !clearPort.MatchString(loc) {
				t.Errorf("%s: /__cfm_verify #%d does not clear X-CFM-Panel-Port and X-Forwarded-Port — a client could claim a panel scope", f, i+1)
			}
		}
	}
}

func TestVerifyLocations_PanelListenersStampTheirPort(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm-panel-listeners.conf.in")
	if err != nil {
		t.Fatalf("read panel listeners: %v", err)
	}
	stamp := regexp.MustCompile(`proxy_set_header X-CFM-Panel-Port (\d+);`)
	locs := verifyLocations(t, string(b))
	if len(locs) == 0 {
		t.Fatalf("no panel /__cfm_verify location found")
	}
	for i, loc := range locs {
		if !stamp.MatchString(loc) {
			t.Errorf("panel /__cfm_verify #%d does not stamp X-CFM-Panel-Port", i+1)
		}
	}
}
