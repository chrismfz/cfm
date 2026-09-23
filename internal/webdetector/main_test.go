package webdetector

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestMain points every store and log default at a temp dir for the whole
// package (see defaultStateDir) before any test builds an Engine. Tests build
// engines from sparse Configs; with the production defaults each of them read
// and wrote the LIVE /var/lib/cfm stores, so a run as root on a CFM node
// replaced the operator's manual challenges and HTTP/3 overrides with test data.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cfm-webdetector-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "webdetector TestMain:", err)
		os.Exit(1)
	}
	defaultStateDir, defaultLogDir = dir, dir
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// Every path FillDefaults supplies must come from defaultStateDir /
// defaultLogDir, or TestMain's redirect misses it and a test writes the live
// file again. A new store added with a literal "/var/lib/cfm/..." default fails
// here, whether or not any test happens to write it yet.
func TestFillDefaultsPathsFollowTheRedirectableDirs(t *testing.T) {
	var c Config
	c.FillDefaults()
	v := reflect.ValueOf(c)
	for i := 0; i < v.NumField(); i++ {
		f := v.Type().Field(i)
		if f.Type.Kind() != reflect.String {
			continue
		}
		p := v.Field(i).String()
		if !strings.HasPrefix(p, "/") {
			continue
		}
		// Operator-edited input, read and never written.
		if f.Name == "ChallengePathsFile" {
			continue
		}
		if !strings.HasPrefix(p, defaultStateDir+"/") && !strings.HasPrefix(p, defaultLogDir+"/") {
			t.Errorf("FillDefaults sets %s = %q, outside defaultStateDir/defaultLogDir (%s): tests would write the live path", f.Name, p, defaultStateDir)
		}
	}
}
