package apiserver

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"cfm/internal/detectorscfg"
	"cfm/internal/hostsecrets"
	"cfm/internal/notify"
	"cfm/internal/webdetector"
)

// TestMain points the notifier and detectors live-config fallbacks at files
// that do not exist, for the whole package. Both are package conffiles on
// every node (/etc/cfm/notify.conf, /etc/cfm/detectors.conf), and the handlers
// under test fall back to them — or, for detectors.conf, prefer them — over the
// test's own cfgDir: the notifier tests saved over the operator's live config.
// It also points the webdetector store/log defaults at the temp dir, so a test
// that builds an Engine can never reach /var/lib/cfm, and the per-host token
// store (hostsecrets.Dir): the health snapshot's challenge-token probe reads
// it.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cfm-apiserver-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "apiserver TestMain:", err)
		os.Exit(1)
	}
	restoreNotify := notify.SetSystemConfigPathForTest(filepath.Join(dir, "absent", "notify.conf"))
	restoreDetectors := detectorscfg.SetSystemConfigPathForTest(filepath.Join(dir, "absent", "detectors.conf"))
	restoreWebdet := webdetector.SetDefaultDirsForTest(filepath.Join(dir, "webdetector"))
	restoreSecrets := hostsecrets.SetDirForTest(filepath.Join(dir, "secrets"))
	code := m.Run()
	restoreNotify()
	restoreDetectors()
	restoreWebdet()
	restoreSecrets()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
