package sslcollector

import (
	_ "embed"
	"os"
	"path/filepath"

	"cfm/internal/logging"
)

// embeddedSSLCollectorLua is the canonical sslcollector.lua module
// bundled into the cfm binary. We embed it (rather than relying solely
// on the install pipeline copying configs/lua/sslcollector.lua to
// /var/lib/cfm/lua/) so that a binary-only deployment cannot fall out
// of sync with the Go code that it must talk to. The operator's
// May 4-dated sslcollector.lua against a May 14-dated cfm binary
// surfaced exactly that hazard.
//
// The file is duplicated into internal/sslcollector/embed/ because
// Go's embed directive cannot reach paths above the package directory
// (and does not follow symlinks). A drift test ensures the two copies
// stay byte-identical.
//
//go:embed embed/sslcollector.lua
var embeddedSSLCollectorLua []byte

// SSLCollectorLuaPath is where the runtime module must live so that
// angie/openresty's `require 'sslcollector'` finds it (it is the first
// path searched in both angie.conf and openresty.conf — see the
// `init_worker_by_lua` error trace in the operator's logs for the full
// search list).
const SSLCollectorLuaPath = "/var/lib/cfm/lua/sslcollector.lua"

// DeploySSLCollectorLua writes the embedded sslcollector.lua to
// /var/lib/cfm/lua/sslcollector.lua atomically with mode 0640 root:cfm,
// but only when the on-disk content differs from the embedded copy.
// Idempotent and cheap: on a system where the package install already
// laid down the matching file, this is a single read + compare.
//
// Errors are logged but not returned — a write failure must not block
// daemon startup. The angie/openresty package's pre-existing copy on
// disk still works as a fallback when this write fails.
func DeploySSLCollectorLua(cfmGID int) {
	target := SSLCollectorLuaPath
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		logging.Logf("[sslcollector] deploy lua: mkdir %s: %v", dir, err)
		return
	}

	// Skip rewrite when content already matches — keeps the file's
	// mtime stable so a stat-only diff against the package version
	// still tells the operator whether their package shipped the
	// current Lua.
	if existing, err := os.ReadFile(target); err == nil && bytesEqual(existing, embeddedSSLCollectorLua) {
		// Still re-assert mode + ownership in case a previous build
		// left it root:root or 0600 from the umask bug.
		if err := os.Chmod(target, 0o640); err != nil {
			logging.Logf("[sslcollector] deploy lua: chmod %s: %v", target, err)
		}
		if cfmGID > 0 {
			if err := os.Chown(target, 0, cfmGID); err != nil {
				logging.Logf("[sslcollector] deploy lua: chown %s to root:%d: %v", target, cfmGID, err)
			}
		}
		return
	}

	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, embeddedSSLCollectorLua, 0o640); err != nil { // #nosec G306
		logging.Logf("[sslcollector] deploy lua: write tmp %s: %v", tmp, err)
		return
	}
	if err := os.Chmod(tmp, 0o640); err != nil {
		logging.Logf("[sslcollector] deploy lua: chmod tmp %s: %v", tmp, err)
	}
	if cfmGID > 0 {
		if err := os.Chown(tmp, 0, cfmGID); err != nil {
			logging.Logf("[sslcollector] deploy lua: chown tmp %s to root:%d: %v", tmp, cfmGID, err)
		}
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		logging.Logf("[sslcollector] deploy lua: rename %s -> %s: %v", tmp, target, err)
		return
	}
	if err := os.Chmod(target, 0o640); err != nil {
		logging.Logf("[sslcollector] deploy lua: chmod final %s: %v", target, err)
	}
	if cfmGID > 0 {
		if err := os.Chown(target, 0, cfmGID); err != nil {
			logging.Logf("[sslcollector] deploy lua: chown final %s to root:%d: %v", target, cfmGID, err)
		}
	}
	logging.Logf("[sslcollector] deploy lua: wrote %d bytes to %s (mode 0640 root:cfm)", len(embeddedSSLCollectorLua), target)
}

// EmbeddedSSLCollectorLua returns a copy of the embedded module bytes.
// Exposed for the drift test in configs_lua_sync_test.go.
func EmbeddedSSLCollectorLua() []byte {
	out := make([]byte, len(embeddedSSLCollectorLua))
	copy(out, embeddedSSLCollectorLua)
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

