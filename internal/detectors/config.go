package detectors

// config.go — detectors.conf parsing now lives in internal/detconf (a
// dependency-free package) so non-detectors readers (CLI drift checks, the
// config-drift API/MCP tooling) can parse with IDENTICAL semantics without
// importing this package — which reaches back into the API server and would
// create an import cycle. Everything below is a thin alias layer keeping the
// historical in-package names working.

import (
	"strings"

	"cfm/internal/detconf"
)

type KV = detconf.KV

type Sections = detconf.Sections

// readLayered keeps readSectionsForReload's read injectable for tests.
var readLayered = detconf.ReadLayered

// splitTypeInstance — manager.go calls the unexported name directly.
var splitTypeInstance = detconf.SplitTypeInstance

func ReadSectionsFile(path string) (Sections, error) {
	return detconf.ReadSectionsFile(path)
}

// ReadLayeredFile reads path plus its "<dir>/detectors.d" overlays — the view
// the manager actually runs on. Prefer this for anything answering "what is
// the effective config"; ReadSectionsFile stays the BASE-only read (e.g. the
// config drift VALUE comparison, where overlay values are intentional
// per-host state — drift's missing_* checks use the layered view).
func ReadLayeredFile(path string) (Sections, error) {
	return detconf.ReadLayeredFile(path)
}

func SplitTypeInstance(section string) (typ, inst string) {
	return detconf.SplitTypeInstance(section)
}

// kvLines splits a multiline KV value (joined with \n) into individual
// non-empty, comment-stripped lines.  Use for QUERY_RULES / CONN_RULES blocks.
func kvLines(kv KV, key string) []string {
	raw, ok := kv[strings.ToUpper(key)]
	if !ok || raw == "" {
		return nil
	}
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(stripInlineComment(line))
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
