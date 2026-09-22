package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	cfgpkg "cfm/internal/config"
)

// One-shot CLI commands (cfm block, cfm dnat, cfm firewall, …) build their own
// firewall backend, and must pick the same engine as the daemon. They used to
// read only the CFM_FIREWALL_ENGINE environment variable and ignore
// FIREWALL_ENGINE in cfm.conf. So on a node configured for nftlib the daemon ran
// nftlib while every CLI command ran the exec nft backend. The two backends tag
// their DNAT rules differently, so `cfm dnat on` from the CLI added a second copy
// of the web redirect beside the daemon's, and each backend misread the other's
// panel accepts.

// cliEngineConfig is cfm.conf from the CLI's config dir (the daemon's, via the
// state file it writes), read once per process.
var cliEngineConfig = sync.OnceValue(func() *cfgpkg.Config {
	cfg, err := loadEngineConfig(cfgDir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot read FIREWALL_ENGINE from cfm.conf (%v); using CFM_FIREWALL_ENGINE or the nft default\n", err)
	}
	return cfg
})

// cliFirewallEngine resolves the engine as the daemon does: CFM_FIREWALL_ENGINE,
// then FIREWALL_ENGINE in cfm.conf, then nft.
func cliFirewallEngine() (raw, normalized, source string) {
	return resolveFirewallEngine(cliEngineConfig())
}

// loadEngineConfig parses dir/cfm.conf. A missing dir or file is not an error:
// the engine then falls back to the environment or the default, as in the
// daemon. The daemon also merges cfm.api.conf, which carries only API
// settings, never the engine.
func loadEngineConfig(dir string) (*cfgpkg.Config, error) {
	if dir == "" {
		return nil, nil
	}
	b, err := os.ReadFile(filepath.Join(dir, "cfm.conf")) // #nosec G304 -- operator config dir
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return cfgpkg.ParseCFMConf(bytes.NewReader(b))
}
