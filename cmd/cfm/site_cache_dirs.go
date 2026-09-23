package main

import (
	"os"
	"path/filepath"
)

// siteCacheRoot is the parent of every Site Cache proxy_cache_path dir.
const siteCacheRoot = "/var/cache/nginx"

// siteCacheDirNames are the Site Cache zone dirs under siteCacheRoot: Tier A is
// the single cfm_static zone, Tier B micro-cache one zone per TTL bucket
// {1,2,5,10,30,60}s. Each proxy_cache_path dir MUST exist before `angie -t` /
// `openresty -t` or the config test fails [emerg]. This list must match the
// proxy_cache_path dirs in configs/openresty.conf and configs/angie.conf and
// the list in scripts/cfm-cache-dirs.sh (the packaging/installer copy of this
// provisioning); scripts/tests/check_site_cache_config.sh enforces it.
var siteCacheDirNames = []string{
	"cfm_static",
	"cfm_micro_1s",
	"cfm_micro_2s",
	"cfm_micro_5s",
	"cfm_micro_10s",
	"cfm_micro_30s",
	"cfm_micro_60s",
}

// ensureSiteCacheDirs provisions the Site Cache dirs under root: each zone dir
// root:<gid> 0770 so the edge workers (cfm group) can write, and root itself
// traversable by them.
//
// The parent needs explicit care: the daemon runs under UMask=0077
// (configs/cfm.service), so os.MkdirAll on a zone dir used to create a missing
// /var/cache/nginx as root:root 0700 — the workers could not reach any cache
// dir and every request of an armed vhost 500'd with "Permission denied" (a
// fresh deb install hits this: the postinst starts the daemon before an edge
// installer runs). A missing parent is now created 0755; an existing one only
// gains a+x (traverse), keeping its other bits.
//
// This is TOP-DIR provisioning only: the levels=1:2 subdirs are created by the
// worker, and scripts/cfm-cache-dirs.sh (run from the packaging and the edge
// installers) purges a cache tree the workers cannot use. Errors are
// ignored, as for the daemon's other runtime dirs: a failure leaves caching
// broken for armed vhosts only, and the edge logs it.
func ensureSiteCacheDirs(root string, gid int) {
	if fi, err := os.Stat(root); err != nil {
		_ = os.MkdirAll(root, 0o755)
		_ = os.Chmod(root, 0o755)
	} else if fi.IsDir() && fi.Mode().Perm()&0o111 != 0o111 {
		keep := fi.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
		_ = os.Chmod(root, keep|0o111)
	}
	for _, name := range siteCacheDirNames {
		d := filepath.Join(root, name)
		_ = os.MkdirAll(d, 0o770)
		_ = os.Chmod(d, 0o770)
		_ = os.Chown(d, 0, gid)
	}
}
