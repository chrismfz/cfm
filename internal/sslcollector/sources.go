package sslcollector

import (
	"os"
	"path/filepath"
	"strings"
)

const defaultMailcowSSLRoot = "/opt/mailcow-dockerized/data/assets/ssl"

func (c *Collector) discoverPairs() []Pair {
	out := make([]Pair, 0, 1024)

	// LetsEncrypt
	out = append(out, scanLetsEncrypt("/etc/letsencrypt/live")...)

	// Mailcow: only the active TLS store and its immediate SNI host directories.
	// Deliberately never walk acme/ or backups/ (account keys and stale certs).
	out = append(out, scanMailcow(defaultMailcowSSLRoot)...)

	// cPanel
	out = append(out, scanCPanel("/var/cpanel/ssl/apache_tls")...)
        out = append(out, scanCPanelHostsInstalled("/var/cpanel/ssl/installed/hosts")...)
        out = append(out, scanCPanelServiceBundles("/var/cpanel/ssl/cpanel")...)

	// DirectAdmin
	out = append(out, scanDirectAdmin("/usr/local/directadmin/data/users")...)
        out = append(out, scanDirectAdminAdmin("/usr/local/directadmin/data/admin")...)

	// Virtualmin
	out = append(out, scanVirtualmin("/etc/ssl/virtualmin")...)
	// Scan EVERY /home[0-9]* mount, not just /home. Hosts add /home2,
	// /home3, ... as /home fills; hardcoding /home left those users'
	// certs undiscovered forever (the watcher fires for them, but the
	// rescan it triggers — and the DiscoveryEvery fallback — only looked
	// at /home). homeMounts() is the same source of truth the watcher uses.
	for _, h := range homeMounts() {
		out = append(out, scanHomeVirtualmin(h)...)
	}
        out = append(out, scanWebminMiniserv("/etc/webmin/miniserv.pem")...)

        // System/service hostname certs (Exim etc)
        out = append(out, scanSystemMailTLS("/etc")...)

	return out
}

// Best-effort check: keep only PEMs that actually contain a private key block.
func pemHasPrivateKey(p string) bool {
        b, err := os.ReadFile(p)
        if err != nil {
                return false
        }
        s := string(b)
        return strings.Contains(s, "BEGIN PRIVATE KEY") ||
                strings.Contains(s, "BEGIN RSA PRIVATE KEY") ||
                strings.Contains(s, "BEGIN EC PRIVATE KEY")
}

func fileOK(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular() && st.Size() > 0
}




// cPanel hostname/service certs often live under:
// /var/cpanel/ssl/installed/hosts/<hostname or service>/
// Common shapes resemble apache_tls ("combined" + "certificates"), but we also try cert/key variants.
func scanCPanelHostsInstalled(root string) []Pair {
        dirs, err := os.ReadDir(root)
        if err != nil {
                return nil
        }
        out := []Pair{}
        for _, d := range dirs {
                if !d.IsDir() {
                        continue
                }
                base := filepath.Join(root, d.Name())

                // Preferred shape: "certificates" + "combined"
                certs := filepath.Join(base, "certificates")
                comb := filepath.Join(base, "combined")
                if fileOK(certs) && fileOK(comb) {
                        out = append(out, Pair{
                                Source:   SrcCPanel,
                                CertPath: certs,
                                KeyPath:  comb,
                        })
                        continue
                }

                // Fallback shapes
                candidates := [][2]string{
                        {filepath.Join(base, "cert"), filepath.Join(base, "key")},
                        {filepath.Join(base, "crt"), filepath.Join(base, "key")},
                        {filepath.Join(base, "certificate"), filepath.Join(base, "privatekey")},
                        {filepath.Join(base, "ssl.crt"), filepath.Join(base, "ssl.key")},
                }
                for _, c := range candidates {
                        if fileOK(c[0]) && fileOK(c[1]) {
                                out = append(out, Pair{Source: SrcCPanel, CertPath: c[0], KeyPath: c[1]})
                                break
                        }
                }
        }
        return out
}

// cPanel service bundles directory may contain PEMs that include both cert+key
// (or at least cert chains). For combined PEM we set CertPath=KeyPath=the same file.
func scanCPanelServiceBundles(dir string) []Pair {
        entries, err := os.ReadDir(dir)
        if err != nil {
                return nil
        }
        out := []Pair{}
        for _, e := range entries {
                if e.IsDir() {
                        continue
                }
                name := e.Name()
                if !strings.HasSuffix(name, ".pem") {
                        continue
                }
                p := filepath.Join(dir, name)
                if !fileOK(p) {
                        continue
                }
                if !pemHasPrivateKey(p) {
                        continue
                }
                out = append(out, Pair{
                        Source:   SrcCPanel,
                        CertPath: p,
                        KeyPath:  p, // combined pem (cert+key) or best-effort
                })
        }
        return out
}









func scanLetsEncrypt(liveDir string) []Pair {
	entries, err := os.ReadDir(liveDir)
	if err != nil {
		return nil
	}
	out := []Pair{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		base := filepath.Join(liveDir, e.Name())
		cert := filepath.Join(base, "fullchain.pem")
		key := filepath.Join(base, "privkey.pem")
		if fileOK(cert) && fileOK(key) {
			out = append(out, Pair{Source: SrcLetsEncrypt, CertPath: cert, KeyPath: key})
		}
	}
	return out
}


// mailcowExcludedDir identifies Mailcow TLS-store trees that hold ACME
// account keys or historical certificates rather than active serving material.
func mailcowExcludedDir(name string) bool {
	switch name {
	case "acme", "backups":
		return true
	default:
		return false
	}
}

// mailcowActiveDirs returns only the active root and immediate SNI host
// directories. It is shared by discovery and the shallow watcher setup so the
// watch set cannot drift wider than the scan set.
func mailcowActiveDirs(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	out := []string{root}
	for _, entry := range entries {
		if !entry.IsDir() || mailcowExcludedDir(entry.Name()) {
			continue
		}
		out = append(out, filepath.Join(root, entry.Name()))
	}
	return out
}

// scanMailcow discovers the active Mailcow certificate pair plus immediate
// per-host SNI pairs. The shared mailcowActiveDirs policy makes the scan
// deliberately non-recursive, so stale/private ACME material can never enter
// the serving inventory.
func scanMailcow(root string) []Pair {
	out := make([]Pair, 0, 4)
	for _, dir := range mailcowActiveDirs(root) {
		cert := filepath.Join(dir, "cert.pem")
		key := filepath.Join(dir, "key.pem")
		if fileOK(cert) && fileOK(key) {
			// Mailcow cert.pem is the served full chain, so no separate ChainPath.
			out = append(out, Pair{Source: SrcMailcow, CertPath: cert, KeyPath: key})
		}
	}
	return out
}


func scanCPanel(root string) []Pair {
    dirs, err := os.ReadDir(root)
    if err != nil {
        return nil
    }

    out := []Pair{}
    for _, d := range dirs {
        if !d.IsDir() {
            continue
        }
        base := filepath.Join(root, d.Name())

        // cPanel apache_tls:
        // - certificates = cert chain
        // - combined     = key + cert chain (key first)
        certs := filepath.Join(base, "certificates")
        comb  := filepath.Join(base, "combined")

        if fileOK(certs) && fileOK(comb) {
            out = append(out, Pair{
                Source:    SrcCPanel,
                CertPath:  certs,   // chain is fine here
                KeyPath:   comb,    // contains private key (+ also certs)
                ChainPath: "",      // optional; not needed for most loaders
            })
            continue
        }

        // fallback: other possible shapes (rare, but keep your old candidates)
        candidates := [][2]string{
            {filepath.Join(base, "cert"), filepath.Join(base, "key")},
            {filepath.Join(base, "crt"), filepath.Join(base, "key")},
            {filepath.Join(base, "certificate"), filepath.Join(base, "privatekey")},
        }
        for _, c := range candidates {
            if fileOK(c[0]) && fileOK(c[1]) {
                out = append(out, Pair{Source: SrcCPanel, CertPath: c[0], KeyPath: c[1]})
                break
            }
        }
    }

    return out
}



func scanDirectAdmin(usersRoot string) []Pair {
	users, err := os.ReadDir(usersRoot)
	if err != nil {
		return nil
	}
	out := []Pair{}
	for _, u := range users {
		if !u.IsDir() {
			continue
		}
		domainsDir := filepath.Join(usersRoot, u.Name(), "domains")
		files, err := os.ReadDir(domainsDir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			name := f.Name()
			// Match only "<domain>.cert", not "<domain>.cert.combined"
			// or "<domain>.cert.creation_time".
			if !strings.HasSuffix(name, ".cert") || strings.Contains(name, ".cert.") {
				continue
			}
			base := filepath.Join(domainsDir, strings.TrimSuffix(name, ".cert"))
			cert := base + ".cert"
			key := base + ".key"

			// DirectAdmin's actual layout (current as of DA 1.6x):
			//   <domain>.cert           leaf only
			//   <domain>.cacert         intermediate chain
			//   <domain>.cert.combined  leaf + chain (no key)
			//   <domain>.key            private key
			//
			// Older / forked / future DA builds have shipped a few
			// other names. We probe a known list in preference order
			// (chain-only first, combined-with-possible-key last —
			// dumpall.go strips PRIVATE KEY blocks defensively, so even
			// if a combined file is picked the worker never sees the
			// key), then fall back to a glob-based scan that catches
			// anything new with "ca", "chain", or "intermediate" in
			// its extension so a DA renaming in v1.7+ doesn't break us
			// silently.
			chain := findDirectAdminChain(base)

			if fileOK(cert) && fileOK(key) {
				p := Pair{Source: SrcDirectAdmin, CertPath: cert, KeyPath: key, ChainPath: chain}
				out = append(out, p)
			}
		}
	}
	return out
}


// findDirectAdminChain locates the intermediate-chain file that pairs
// with a DA per-domain cert at `<base>.cert`. Returns "" when nothing
// suitable is found (worker then ships leaf-only, current behaviour).
//
// Lookup order:
//  1. Explicit, ordered candidate list — covers known DA naming
//     conventions across versions. Chain-only files are preferred over
//     combined files; combined files (which may carry the private key)
//     are accepted but PRIVATE KEY blocks are stripped in dumpall.go
//     before the bytes leave the daemon.
//  2. Glob fallback — any sibling `<base>.*` whose extension contains
//     "ca", "chain", "bundle", "intermediate", or "fullchain". This
//     catches future renames without requiring a code change.
//     `.cert`, `.csr`, `.key`, `.conf`, and other obvious non-chain
//     extensions are excluded.
func findDirectAdminChain(base string) string {
	// Known names, most-specific / safest first.
	for _, suf := range []string{
		".cacert",        // modern DA — chain only
		".ca",            // legacy DA
		".chain",         // some forks
		".chain.pem",
		".ca-bundle",     // commercial CA distributions imported into DA
		".cabundle",
		".intermediate",
		".intermediate.pem",
		".fullchain",     // rare in DA but harmless to probe
		".fullchain.pem",
		".cert.combined", // leaf+chain (no key) — modern DA
		".combined",      // legacy combined (may include key; scrubbed in dumpall.go)
	} {
		if fileOK(base + suf) {
			return base + suf
		}
	}

	// Glob fallback: catch future renames. Same directory only.
	matches, _ := filepath.Glob(base + ".*")
	for _, m := range matches {
		if !fileOK(m) {
			continue
		}
		ext := strings.ToLower(strings.TrimPrefix(m, base+"."))
		// Reject things we definitely don't want as the chain source.
		switch ext {
		case "cert", "key", "csr", "conf", "ftp", "ip_list",
			"subdomains", "usage", "handlers", "locations.json",
			"csr_info", "cust_nginx", "ssl.bkup", "ssl.next_retry.bkup",
			"cert.creation_time":
			continue
		}
		if strings.Contains(ext, "private") ||
			strings.HasSuffix(ext, ".tmp") ||
			strings.HasSuffix(ext, ".swp") ||
			strings.HasSuffix(ext, ".bak") {
			continue
		}
		if strings.Contains(ext, "ca") ||
			strings.Contains(ext, "chain") ||
			strings.Contains(ext, "bundle") ||
			strings.Contains(ext, "intermediate") ||
			strings.Contains(ext, "fullchain") {
			return m
		}
	}
	return ""
}

// DirectAdmin hostname / panel certs:
// /usr/local/directadmin/data/admin/ssl.cert + ssl.key (+ optional ssl.ca)
func scanDirectAdminAdmin(adminDir string) []Pair {
        cert := filepath.Join(adminDir, "ssl.cert")
        key := filepath.Join(adminDir, "ssl.key")
        ca  := filepath.Join(adminDir, "ssl.ca")
        if !fileOK(cert) || !fileOK(key) {
                return nil
        }
        p := Pair{Source: SrcDirectAdmin, CertPath: cert, KeyPath: key}
        if fileOK(ca) {
                p.ChainPath = ca
        }
        return []Pair{p}
}

// Webmin/Virtualmin panel (miniserv) typically uses a single combined PEM file.
// We treat it as CertPath=KeyPath=miniserv.pem.
func scanWebminMiniserv(pemPath string) []Pair {
        if !fileOK(pemPath) {
                return nil
        }
        if !pemHasPrivateKey(pemPath) {
                return nil
        }
        return []Pair{{Source: SrcWebmin, CertPath: pemPath, KeyPath: pemPath}}

}



func scanVirtualmin(root string) []Pair {
	out := []Pair{}
	keys, _ := filepath.Glob(filepath.Join(root, "*.key"))
	for _, k := range keys {
		base := strings.TrimSuffix(k, ".key")
		cert := base + ".cert"
		if fileOK(cert) {
			out = append(out, Pair{Source: SrcVirtualmin, CertPath: cert, KeyPath: k})
		}
	}
	return out
}

func scanHomeVirtualmin(home string) []Pair {
	out := []Pair{}
	keys, _ := filepath.Glob(filepath.Join(home, "*", "domains", "*", "ssl.key"))
	for _, k := range keys {
		dir := filepath.Dir(k)
		cert := filepath.Join(dir, "ssl.cert")
		if !fileOK(cert) {
			continue
		}
		p := Pair{Source: SrcVirtualmin, CertPath: cert, KeyPath: k}
		// Attach the intermediate chain when present. Virtualmin writes
		// ssl.ca (intermediate-only) and ssl.combined (leaf+chain) next to
		// ssl.cert. Without this the worker ships a leaf-only chain, which
		// fails for clients that don't cache intermediates (Android, some
		// Java/OCSP stacks). PRIVATE KEY blocks in a combined file are
		// scrubbed in dumpall.go before the bytes leave the daemon.
		for _, chain := range []string{
			filepath.Join(dir, "ssl.ca"),
			filepath.Join(dir, "ssl.combined"),
		} {
			if fileOK(chain) {
				p.ChainPath = chain
				break
			}
		}
		out = append(out, p)
	}
	return out
}


// System/service TLS certs: often used for hostname on cPanel/DA servers (Exim).
// Examples:
//  - /etc/exim.crt + /etc/exim.key   (common on cPanel-like setups)
//  - /etc/exim.cert + /etc/exim.key  (common on DirectAdmin-like setups)
func scanSystemMailTLS(etcDir string) []Pair {
        out := []Pair{}

        candidates := [][3]string{
                // cert, key, chain(optional)
                {"exim.crt",  "exim.key",  ""},
                {"exim.cert", "exim.key",  ""},
                {"exim.pem",  "exim.key",  ""}, // some distros
                {"exim.pem",  "exim.pem",  ""}, // combined pem (rare)
        }

        for _, c := range candidates {
                cert := filepath.Join(etcDir, c[0])
                key  := filepath.Join(etcDir, c[1])
                chain := ""
                if c[2] != "" {
                        chain = filepath.Join(etcDir, c[2])
                }

                if !fileOK(cert) || !fileOK(key) {
                        continue
                }

                // If cert==key (combined PEM), ensure it has a key block.
                if cert == key && !pemHasPrivateKey(cert) {
                        continue
                }

                p := Pair{Source: SrcGeneric, CertPath: cert, KeyPath: key}
                if chain != "" && fileOK(chain) {
                        p.ChainPath = chain
                }
                out = append(out, p)
        }

        return out
}
