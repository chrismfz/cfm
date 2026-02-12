package sslcollector

import (
	"os"
	"path/filepath"
	"strings"
)

func (c *Collector) discoverPairs() []Pair {
	out := make([]Pair, 0, 1024)

	// LetsEncrypt
	out = append(out, scanLetsEncrypt("/etc/letsencrypt/live")...)

	// cPanel
	out = append(out, scanCPanel("/var/cpanel/ssl/apache_tls")...)
        out = append(out, scanCPanelHostsInstalled("/var/cpanel/ssl/installed/hosts")...)
        out = append(out, scanCPanelServiceBundles("/var/cpanel/ssl/cpanel")...)

	// DirectAdmin
	out = append(out, scanDirectAdmin("/usr/local/directadmin/data/users")...)
        out = append(out, scanDirectAdminAdmin("/usr/local/directadmin/data/admin")...)

	// Virtualmin
	out = append(out, scanVirtualmin("/etc/ssl/virtualmin")...)
	out = append(out, scanHomeVirtualmin("/home")...)
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
			if !strings.HasSuffix(f.Name(), ".cert") {
				continue
			}
			base := filepath.Join(domainsDir, strings.TrimSuffix(f.Name(), ".cert"))
			cert := base + ".cert"
			key := base + ".key"
			ca := base + ".ca"
			combined := base + ".combined"

			if fileOK(cert) && fileOK(key) {
				p := Pair{Source: SrcDirectAdmin, CertPath: cert, KeyPath: key}
				if fileOK(combined) {
					p.ChainPath = combined
				} else if fileOK(ca) {
					p.ChainPath = ca
				}
				out = append(out, p)
			}
		}
	}
	return out
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
		cert := filepath.Join(filepath.Dir(k), "ssl.cert")
		if fileOK(cert) {
			out = append(out, Pair{Source: SrcVirtualmin, CertPath: cert, KeyPath: k})
		}
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
