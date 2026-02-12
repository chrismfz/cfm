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

	// DirectAdmin
	out = append(out, scanDirectAdmin("/usr/local/directadmin/data/users")...)

	// Virtualmin
	out = append(out, scanVirtualmin("/etc/ssl/virtualmin")...)
	out = append(out, scanHomeVirtualmin("/home")...)

	return out
}

func fileOK(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular() && st.Size() > 0
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
