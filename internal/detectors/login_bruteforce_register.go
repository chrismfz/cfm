package detectors

import (
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/loginbf"
	"cfm/internal/detectors/meta"
	"cfm/internal/webdetector"
)

const loginBruteforceType = "login_bruteforce"

// loginBruteforceProxyASNs are reverse proxies and WAF CDNs CFM does not
// trust to name the client: every visitor of a site behind one reads as the
// proxy's address, and a 3 day ban reported to the fleet would take every
// site behind it down. Sucuri, Imperva, Fastly, Akamai, StackPath and Bunny.
// Cloudflare is NOT listed: its proxies are trusted (trusted_proxies.conf,
// and the detector skips those ranges, which exempts every Worker too: a
// known gap), while its ASN is also WARP's egress, which an attacker can
// brute force from.
const loginBruteforceProxyASNs = "30148,19551,54113,20940,16625,12989,33438,200325"

// loginBruteforceDefaults is the [login_bruteforce] section a node runs when
// its detectors.conf has none (every node whose conffile predates it): the
// operator wanted it on fleet-wide from the start, not only on fresh
// installs. It must equal the stock configs/detectors.conf section
// (TestLoginBruteforceDefaultsMatchReferenceConfig pins it).
func loginBruteforceDefaults() KV {
	return KV{
		"ENABLED":    "1",
		"EVERY":      "10s",
		"WINDOW":     "1h",
		"SITE_FAILS": "5",
		"SITES":      "5",
		"DRY_RUN":    "0",
		"BLOCK":      "3d",
		// A banned client behind Cloudflare is not stopped by the nft drop and,
		// with [webdetector] EDGE_BAN_MODE = log, not at the edge either: it keeps
		// failing, and every new alert would mail and report it again.
		"BLOCK_COOLDOWN": "6h",
		"ALLOW_ASNS":     loginBruteforceProxyASNs,
	}
}

// loginBruteforceLeniencyDefaults is the [login_bruteforce.leniency] a node
// runs with the built-in section: a Greek or Cypriot address (most of the
// customers) gets a 10 minute ban, reported nowhere. Customers who lock
// themselves out know unblock.myip.gr.
func loginBruteforceLeniencyDefaults() KV {
	return KV{
		"MATCH_COUNTRY":  "GR,CY",
		"BLOCK":          "10m",
		"BLOCK_COOLDOWN": "10m",
		"SEND_TO_API":    "no",
	}
}

// applyBuiltinLoginBruteforce adds the default section when the config has
// no login_bruteforce section at all, and the GR/CY leniency to every
// login_bruteforce section that has none. A section the operator wrote, even
// one with ENABLED = 0, is otherwise left as written. The leniency is added
// even to a written section because cfm-admin's "Add" and "Initialize from
// catalog" write the section without one, and without it a Greek customer
// who mistypes gets the full ban and a fleet report. A leniency with no
// criteria gets the GR/CY ones too: cfm-admin's "Add leniency companion"
// writes MATCH_COUNTRY = "". A section runs with no leniency only when its
// [.leniency] says ENABLED = 0.
func applyBuiltinLoginBruteforce(secs *Sections) {
	if secs == nil {
		return
	}
	if secs.ByName == nil {
		secs.ByName = make(map[string]KV)
	}
	if secs.ByType == nil {
		secs.ByType = make(map[string][]string)
	}
	var written []string
	for name := range secs.ByName {
		if typ, _ := SplitTypeInstance(name); typ == loginBruteforceType {
			written = append(written, name)
		}
	}
	if len(written) == 0 {
		def := loginBruteforceDefaults()
		def[cfmEndpointsSyntheticKey] = "1"
		secs.ByName[loginBruteforceType] = def
		secs.ByType[loginBruteforceType] = []string{loginBruteforceType}
		written = []string{loginBruteforceType}
	}
	for _, name := range written {
		lk := name + ".leniency"
		lkv, ok := secs.ByName[lk]
		switch {
		case !ok:
			secs.ByName[lk] = loginBruteforceLeniencyDefaults()
		case !kvBool(lkv, "ENABLED", true):
			secs.ByName[lk] = KV{} // no criteria: parseLeniencyPolicy turns it off
		case kvStrClean(lkv, "MATCH_COUNTRY", "") == "" && kvStrClean(lkv, "MATCH_ASN", "") == "":
			merged := loginBruteforceLeniencyDefaults()
			for k, v := range lkv {
				if cleanScalar(v) != "" {
					merged[k] = v
				}
			}
			secs.ByName[lk] = merged
		}
	}
}

func init() {
	tmpl := map[string]string{}
	for k, v := range loginBruteforceDefaults() {
		tmpl[k] = v
	}
	meta.Register(meta.DetectorMeta{
		TypeKey:             loginBruteforceType,
		Title:               "Login brute force",
		Description:         "nft ban for a client that fails logins on one site, or on many sites, within an hour (the web detector's login column).",
		DefaultsTemplate:    tmpl,
		LeniencySupported:   true,
		LeniencyRecommended: true,
	})

	Register(loginBruteforceType, func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		d := loginbf.New(loginbf.Config{
			Every:     kvDur(kv, "EVERY", 10*time.Second),
			Window:    kvDur(kv, "WINDOW", time.Hour),
			SiteFails: kvInt(kv, "SITE_FAILS", 5),
			Sites:     kvInt(kv, "SITES", 5),
			DryRun:    kvBool(kv, "DRY_RUN", false),
			AllowIPs:  csvKV(kv, "ALLOW_IPS"),
			AllowNets: csvKV(kv, "ALLOW_NETS"),
			// The proxy list is the default even for a section the operator
			// wrote without the key: a minimal section must not ban a proxy.
			AllowASNs: []string{kvStrClean(kv, "ALLOW_ASNS", loginBruteforceProxyASNs)},
		})
		d.SetName(section)
		d.AddUnsubscribe(webdetector.SubscribeLoginEvents(func(ev webdetector.LoginEvent) {
			d.Enqueue(loginbf.Event{When: ev.When, IP: ev.IP, Host: ev.Host, Site: ev.Site, Tag: ev.Tag, OK: ev.OK, Owner: ev.Owner})
		}))
		return d, nil
	})
}
