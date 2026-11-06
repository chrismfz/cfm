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
// site behind it down. Cloudflare is trusted (trusted_proxies.conf), but a
// request a Cloudflare address sends without CF-Connecting-IP (a Worker)
// reads as Cloudflare's own address too.
const loginBruteforceProxyASNs = "13335,209242,30148,19551,54113,20940,16625,12989,33438,200325"

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

// applyBuiltinLoginBruteforce adds the default section (and its leniency)
// when the config has no login_bruteforce section at all. A section the
// operator wrote, even one with ENABLED = 0 or without a leniency block, is
// left exactly as written.
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
	for name := range secs.ByName {
		if typ, _ := SplitTypeInstance(name); typ == loginBruteforceType {
			return
		}
	}
	def := loginBruteforceDefaults()
	def[cfmEndpointsSyntheticKey] = "1"
	secs.ByName[loginBruteforceType] = def
	// A leniency block written on its own is the operator's: keep it.
	if _, ok := secs.ByName[loginBruteforceType+".leniency"]; !ok {
		secs.ByName[loginBruteforceType+".leniency"] = loginBruteforceLeniencyDefaults()
	}
	secs.ByType[loginBruteforceType] = []string{loginBruteforceType}
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
			AllowASNs: csvKV(kv, "ALLOW_ASNS"),
		})
		d.SetName(section)
		d.AddUnsubscribe(webdetector.SubscribeLoginFailEvents(func(ev webdetector.LoginFailEvent) {
			d.Enqueue(loginbf.Event{When: ev.When, IP: ev.IP, Host: ev.Host, Site: ev.Site, Tag: ev.Tag, Owner: ev.Owner})
		}))
		return d, nil
	})
}
