package nft

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
//	"time"

	"cfm/internal/blocklists"
)

// --- Applier: καλείται από τον blocklists.Manager για κάθε feed ----

func (b *Backend) ApplyFeed(ctx context.Context, f blocklists.Feed, res *blocklists.FetchResult) error {
	if res == nil {
		return nil
	}
	feedKey := SanitizeFeedName(f.Name)
	isAllow := (f.Type == blocklists.TypeAllow)
	base := "block_ext"
	if isAllow {
		base = "allow_ext"
	}

	// χώρισε hosts vs nets, v4/v6
	h4, n4 := splitHostsNets(res.V4, false)
	h6, n6 := splitHostsNets(res.V6, true)

	ttl := f.TTL // *time.Duration ή nil (όπως το έχεις στο Feed)

	// per-feed δυναμικά sets
	nameH4 := fmt.Sprintf("%s_v4_hosts_%s", base, feedKey)
	nameN4 := fmt.Sprintf("%s_v4_nets_%s", base, feedKey)
	nameH6 := fmt.Sprintf("%s_v6_hosts_%s", base, feedKey)
	nameN6 := fmt.Sprintf("%s_v6_nets_%s", base, feedKey)

	if err := b.EnsureSetDynamic(nameH4, false, false); err == nil { _ = b.ReplaceSetFlushAdd(nameH4, h4, ttl) }
	if err := b.EnsureSetDynamic(nameN4, false, true);  err == nil { _ = b.ReplaceSetFlushAdd(nameN4, n4, ttl) }
	if err := b.EnsureSetDynamic(nameH6, true,  false); err == nil { _ = b.ReplaceSetFlushAdd(nameH6, h6, ttl) }
	if err := b.EnsureSetDynamic(nameN6, true,  true);  err == nil { _ = b.ReplaceSetFlushAdd(nameN6, n6, ttl) }

	// μετά από κάθε apply, ξαναχτίσε τα unions που κοιτούν οι rules
	return b.RebuildExternalUnions()
}

// RebuildExternalUnions: union όλων των per-feed sets σε 4 “global” sets
func (b *Backend) RebuildExternalUnions() error {
	type bucketKey struct{ action, fam, kind string } // action: allow|block; fam: v4|v6; kind: hosts|nets
	re := regexp.MustCompile(`^(allow|block)_ext_(v4|v6)_(hosts|nets)_(.+)$`)

	// μάζεψε ονόματα per-feed sets από το table
	names := append(b.listSetsWithPrefix("allow_ext_"), b.listSetsWithPrefix("block_ext_")...)
	buckets := map[bucketKey][]string{}
	for _, name := range names {
		m := re.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		k := bucketKey{action: m[1], fam: m[2], kind: m[3]}
		buckets[k] = append(buckets[k], name)
	}

	// για κάθε bucket, διάβασε elements και γράψε το union set χωρίς suffix
	for k, sets := range buckets {
		union := fmt.Sprintf("%s_ext_%s_%s", k.action, k.fam, k.kind) // π.χ. allow_ext_v4_hosts
		var elems []string
		for _, s := range sets {
			items, _ := b.ListSetElementsRaw(s) // []string με IP ή CIDR όπως το κρατάει το nft
			elems = append(elems, items...)
		}
		elems = dedupKeepOrder(elems)

		isV6 := (k.fam == "v6")
		isNets := (k.kind == "nets")
		if err := b.EnsureSetDynamic(union, isV6, isNets); err != nil {
			continue
		}
		if err := b.ReplaceSetFlushAdd(union, elems, nil); err != nil {
			continue
		}
	}
	return nil
}

// --- Helpers -------------------------------------------------------------

// Επιστρέφει τα elements ενός set ως raw []string (IP ή CIDR), χωρίς parsing σε net.IP
func (b *Backend) ListSetElementsRaw(setName string) ([]string, error) {
	raw, err := exec.Command("nft", "-j", "list", "set", family, tableName, setName).CombinedOutput()
	if err != nil {
		return nil, err
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	nftables, _ := root["nftables"].([]any)
	var out []string
	for _, it := range nftables {
		m, _ := it.(map[string]any)
		setObj, _ := m["set"].(map[string]any)
		if setObj == nil {
			continue
		}
		arr, _ := setObj["elem"].([]any)
		if len(arr) == 0 {
			arr, _ = setObj["elements"].([]any)
		}
		for _, e := range arr {
			switch v := e.(type) {
			case string:
				s := strings.TrimSpace(v)
				if s != "" {
					out = append(out, s)
				}
			case map[string]any:
				// JSON formats ποικίλουν: πιάσε val όπου υπάρχει
				if inner, ok := v["elem"].(map[string]any); ok {
					val := toStr(inner["val"])
					val = strings.TrimSpace(val)
					if val != "" {
						out = append(out, val)
					}
				} else if val := strings.TrimSpace(toStr(v["elem"])); val != "" {
					out = append(out, val)
				}
				// (σε “interval” sets το nft συνήθως επιστρέφει CIDR ως string, οπότε τα καλύψαμε ήδη)
			}
		}
	}
	return out, nil
}

// split hosts vs nets, validate family
func splitHostsNets(elems []string, isV6 bool) (hosts []string, nets []string) {
	seenH, seenN := map[string]struct{}{}, map[string]struct{}{}
	maxBits := 32
	if isV6 {
		maxBits = 128
	}
	for _, s := range elems {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				continue
			}
			ones, bits := n.Mask.Size()
			if bits != maxBits {
				continue
			}
			if ones == maxBits {
				ip := n.IP.String()
				if _, ok := seenH[ip]; !ok {
					seenH[ip] = struct{}{}
					hosts = append(hosts, ip)
				}
			} else {
				canon := n.IP.Mask(n.Mask).String() + "/" + strconv.Itoa(ones)
				if _, ok := seenN[canon]; !ok {
					seenN[canon] = struct{}{}
					nets = append(nets, canon)
				}
			}
		} else {
			ip := net.ParseIP(s)
			if ip == nil {
				continue
			}
			if !isV6 && ip.To4() == nil {
				continue
			}
			if isV6 && (ip.To16() == nil || ip.To4() != nil) {
				continue
			}
			ipS := ip.String()
			if _, ok := seenH[ipS]; !ok {
				seenH[ipS] = struct{}{}
				hosts = append(hosts, ipS)
			}
		}
	}
	return
}

func dedupKeepOrder(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, x := range in {
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}
