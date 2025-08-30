//go:build linux

package nft

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	enrichpkg "cfm/internal/enrich"
	"cfm/internal/firewall"
	cfgpkg "cfm/internal/config"
)

const (
	tableName = "cfm"
	family    = "inet"

	// manual
	setV4   = "block_v4"
	setV6   = "block_v6"
	allowV4 = "allow_v4"
	allowV6 = "allow_v6"
	allowDynV4 = "allow_dyn_v4"
	allowDynV6 = "allow_dyn_v6"

	// external (SPLIT: hosts vs nets)
	allowExtV4Hosts = "allow_ext_v4_hosts" // type ipv4_addr; flags timeout
	allowExtV6Hosts = "allow_ext_v6_hosts" // type ipv6_addr; flags timeout
	allowExtV4Nets  = "allow_ext_v4_nets"  // type ipv4_addr; flags timeout,interval
	allowExtV6Nets  = "allow_ext_v6_nets"  // type ipv6_addr; flags timeout,interval

	blockExtV4Hosts = "block_ext_v4_hosts"
	blockExtV6Hosts = "block_ext_v6_hosts"
	blockExtV4Nets  = "block_ext_v4_nets"
	blockExtV6Nets  = "block_ext_v6_nets"
)




type setDesc struct {
    name   string // π.χ. block_ext_v4_nets_dshield
    family string // "ip" ή "ip6"
    action string // "ALLOW" ή "BLOCK"
    scope  string // "hosts" ή "nets"
    feed   string // π.χ. "dshield", "myallow" (κενό για manual)
}


var debugEnv = os.Getenv("CFM_DEBUG") == "1"

type Backend struct{
    last map[string]int // last seen packets per counter (for delta logging)
    cfg  *cfgpkg.PortsConfig

    enr  *enrichpkg.Enricher
}

//func New() *Backend { return &Backend{} }

func New() *Backend {
    return &Backend{
        last: make(map[string]int),
    }
}

// Προαιρετικός helper: ενεργοποιεί enrichment αν βρεθούν mmdb σε dirs
func (b *Backend) EnableEnrichment(dirs ...string) {
    if b == nil || b.enr != nil { return }
    if e, _ := enrichpkg.New(dirs...); e != nil {
        b.enr = e
    }
}

// (προαιρετικά) Setter αν θέλεις να το περνάς “έτοιμο”
func (b *Backend) SetEnricher(e *enrichpkg.Enricher) { b.enr = e }


// ---------- ensure base ----------

func (b *Backend) ensureSetWithFlags(name, typ, flags string) error {
	if !b.setExists(name) {
		return b.nftCmd(fmt.Sprintf(`add set %s %s %s { type %s; flags %s; }`, family, tableName, name, typ, flags))
	}
	return nil
}

func (b *Backend) ensureSet(name, typ string) error {
	if !b.setExists(name) {
		return b.nftCmd(fmt.Sprintf(`add set %s %s %s { type %s; flags timeout; }`, family, tableName, name, typ))
	}
	return nil
}







func (b *Backend) EnsureBase() error {
	// 1) Ensure table
	if !b.tableExists() {
		if err := b.nftCmd(fmt.Sprintf("add table %s %s", family, tableName)); err != nil {
			return err
		}
	}

	// 2) Ensure chains
	// input (with hook)
	if !b.chainExists("input") {
		if err := b.nftCmd(fmt.Sprintf(
			`add chain %s %s input { type filter hook input priority filter; policy accept; }`,
			family, tableName,
		)); err != nil {
			return err
		}
	}
	// flood (no hook)
	if !b.chainExists("flood") {
		if err := b.nftCmd(fmt.Sprintf(`add chain %s %s flood`, family, tableName)); err != nil {
			return err
		}
	}

	// 3) Ensure sets (manual/dyn/external)
	// manual allow/block
	if err := b.ensureSet(allowV4, "ipv4_addr"); err != nil { return err }
	if err := b.ensureSet(allowV6, "ipv6_addr"); err != nil { return err }
	if err := b.ensureSet(setV4,   "ipv4_addr"); err != nil { return err }
	if err := b.ensureSet(setV6,   "ipv6_addr"); err != nil { return err }
	// dyn allow
	if err := b.ensureSet(allowDynV4, "ipv4_addr"); err != nil { return err }
	if err := b.ensureSet(allowDynV6, "ipv6_addr"); err != nil { return err }
	// external allow (hosts/nets)
	if err := b.ensureSetWithFlags(allowExtV4Hosts, "ipv4_addr", "timeout");          err != nil { return err }
	if err := b.ensureSetWithFlags(allowExtV6Hosts, "ipv6_addr", "timeout");          err != nil { return err }
	if err := b.ensureSetWithFlags(allowExtV4Nets,  "ipv4_addr", "timeout,interval"); err != nil { return err }
	if err := b.ensureSetWithFlags(allowExtV6Nets,  "ipv6_addr", "timeout,interval"); err != nil { return err }
	// external block (hosts/nets)
	if err := b.ensureSetWithFlags(blockExtV4Hosts, "ipv4_addr", "timeout");          err != nil { return err }
	if err := b.ensureSetWithFlags(blockExtV6Hosts, "ipv6_addr", "timeout");          err != nil { return err }
	if err := b.ensureSetWithFlags(blockExtV4Nets,  "ipv4_addr", "timeout,interval"); err != nil { return err }
	if err := b.ensureSetWithFlags(blockExtV6Nets,  "ipv6_addr", "timeout,interval"); err != nil { return err }



// reason-specific throttled sets
_ = b.ensureSetWithFlags("th_syn_v4",      "ipv4_addr", "timeout")
_ = b.ensureSetWithFlags("th_syn_v6",      "ipv6_addr", "timeout")
_ = b.ensureSetWithFlags("th_pps_v4",      "ipv4_addr", "timeout")
_ = b.ensureSetWithFlags("th_pps_v6",      "ipv6_addr", "timeout")
_ = b.ensureSetWithFlags("th_pf_tcp_v4",   "ipv4_addr", "timeout")
_ = b.ensureSetWithFlags("th_pf_tcp_v6",   "ipv6_addr", "timeout")
_ = b.ensureSetWithFlags("th_pf_udp_v4",   "ipv4_addr", "timeout")
_ = b.ensureSetWithFlags("th_pf_udp_v6",   "ipv6_addr", "timeout")
// (προαιρετικά) συγκεντρωτικά
_ = b.ensureSetWithFlags("throttled_v4",   "ipv4_addr", "timeout")
_ = b.ensureSetWithFlags("throttled_v6",   "ipv6_addr", "timeout")



	// 4) Base allow/deny rules (idempotent, σταθερή σειρά)
	addRule := func(expr string) error {
		if !b.ruleExists("input", expr) {
			return b.nftCmd(fmt.Sprintf(`add rule %s %s input %s`, family, tableName, expr))
		}
		return nil
	}
	// 1) manual allow
	if err := addRule(`ip saddr @allow_v4 accept`);  err != nil { return err }
	if err := addRule(`ip6 saddr @allow_v6 accept`); err != nil { return err }
	// 2) dyn allow
	if err := addRule(`ip saddr @allow_dyn_v4 accept`);  err != nil { return err }
	if err := addRule(`ip6 saddr @allow_dyn_v6 accept`); err != nil { return err }
	// 3) external allow (hosts, then nets)
	if err := addRule(`ip saddr @allow_ext_v4_hosts accept`);  err != nil { return err }
	if err := addRule(`ip6 saddr @allow_ext_v6_hosts accept`); err != nil { return err }
	if err := addRule(`ip saddr @allow_ext_v4_nets accept`);   err != nil { return err }
	if err := addRule(`ip6 saddr @allow_ext_v6_nets accept`);  err != nil { return err }
	// 4) manual block
	if err := addRule(`ip saddr @block_v4 drop`);  err != nil { return err }
	if err := addRule(`ip6 saddr @block_v6 drop`); err != nil { return err }
	// 5) external block (hosts, then nets)
	if err := addRule(`ip saddr @block_ext_v4_hosts drop`);  err != nil { return err }
	if err := addRule(`ip6 saddr @block_ext_v6_hosts drop`); err != nil { return err }
	if err := addRule(`ip saddr @block_ext_v4_nets drop`);   err != nil { return err }
	if err := addRule(`ip6 saddr @block_ext_v6_nets drop`);  err != nil { return err }

	// 5) Ensure jump flood is present *μετά* τα allow/deny και *πριν* τα port rules
	if !b.ruleExists("input", "jump flood") {
		if err := b.nftCmd(fmt.Sprintf(`add rule %s %s input jump flood`, family, tableName)); err != nil {
			return err
		}
	}

	return nil
}












// -------- block (manual) --------

func (b *Backend) AddBlock(ip net.IP, _ string, ttl *time.Duration) error {
	if ip == nil {
		return errors.New("nil ip")
	}
	set := setV4
	if ip.To4() == nil {
		set = setV6
	}
	elem := ip.String()

	_ = b.RemoveBlock(ip)

	ttlStr := ""
	if ttl != nil && *ttl > 0 {
		ttlStr = humanTimeout(*ttl) // 90s / 5m / 1h
	}

	out, err := b.nftAddElementArgv(set, elem, ttlStr)
	if err == nil {
		return nil
	}
	if strings.Contains(out, "already exists") || strings.Contains(out, "File exists") {
		_ = b.RemoveBlock(ip)
		if out2, err2 := b.nftAddElementArgv(set, elem, ttlStr); err2 == nil {
			return nil
		} else {
			return fmt.Errorf("nft add element (retry) failed: %v: %s", err2, out2)
		}
	}
	return fmt.Errorf("nft add element failed: %v: %s", err, out)
}

func (b *Backend) RemoveBlock(ip net.IP) error {
	if ip == nil {
		return errors.New("nil ip")
	}
	set := setV4
	elem := ip.String()
	if ip.To4() == nil {
		set = setV6
	}
	cmd := fmt.Sprintf(`delete element %s %s %s { %s }`, family, tableName, set, elem)
	out, err := b.nftOut(cmd)
	if err != nil && !strings.Contains(out, "No such file or directory") && !strings.Contains(out, "Could not delete element") {
		return fmt.Errorf("nft: %v: %s", err, out)
	}
	return nil
}

func (b *Backend) ListBlocks() ([]firewall.BlockedEntry, error) {
	var outAll []firewall.BlockedEntry
	sets := []struct {
		name string
		v6   bool
	}{{setV4, false}, {setV6, true}}
	for _, s := range sets {
		if ents, ok := b.listSetJSON_robust(s.name); ok {
			outAll = append(outAll, ents...)
			continue
		}
		if ents, ok := b.listSetText(s.name, s.v6); ok {
			outAll = append(outAll, ents...)
		}
	}
	return outAll, nil
}

// -------- allow (manual) --------

func (b *Backend) AddAllow(ip net.IP, ttl *time.Duration) error {
	if ip == nil {
		return errors.New("nil ip")
	}
	set := allowV4
	if ip.To4() == nil {
		set = allowV6
	}
	elem := ip.String()

	_ = b.RemoveAllow(ip)

	ttlStr := ""
	if ttl != nil && *ttl > 0 {
		ttlStr = humanTimeout(*ttl)
	}
	out, err := b.nftAddElementArgv(set, elem, ttlStr)
	if err == nil {
		return nil
	}
	if strings.Contains(out, "already exists") || strings.Contains(out, "File exists") {
		_ = b.RemoveAllow(ip)
		if out2, err2 := b.nftAddElementArgv(set, elem, ttlStr); err2 == nil {
			return nil
		} else {
			return fmt.Errorf("nft add allow (retry) failed: %v: %s", err2, out2)
		}
	}
	return fmt.Errorf("nft add allow failed: %v: %s", err, out)
}

func (b *Backend) RemoveAllow(ip net.IP) error {
	if ip == nil {
		return errors.New("nil ip")
	}
	set := allowV4
	elem := ip.String()
	if ip.To4() == nil {
		set = allowV6
	}
	cmd := fmt.Sprintf(`delete element %s %s %s { %s }`, family, tableName, set, elem)
	out, err := b.nftOut(cmd)
	if err != nil && !strings.Contains(out, "No such file or directory") && !strings.Contains(out, "Could not delete element") {
		return fmt.Errorf("nft: %v: %s", err, out)
	}
	return nil
}

func (b *Backend) ListAllows() ([]firewall.BlockedEntry, error) {
	var outAll []firewall.BlockedEntry
	sets := []struct {
		name string
		v6   bool
	}{{allowV4, false}, {allowV6, true}}
	for _, s := range sets {
		if ents, ok := b.listSetJSON_robust(s.name); ok {
			outAll = append(outAll, ents...)
			continue
		}
		if ents, ok := b.listSetText(s.name, s.v6); ok {
			outAll = append(outAll, ents...)
		}
	}
	return outAll, nil
}

// -------- listing helpers (JSON + text fallback) --------

func (b *Backend) listSetJSON_robust(setName string) ([]firewall.BlockedEntry, bool) {
	raw, err := exec.Command("nft", "-j", "list", "set", family, tableName, setName).CombinedOutput()
	if err != nil {
		return nil, false
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, false
	}
	nftables, _ := root["nftables"].([]any)
	if len(nftables) == 0 {
		return nil, false
	}

	var out []firewall.BlockedEntry
	parseSeconds := func(m map[string]any, key string) int {
		if m == nil {
			return 0
		}
		switch v := m[key].(type) {
		case float64:
			if v > 0 {
				return int(v)
			}
		case int:
			if v > 0 {
				return v
			}
		case string:
			s := strings.TrimSpace(v)
			if strings.HasSuffix(s, "s") {
				if n, err := strconv.Atoi(strings.TrimSuffix(s, "s")); err == nil && n > 0 {
					return n
				}
			} else if n, err := strconv.Atoi(s); err == nil && n > 0 {
				return n
			}
		}
		return 0
	}

	for _, item := range nftables {
		m, _ := item.(map[string]any)
		setObj, _ := m["set"].(map[string]any)
		if setObj == nil {
			continue
		}
		arr, _ := setObj["elem"].([]any)
		if len(arr) == 0 {
			arr, _ = setObj["elements"].([]any)
		}
		if len(arr) == 0 {
			continue
		}
		for _, e := range arr {
			switch v := e.(type) {
			case string:
				if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
					out = append(out, firewall.BlockedEntry{IP: ip})
				}
			case map[string]any:
				var elemIP string
				var seconds int
				if inner, ok := v["elem"].(map[string]any); ok {
					// host entry
					elemIP = toStr(inner["val"])
					if s := parseSeconds(inner, "expires"); s > 0 {
						seconds = s
					} else {
						seconds = parseSeconds(inner, "timeout")
					}
				} else {
					// older/other formats
					elemIP = toStr(v["elem"])
					if s := parseSeconds(v, "expires"); s > 0 {
						seconds = s
					} else {
						seconds = parseSeconds(v, "timeout")
					}
				}
				ip := net.ParseIP(strings.TrimSpace(elemIP))
				if ip == nil {
					continue
				}
				var exp *time.Time
				if seconds > 0 {
					t := time.Now().Add(time.Duration(seconds) * time.Second)
					exp = &t
				}
				out = append(out, firewall.BlockedEntry{IP: ip, Expires: exp})
			}
		}
	}
	return out, len(out) > 0
}

func toStr(x any) string {
	switch t := x.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprintf("%v", t)
	}
}

func (b *Backend) listSetText(setName string, v6 bool) ([]firewall.BlockedEntry, bool) {
	raw, err := exec.Command("nft", "list", "set", family, tableName, setName).CombinedOutput()
	if err != nil {
		return nil, false
	}
	s := string(raw)
	start := strings.Index(s, "elements = {")
	if start == -1 {
		return nil, false
	}
	end := strings.Index(s[start:], "}")
	if end == -1 {
		return nil, false
	}
	inner := s[start+len("elements = {") : start+end]
	toks := strings.Split(inner, ",")
	var out []firewall.BlockedEntry
	reV4 := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reV6 := regexp.MustCompile(`\b[0-9a-fA-F:]+::?[0-9a-fA-F:]*\b`)

	for _, t := range toks {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		var ipStr string
		if v6 {
			ipStr = reV6.FindString(t)
		} else {
			ipStr = reV4.FindString(t)
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		var exp *time.Time
		if i := strings.Index(t, "timeout "); i != -1 {
			part := strings.TrimSpace(t[i+len("timeout "):])
			if j := strings.Index(part, "s"); j != -1 {
				if n, err := strconv.Atoi(strings.TrimSpace(part[:j])); err == nil && n > 0 {
					tt := time.Now().Add(time.Duration(n) * time.Second)
					exp = &tt
				}
			}
		}
		out = append(out, firewall.BlockedEntry{IP: ip, Expires: exp})
	}
	return out, len(out) > 0
}

// -------- shell helpers --------

func (b *Backend) tableExists() bool {
	_, err := exec.Command("nft", "list", "table", family, tableName).CombinedOutput()
	return err == nil
}
func (b *Backend) chainExists(chain string) bool {
	_, err := exec.Command("nft", "list", "chain", family, tableName, chain).CombinedOutput()
	return err == nil
}
func (b *Backend) ruleExists(chain, contains string) bool {
	out, err := exec.Command("nft", "list", "chain", family, tableName, chain).CombinedOutput()
	return err == nil && strings.Contains(string(out), contains)
}
func (b *Backend) setExists(name string) bool {
	_, err := exec.Command("nft", "list", "set", family, tableName, name).CombinedOutput()
	return err == nil
}
func (b *Backend) nftCmd(expr string) error {
	_, err := b.nftOut(expr)
	return err
}
func (b *Backend) nftOut(expr string) (string, error) {
	expr = strings.TrimSpace(expr)
	if !strings.HasSuffix(expr, ";") {
		expr += ";"
	}
	if debugEnv {
		fmt.Fprintln(os.Stderr, "[nft] expr:", expr)
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(expr + "\n")
	out, err := cmd.CombinedOutput()
	if debugEnv {
		fmt.Fprintln(os.Stderr, "[nft] rc:", err)
		if len(out) > 0 {
			fmt.Fprintln(os.Stderr, "[nft] out:", string(out))
		}
	}
	return string(out), err
}

// argv-mode add element (όπως στο shell)
func (b *Backend) nftAddElementArgv(set, ip, ttl string) (string, error) {
	args := []string{"add", "element", family, tableName, set, "{", ip}
	if ttl != "" {
		args = append(args, "timeout", ttl)
	}
	args = append(args, "}")
	if debugEnv {
		fmt.Fprintln(os.Stderr, "[nft argv] cmd:", "nft", strings.Join(args, " "))
	}
	out, err := exec.Command("nft", args...).CombinedOutput()
	if debugEnv {
		fmt.Fprintln(os.Stderr, "[nft argv] rc:", err)
		if len(out) > 0 {
			fmt.Fprintln(os.Stderr, "[nft argv] out:", string(out))
		}
	}
	return string(out), err
}

// 90s/5m/1h/1d
func humanTimeout(d time.Duration) string {
	sec := int(d.Seconds())
	if sec <= 0 {
		return "0s"
	}
	if sec%86400 == 0 {
		return fmt.Sprintf("%dd", sec/86400)
	}
	if sec%3600 == 0 {
		return fmt.Sprintf("%dh", sec/3600)
	}
	if sec%60 == 0 {
		return fmt.Sprintf("%dm", sec/60)
	}
	return fmt.Sprintf("%ds", sec)
}

// ---------- external sets apply (flush + bulk add) ----------

// ReplaceSetFlushAdd: καθαρίζει το set και βάζει elems (IP ή CIDR) σε batches.
// Για _nets sets κάνει κανονικοποίηση CIDR (drop overlapping subnets).
// ttl==nil => χωρίς timeout per-element.
func (b *Backend) ReplaceSetFlushAdd(setName string, elems []string, ttl *time.Duration) error {
	// flush
	if err := b.nftExpr(fmt.Sprintf(`flush set %s %s %s;`, family, tableName, setName)); err != nil {
		return fmt.Errorf("flush %s: %w", setName, err)
	}

	// Αν είναι *nets set, καθάρισε επικαλύψεις

if strings.Contains(setName, "_v4_nets") {
    elems = normalizeCIDRsV4(elems)
}
if strings.Contains(setName, "_v6_nets") {
    elems = normalizeCIDRsV6(elems)
}


	ttlStr := ""
	if ttl != nil && *ttl > 0 {
		ttlStr = ttl.String()
	}
	return b.nftAddElementsExpr(setName, elems, ttlStr, 1500)
}

// add element ... { ... } σε batches, μέσω nft -f - (expr)
func (b *Backend) nftAddElementsExpr(setName string, elems []string, ttlStr string, batchSize int) error {
	if len(elems) == 0 {
		return nil
	}
	if batchSize <= 0 {
		batchSize = 1000
	}
	for i := 0; i < len(elems); i += batchSize {
		j := i + batchSize
		if j > len(elems) {
			j = len(elems)
		}
		chunk := elems[i:j]

		var sb strings.Builder
		sb.WriteString("add element ")
		sb.WriteString(family)
		sb.WriteString(" ")
		sb.WriteString(tableName)
		sb.WriteString(" ")
		sb.WriteString(setName)
		sb.WriteString(" { ")
		first := true
		for _, e := range chunk {
			e = strings.TrimSpace(e)
			if e == "" {
				continue
			}
			if !first {
				sb.WriteString(", ")
			}
			sb.WriteString(e)
			if ttlStr != "" {
				sb.WriteString(" timeout ")
				sb.WriteString(ttlStr)
			}
			first = false
		}
		sb.WriteString(" };")

		if err := b.nftExpr(sb.String()); err != nil {
			return fmt.Errorf("batch add to %s failed: %w", setName, err)
		}
	}
	return nil
}

// expr runner
func (b *Backend) nftExpr(expr string) error {
	if debugEnv {
		fmt.Fprintln(os.Stderr, "[nft expr]:", expr)
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(expr + "\n")
	out, err := cmd.CombinedOutput()
	if debugEnv {
		fmt.Fprintln(os.Stderr, "[nft] rc:", err)
		if len(out) > 0 {
			fmt.Fprintln(os.Stderr, "[nft] out:", string(out))
		}
	}
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(out))
	}
	return nil
}

// ---------- CIDR normalization (drop overlaps) ----------

// IPv4
type v4range struct {
	start uint32
	end   uint32
	cidr  string
}

func ip4ToU32(ip net.IP) uint32 {
	ip4 := ip.To4()
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func cidrRangeV4(c *net.IPNet) (uint32, uint32) {
	network := c.IP.Mask(c.Mask).To4()
	start := ip4ToU32(network)
	ones, bits := c.Mask.Size()
	// host count = 2^(bits-ones)
	host := uint32(1)<<(uint(bits-ones)) - 1
	end := start + host
	return start, end
}

func normalizeCIDRsV4(in []string) []string {
	// parse + canonicalize + dedup
	seen := make(map[string]struct{})
	var arr []v4range
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || strings.IndexByte(s, '/') == -1 {
			continue
		}
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		// canonical cidr string
		canon := ipnet.IP.Mask(ipnet.Mask).String() + "/" + strconv.Itoa(maskOnes(ipnet.Mask))
		if _, ok := seen[canon]; ok {
			continue
		}
		seen[canon] = struct{}{}
		st, en := cidrRangeV4(ipnet)
		arr = append(arr, v4range{start: st, end: en, cidr: canon})
	}

	if len(arr) == 0 {
		return nil
	}

	// sort: start asc, end desc (ώστε ο υπερ-χώρος πρώτος)
	sortFunc := func(i, j int) bool {
		if arr[i].start == arr[j].start {
			return arr[i].end > arr[j].end
		}
		return arr[i].start < arr[j].start
	}
	// local sort to avoid extra import
	for i := 1; i < len(arr); i++ {
		for j := i; j > 0 && sortFunc(j, j-1); j-- {
			arr[j], arr[j-1] = arr[j-1], arr[j]
		}
	}

	out := make([]string, 0, len(arr))
	var coverEnd uint32 = 0
	for _, r := range arr {
		if len(out) == 0 {
			out = append(out, r.cidr)
			coverEnd = r.end
			continue
		}
		// αν ο τρέχων αρχίζει μέσα σε ήδη καλυμμένο διάστημα και τελειώνει πριν/ίσο με coverEnd => contained → drop
		if r.start <= coverEnd && r.end <= coverEnd {
			continue
		}
		// εκτός κάλυψης → keep
		if r.start > coverEnd {
			out = append(out, r.cidr)
			coverEnd = r.end
			continue
		}
		// Θεωρητικά partial overlap δεν πρέπει να υπάρξει με CIDR, παρ' όλα αυτά:
		if r.end > coverEnd {
			// επεκτείνει την κάλυψη (σπάνιο για CIDR) – κρατάμε το νέο για ασφάλεια
			out = append(out, r.cidr)
			coverEnd = r.end
		}
	}
	return out
}

func maskOnes(m net.IPMask) int {
	ones, _ := m.Size()
	return ones
}

// IPv6
type v6range struct {
	start *big.Int
	end   *big.Int
	cidr  string
}

func ip6ToBig(ip net.IP) *big.Int {
	ip = ip.To16()
	return new(big.Int).SetBytes(ip)
}

func cidrRangeV6(n *net.IPNet) (*big.Int, *big.Int) {
	base := ip6ToBig(n.IP.Mask(n.Mask))
	ones, bits := n.Mask.Size()
	rem := uint(bits - ones)
	hostCount := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), rem), big.NewInt(1))
	end := new(big.Int).Add(base, hostCount)
	return base, end
}

func normalizeCIDRsV6(in []string) []string {
	seen := make(map[string]struct{})
	var arr []v6range
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || strings.IndexByte(s, '/') == -1 {
			continue
		}
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		ipnet.IP = ipnet.IP.Mask(ipnet.Mask)
		canon := ipnet.String()
		if _, ok := seen[canon]; ok {
			continue
		}
		seen[canon] = struct{}{}
		st, en := cidrRangeV6(ipnet)
		arr = append(arr, v6range{start: st, end: en, cidr: canon})
	}
	if len(arr) == 0 {
		return nil
	}

	// sort: start asc, end desc
	less := func(a, b v6range) bool {
		c := a.start.Cmp(b.start)
		if c == 0 {
			return a.end.Cmp(b.end) > 0
		}
		return c < 0
	}
	for i := 1; i < len(arr); i++ {
		for j := i; j > 0 && less(arr[j], arr[j-1]); j-- {
			arr[j], arr[j-1] = arr[j-1], arr[j]
		}
	}

	out := make([]string, 0, len(arr))
	coverEnd := new(big.Int).SetUint64(0)
	for _, r := range arr {
		if len(out) == 0 {
			out = append(out, r.cidr)
			coverEnd = new(big.Int).Set(r.end)
			continue
		}
		if r.start.Cmp(coverEnd) <= 0 && r.end.Cmp(coverEnd) <= 0 {
			// contained
			continue
		}
		if r.start.Cmp(coverEnd) == 1 {
			// disjoint → keep
			out = append(out, r.cidr)
			coverEnd = new(big.Int).Set(r.end)
			continue
		}
		// unexpected partial: keep and extend cover
		if r.end.Cmp(coverEnd) == 1 {
			out = append(out, r.cidr)
			coverEnd = new(big.Int).Set(r.end)
		}
	}
	return out
}



// Sanitizer για feed names: lower, [a-z0-9_], κόψιμο μήκους, prefix αν αρχίζει με digit
func SanitizeFeedName(s string) string {
    s = strings.ToLower(s)
    b := make([]rune, 0, len(s))
    for _, r := range s {
        if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
            b = append(b, r)
        } else {
            b = append(b, '_')
        }
    }
    out := strings.Trim(bulkUnderscores(string(b)), "_")
    if out == "" { out = "feed" }
    if out[0] >= '0' && out[0] <= '9' {
        out = "f_" + out
    }
    if len(out) > 40 { // αυθαίρετο όριο για καθαρότητα ονόματος
        out = out[:40]
    }
    return out
}
func bulkUnderscores(s string) string {
    for strings.Contains(s, "__") {
        s = strings.ReplaceAll(s, "__", "_")
    }
    return s
}

// Δημιουργεί δυναμικό set με flags ανάλογα με hosts/nets και v4/v6
func (b *Backend) EnsureSetDynamic(name string, v6 bool, isNet bool) error {
    typ := "ipv4_addr"
    if v6 { typ = "ipv6_addr" }
    flags := "timeout"
    if isNet { flags = "timeout,interval" }
    return b.ensureSetWithFlags(name, typ, flags)
}



// --- WHICH IP support --------------------------------------------------------
// --- inside package nft (internal/firewall/nft/nft.go) ---

type setMeta struct {
	Name string
	Type string // ipv4_addr | ipv6_addr
	Flags []string // e.g. ["timeout","interval"]
}


// DropFeedSets διαγράφει όλα τα per-feed sets (hosts/nets, v4/v6, allow/block)
func (b *Backend) DropFeedSets(feedName string) {
    suff := SanitizeFeedName(feedName)
    sets := []string{
        "allow_ext_v4_hosts_" + suff,
        "allow_ext_v4_nets_"  + suff,
        "allow_ext_v6_hosts_" + suff,
        "allow_ext_v6_nets_"  + suff,
        "block_ext_v4_hosts_" + suff,
        "block_ext_v4_nets_"  + suff,
        "block_ext_v6_hosts_" + suff,
        "block_ext_v6_nets_"  + suff,
    }
    for _, s := range sets {
        // αγνόησε σφάλματα αν δεν υπάρχουν ή είναι δεσμευμένα
        _ = exec.Command("nft", "flush", "set", "inet", tableName, s).Run()
        _ = exec.Command("nft", "delete", "set", "inet", tableName, s).Run()
    }
}





// DropEverything: delete whole table inet cfm
func (b *Backend) DropEverything() error {
	if !b.tableExists() {
		return nil
	}
	// best-effort flush first (μην αποτύχει delete λόγω refs)
	_ = exec.Command("nft", "flush", "table", family, tableName).Run()
	return b.nftCmd(fmt.Sprintf("delete table %s %s", family, tableName))
}

// ResetTable: flush whole table (rules + sets content), κρατώντας το table
func (b *Backend) ResetTable() error {
	if !b.tableExists() {
		return nil
	}
	return b.nftCmd(fmt.Sprintf("flush table %s %s", family, tableName))
}



//
func (b *Backend) ResetCFMTable() error {
    // Σβήσε το table αν υπάρχει (αγνόησε error αν δεν υπάρχει)
    _ = b.nftCmd(fmt.Sprintf("delete table %s %s", family, tableName))
    // Ξαναφτιάξ’ το άδειο
    return b.nftCmd(fmt.Sprintf("add table %s %s", family, tableName))
}
