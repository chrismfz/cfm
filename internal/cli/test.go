package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	cfgpkg "cfm/internal/config"
	"cfm/internal/detectors"
)

func RunTest() {
	fmt.Println("== cfm test ==")

	type check struct {
		name string
		fn   func() (string, bool)
	}

	checks := []check{
		{"nft (binary)", func() (string, bool) { return HasBinary("nft") }},
		{"iptables (binary)", func() (string, bool) { return HasBinary("iptables") }},
		{"ip6tables (binary)", func() (string, bool) { return HasBinary("ip6tables") }},
		{"ipset (binary)", func() (string, bool) { return HasBinary("ipset") }},
		{"kernel module: nf_tables", func() (string, bool) { return HasModule("nf_tables") }},
		{"kernel module: ip_tables", func() (string, bool) { return HasModule("ip_tables") }},
		{"kernel module: xt_owner", func() (string, bool) { return HasModule("xt_owner") }},
	}

	for _, c := range checks {
		msg, ok := c.fn()
		status := "OK"
		if !ok {
			status = "MISSING"
		}
		fmt.Printf(" - %-28s : %-7s %s\n", c.name, status, msg)
	}

	fmt.Printf("\nDetected backend preference: %s\n", detectBackend())
	runConfigDriftChecks()
}

func runConfigDriftChecks() {
	cfgDir, ok := ResolveConfigDir("")
	if !ok {
		fmt.Println("\n== config drift ==")
		fmt.Println(" - config directory not found (no /etc/cfm and no nearby ./configs)")
		return
	}

	fmt.Printf("\n== config drift (%s) ==\n", cfgDir)

	liveCFM := filepath.Join(cfgDir, "cfm.conf")
	if _, err := os.Stat(liveCFM); err != nil {
		fmt.Printf(" - cfm.conf             : SKIP   live file not found (%s)\n", liveCFM)
	} else {
		refCFM, hasRef := findRefFile(cfgDir, "cfm.conf")
		if hasRef {
			missing, extra, err := diffFlatConfigKeys(liveCFM, refCFM)
			if err != nil {
				fmt.Printf(" - cfm.conf             : ERROR  %v\n", err)
			} else {
				printDiff("cfm.conf", refCFM, missing, extra)
			}
		} else {
			fmt.Printf(" - cfm.conf             : SKIP   reference file not found (checked defaults)\n")
		}
		report, err := auditCFMConfig(liveCFM)
		if err != nil {
			fmt.Printf(" - cfm.conf/audit       : ERROR  %v\n", err)
		} else {
			printAudit("cfm.conf/audit", report)
		}
	}

	liveDet := filepath.Join(cfgDir, "detectors.conf")
	if _, err := os.Stat(liveDet); err != nil {
		fmt.Printf(" - detectors.conf       : SKIP   live file not found (%s)\n", liveDet)
		return
	}
	refDet, hasRefDet := findRefFile(cfgDir, "detectors.conf")
	if hasRefDet {
		missingGlobal, extraGlobal, err := diffDetectorsGlobalKeys(liveDet, refDet)
		if err != nil {
			fmt.Printf(" - detectors.conf/global: ERROR  %v\n", err)
		} else {
			printDiff("detectors.conf/global", refDet, missingGlobal, extraGlobal)
		}
	} else {
		fmt.Printf(" - detectors.conf/global: SKIP   reference file not found (checked defaults)\n")
	}

	missingTypes, extraTypes, err := diffDetectorTypes(liveDet)
	if err != nil {
		fmt.Printf(" - detectors.conf/types : ERROR  %v\n", err)
		return
	}
	if len(missingTypes) == 0 && len(extraTypes) == 0 {
		fmt.Printf(" - detectors.conf/types : OK     live section types match registered detectors\n")
		return
	}
	fmt.Printf(" - detectors.conf/types : DRIFT\n")
	if len(missingTypes) > 0 {
		fmt.Printf("   missing section types: %s\n", strings.Join(missingTypes, ", "))
	}
	if len(extraTypes) > 0 {
		fmt.Printf("   unknown section types: %s\n", strings.Join(extraTypes, ", "))
	}
}

type auditReport struct {
	UnknownKeys []string
	BogusLines  []string
}

func printAudit(name string, a auditReport) {
	if len(a.UnknownKeys) == 0 && len(a.BogusLines) == 0 {
		fmt.Printf(" - %-20s : OK     no unknown keys or malformed lines\n", name)
		return
	}
	fmt.Printf(" - %-20s : DRIFT\n", name)
	if len(a.UnknownKeys) > 0 {
		fmt.Printf("   unknown/deprecated keys: %s\n", strings.Join(a.UnknownKeys, ", "))
	}
	if len(a.BogusLines) > 0 {
		fmt.Printf("   malformed lines       : %s\n", strings.Join(a.BogusLines, "; "))
	}
}

func auditCFMConfig(path string) (auditReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return auditReport{}, err
	}
	defer f.Close()

	unknown := map[string]struct{}{}
	var bogus []string
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		i := strings.Index(line, "=")
		if i <= 0 {
			bogus = append(bogus, fmt.Sprintf("line %d: %s", lineNo, strings.TrimSpace(raw)))
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(line[:i]))
		if !isSimpleKey(key) {
			bogus = append(bogus, fmt.Sprintf("line %d: %s", lineNo, strings.TrimSpace(raw)))
			continue
		}
		if !cfgpkg.IsKnownKey(key) {
			unknown[key] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		return auditReport{}, err
	}
	unknownList := make([]string, 0, len(unknown))
	for k := range unknown {
		unknownList = append(unknownList, k)
	}
	sort.Strings(unknownList)
	return auditReport{UnknownKeys: unknownList, BogusLines: bogus}, nil
}

func printDiff(name, ref string, missing, extra []string) {
	if len(missing) == 0 && len(extra) == 0 {
		fmt.Printf(" - %-20s : OK     matches reference keys (%s)\n", name, ref)
		return
	}
	fmt.Printf(" - %-20s : DRIFT  compare=%s\n", name, ref)
	if len(missing) > 0 {
		fmt.Printf("   missing keys: %s\n", strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		fmt.Printf("   extra keys  : %s\n", strings.Join(extra, ", "))
	}
}

func findRefFile(cfgDir, name string) (string, bool) {
	candidates := []string{
		filepath.Join(cfgDir, name+".example"),
		filepath.Join(cfgDir, "default", name),
		filepath.Join("/usr/share/cfm", name),
		filepath.Join("configs", name),
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, true
		}
	}
	return "", false
}

func diffFlatConfigKeys(livePath, refPath string) (missing, extra []string, err error) {
	live, err := readFlatConfigKeys(livePath)
	if err != nil {
		return nil, nil, err
	}
	ref, err := readFlatConfigKeys(refPath)
	if err != nil {
		return nil, nil, err
	}
	return setDiff(ref, live), setDiff(live, ref), nil
}

func readFlatConfigKeys(path string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	keys := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		if i := strings.Index(line, "="); i > 0 {
			k := strings.ToUpper(strings.TrimSpace(line[:i]))
			if isSimpleKey(k) {
				keys[k] = struct{}{}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

func isSimpleKey(k string) bool {
	if k == "" {
		return false
	}
	for _, r := range k {
		if !((r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}

func diffDetectorsGlobalKeys(livePath, refPath string) (missing, extra []string, err error) {
	liveSecs, err := detectors.ReadSectionsFile(livePath)
	if err != nil {
		return nil, nil, err
	}
	refSecs, err := detectors.ReadSectionsFile(refPath)
	if err != nil {
		return nil, nil, err
	}
	liveGlobal := map[string]struct{}{}
	for k := range liveSecs.Global {
		liveGlobal[k] = struct{}{}
	}
	refGlobal := map[string]struct{}{}
	for k := range refSecs.Global {
		refGlobal[k] = struct{}{}
	}
	return setDiff(refGlobal, liveGlobal), setDiff(liveGlobal, refGlobal), nil
}

func diffDetectorTypes(livePath string) (missing []string, extra []string, err error) {
	liveSecs, err := detectors.ReadSectionsFile(livePath)
	if err != nil {
		return nil, nil, err
	}
	liveTypes := map[string]struct{}{}
	for sec := range liveSecs.ByName {
		if sec == "global" {
			continue
		}
		typ, _ := detectors.SplitTypeInstance(sec)
		if canonical, ok := detectors.CanonicalType(typ); ok {
			if detectors.ConfigSectionOptional(canonical) {
				continue
			}
			liveTypes[canonical] = struct{}{}
		} else if typ != "" {
			liveTypes[typ] = struct{}{}
		}
	}
	regTypes := map[string]struct{}{}
	for _, typ := range detectors.RegisteredTypes() {
		if detectors.ConfigSectionOptional(typ) {
			continue
		}
		regTypes[typ] = struct{}{}
	}
	return setDiff(regTypes, liveTypes), setDiff(liveTypes, regTypes), nil
}

func setDiff(a, b map[string]struct{}) []string {
	out := make([]string, 0)
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func detectBackend() string {
	if _, ok := LookPath("nft"); ok {
		return "nftables"
	}
	if _, ok := LookPath("iptables"); ok {
		return "iptables"
	}
	return "none"
}
