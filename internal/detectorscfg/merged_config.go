package detectorscfg

// merged_config.go — the EFFECTIVE detectors.conf view: the base conffile with
// every /etc/cfm/detectors.d/*.conf overlay merged over it, exactly as the
// detector manager runs it (detconf.ReadLayered — the same layered reader).
//
// LoadAdminConfig (admin_config.go) returns the BASE file the editor edits;
// this returns what actually applies AND the per-key overrides the overlays
// introduced, so "which value wins, and which file set it?" is answerable in one
// read. Values come from detconf (the authoritative "what runs" parser); a merge
// has no single line fidelity, so there are no raw_lines/examples here.

import (
	"path/filepath"
	"sort"

	"cfm/internal/detconf"
)

// Override is one effective key an overlay changed from — or added on top of —
// the base detectors.conf: the "what did my detectors.d/ overlays actually do?"
// delta of the merged view.
type Override struct {
	Section   string `json:"section"`
	Key       string `json:"key"`
	InBase    bool   `json:"in_base"`          // was the key present in the base file?
	Base      string `json:"base,omitempty"`   // base value (omitted/empty when overlay-only or empty)
	Effective string `json:"effective"`        // value the daemon runs
	Source    string `json:"source"`           // overlay filename that won the key
	Append    bool   `json:"append,omitempty"` // winning overlay used "+=" (value is cumulative)
}

// MergedAdminConfig is the effective merged view plus its overlay provenance.
type MergedAdminConfig struct {
	Config       AdminConfig `json:"config"`
	Path         string      `json:"path"`
	Exists       bool        `json:"exists"`
	OverlayFiles []string    `json:"overlay_files"`
	Overrides    []Override  `json:"overrides"`
}

// overrideSrc records which overlay last assigned a key and how.
type overrideSrc struct {
	file   string
	append bool
}

// LoadMergedAdminConfig builds the effective merged view for cfgDir. With no
// overlay directory (or an empty one) the merged config equals the base and
// Overrides is empty — identical values to LoadAdminConfig's keys.
func LoadMergedAdminConfig(cfgDir string) (MergedAdminConfig, error) {
	path, exists := resolveDetectorsConfigPath(cfgDir)
	out := MergedAdminConfig{
		Path:         path,
		Exists:       exists,
		Config:       emptyAdminConfig(),
		OverlayFiles: []string{},
		Overrides:    []Override{},
	}
	if !exists {
		return out, nil
	}
	dropinDir := detconf.DefaultDropinDir(path)
	overlayNames, err := detconf.ListDropins(dropinDir)
	if err != nil {
		return out, err
	}
	baseSec, err := detconf.ReadSectionsFile(path)
	if err != nil {
		return out, err
	}
	merged, _, err := detconf.ReadLayered(path, dropinDir)
	if err != nil {
		return out, err
	}
	out.Config = buildAdminConfigFromSections(merged)
	out.OverlayFiles = append(out.OverlayFiles, overlayNames...)

	// Winning source per (section,key): overlays merge in lexicographic order,
	// later replaces earlier, so the LAST overlay that assigns a key wins it.
	winner := map[string]map[string]overrideSrc{}
	for _, name := range overlayNames {
		layer, err := detconf.ReadSectionsFile(filepath.Join(dropinDir, name))
		if err != nil {
			return out, err
		}
		for section, kv := range layer.ByName {
			for k := range kv {
				if winner[section] == nil {
					winner[section] = map[string]overrideSrc{}
				}
				winner[section][k] = overrideSrc{file: name, append: layer.AppendKeys[section][k]}
			}
		}
	}
	out.Overrides = computeOverrides(baseSec, merged, winner)
	return out, nil
}

// computeOverrides diffs the merged view against the base file: every effective
// key whose value differs from base, or that base did not have, attributed to
// the overlay that set it. Both sides are parsed by detconf, so the comparison
// is apples-to-apples.
func computeOverrides(base, merged detconf.Sections, winner map[string]map[string]overrideSrc) []Override {
	res := []Override{}
	for _, section := range sortedSectionNames(merged.ByName) {
		mkv := merged.ByName[section]
		bkv := base.ByName[section] // nil when the section is overlay-only
		for _, k := range sortedMapKeys(mkv) {
			eff := mkv[k]
			bval, inBase := "", false
			if bkv != nil {
				bval, inBase = bkv[k]
			}
			if inBase && bval == eff {
				continue // overlay left this key's effective value unchanged
			}
			src := winner[section][k]
			res = append(res, Override{
				Section:   section,
				Key:       k,
				InBase:    inBase,
				Base:      bval,
				Effective: eff,
				Source:    src.file,
				Append:    src.append,
			})
		}
	}
	return res
}

// buildAdminConfigFromSections shapes a detconf merged Sections into the same
// AdminConfig buckets LoadAdminConfig produces (kind classification + enabled),
// minus raw_lines/examples. Reuses classifySectionKind/parseEnabled so the
// bucketing never drifts from the base loader.
func buildAdminConfigFromSections(s detconf.Sections) AdminConfig {
	cfg := emptyAdminConfig()
	for _, name := range sortedSectionNames(s.ByName) {
		kv := s.ByName[name]
		if name == "global" {
			cfg.Global = cloneStringMap(kv)
			continue
		}
		as := AdminSection{Name: name, Enabled: parseEnabled(kv), Keys: cloneStringMap(kv)}
		switch classifySectionKind(name) {
		case "leniency":
			as.Kind = "leniency"
			cfg.Leniency = append(cfg.Leniency, as)
		case "advanced":
			as.Kind = "advanced"
			cfg.Advanced = append(cfg.Advanced, as)
		default:
			as.Kind = "core"
			cfg.Core = append(cfg.Core, as)
		}
	}
	sort.Slice(cfg.Core, func(i, j int) bool { return cfg.Core[i].Name < cfg.Core[j].Name })
	sort.Slice(cfg.Leniency, func(i, j int) bool { return cfg.Leniency[i].Name < cfg.Leniency[j].Name })
	sort.Slice(cfg.Advanced, func(i, j int) bool { return cfg.Advanced[i].Name < cfg.Advanced[j].Name })
	return cfg
}

func emptyAdminConfig() AdminConfig {
	return AdminConfig{
		Global:   map[string]string{},
		Core:     []AdminSection{},
		Leniency: []AdminSection{},
		Advanced: []AdminSection{},
	}
}

func sortedSectionNames(m map[string]detconf.KV) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
