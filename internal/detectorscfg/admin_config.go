package detectorscfg

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

type AdminSection struct {
	Name     string            `json:"name"`
	Kind     string            `json:"kind"`
	Enabled  bool              `json:"enabled"`
	Keys     map[string]string `json:"keys"`
	RawLines []string          `json:"raw_lines,omitempty"`
}

type AdminConfig struct {
	Global   map[string]string `json:"global"`
	Core     []AdminSection    `json:"core"`
	Leniency []AdminSection    `json:"leniency"`
	Advanced []AdminSection    `json:"advanced"`
	Examples []AdminExample    `json:"examples,omitempty"`
}

type AdminExample struct {
	ID            string            `json:"id"`
	Title         string            `json:"title"`
	Section       string            `json:"section"`
	Kind          string            `json:"kind"`
	Preview       string            `json:"preview"`
	Keys          map[string]string `json:"keys"`
	CommentSource string            `json:"comment_source,omitempty"`
}

type sectionDoc struct {
	Name    string
	Entries []sectionEntry
}

type sectionEntryKind string

const (
	sectionEntryBlank   sectionEntryKind = "blank"
	sectionEntryComment sectionEntryKind = "comment"
	sectionEntryKey     sectionEntryKind = "key"
	sectionEntryOther   sectionEntryKind = "other"
)

type sectionEntry struct {
	Kind         sectionEntryKind
	Raw          string
	Key          string
	Value        string
	InlineSuffix string
}

type exampleDoc struct {
	ID      string
	Title   string
	Section string
	Keys    map[string]string
}

type doc struct {
	Preamble []string
	Order    []string
	Sections map[string]*sectionDoc
	Examples []exampleDoc
}

type AdminConfigBackup struct {
	ID      string    `json:"id"`
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	Created time.Time `json:"created"`
}

func resolveDetectorsConfigPath(cfgDir string) (string, bool) {
	if fileExists("/etc/cfm/detectors.conf") {
		return "/etc/cfm/detectors.conf", true
	}
	if cfgDir != "" {
		p := filepath.Join(cfgDir, "detectors.conf")
		_, err := os.Stat(p)
		return p, err == nil
	}
	return "/etc/cfm/detectors.conf", false
}

func LoadAdminConfig(cfgDir string) (AdminConfig, string, error) {
	path, exists := resolveDetectorsConfigPath(cfgDir)
	if !exists {
		return AdminConfig{Global: map[string]string{}}, path, nil
	}
	d, err := parseDoc(path)
	if err != nil {
		return AdminConfig{}, path, err
	}
	return buildAdminConfig(d), path, nil
}

func RenderAdminConfig(cfgDir string, cfg AdminConfig) (string, error) {
	path, exists := resolveDetectorsConfigPath(cfgDir)
	var d *doc
	if exists {
		parsed, err := parseDoc(path)
		if err != nil {
			return "", err
		}
		d = parsed
	} else {
		d = &doc{Sections: map[string]*sectionDoc{}}
	}
	return renderFromDoc(d, cfg), nil
}

func SaveAdminConfigWithBackup(cfgDir string, cfg AdminConfig) (string, string, error) {
	path, _ := resolveDetectorsConfigPath(cfgDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return path, "", err
	}
	text, err := RenderAdminConfig(cfgDir, cfg)
	if err != nil {
		return path, "", err
	}
	backupPath, err := writeFileAtomic(path, []byte(text))
	if err != nil {
		return path, "", err
	}
	return path, backupIDFromPath(backupPath), nil
}

func ReloadNow() error { return nil }

func ListAdminConfigBackups(cfgDir string) ([]AdminConfigBackup, error) {
	path, _ := resolveDetectorsConfigPath(cfgDir)
	matches, err := filepath.Glob(path + ".bak-*")
	if err != nil {
		return nil, err
	}
	out := make([]AdminConfigBackup, 0, len(matches))
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			continue
		}
		id := backupIDFromPath(match)
		if id == "" {
			continue
		}
		out = append(out, AdminConfigBackup{ID: id, Path: match, Size: info.Size(), Created: info.ModTime().UTC()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

func ReadAdminConfigBackup(cfgDir, backupID string) (string, error) {
	bp, err := resolveBackupPath(cfgDir, backupID)
	if err != nil {
		return "", err
	}
	// #nosec G304 -- backup path is constrained by resolveBackupPath + validateBackupID.
	b, err := os.ReadFile(bp)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func RestoreAdminConfigBackup(cfgDir, backupID string) (string, string, error) {
	path, _ := resolveDetectorsConfigPath(cfgDir)
	safeBackupID, err := validateBackupID(backupID)
	if err != nil {
		return path, "", err
	}
	bp, err := resolveBackupPath(cfgDir, safeBackupID)
	if err != nil {
		return path, "", err
	}
	// #nosec G304 -- backup path is constrained by resolveBackupPath + validateBackupID.
	content, err := os.ReadFile(bp)
	if err != nil {
		return path, "", err
	}
	restoreID := safeBackupID + "-restore-" + time.Now().UTC().Format("20060102150405")
	if fileExists(path) {
		if err := copyFileSafe(path, path+".bak-"+restoreID); err != nil {
			return path, "", err
		}
	}
	if _, err := writeFileAtomic(path, content); err != nil {
		return path, "", err
	}
	return path, restoreID, nil
}

func resolveBackupPath(cfgDir, backupID string) (string, error) {
	path, _ := resolveDetectorsConfigPath(cfgDir)
	id, err := validateBackupID(backupID)
	if err != nil {
		return "", err
	}
	bp := path + ".bak-" + id
	if !fileExists(bp) {
		return "", fmt.Errorf("backup not found")
	}
	return bp, nil
}

func parseDoc(path string) (*doc, error) {
	// #nosec G304 -- path is resolved from the configured detectors.conf location.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	d := &doc{Sections: map[string]*sectionDoc{}}
	cur := ""
	var currentExample *exampleDoc
	flushExample := func() {
		if currentExample == nil {
			return
		}
		if currentExample.ID == "" || len(currentExample.Keys) == 0 {
			currentExample = nil
			return
		}
		d.Examples = append(d.Examples, *currentExample)
		currentExample = nil
	}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		raw := sc.Text()
		trim := strings.TrimSpace(raw)
		if strings.HasPrefix(trim, "[") && strings.Contains(trim, "]") {
			flushExample()
			idx := strings.Index(trim, "]")
			cur = strings.TrimSpace(trim[1:idx])
			if d.Sections[cur] == nil {
				d.Sections[cur] = &sectionDoc{Name: cur}
				d.Order = append(d.Order, cur)
			}
			continue
		}
		if attrs, ok := parseExampleTag(trim); ok {
			flushExample()
			currentExample = &exampleDoc{
				ID:      attrs["id"],
				Title:   attrs["title"],
				Section: attrs["section"],
				Keys:    map[string]string{},
			}
			continue
		}
		if currentExample != nil {
			candidate, ok := parseCommentKeyValue(trim)
			if ok {
				currentExample.Keys[candidate[0]] = candidate[1]
				continue
			}
			if trim == "" || strings.HasPrefix(trim, ";") || strings.HasPrefix(trim, "#") {
				continue
			}
			flushExample()
		}
		if cur == "" {
			d.Preamble = append(d.Preamble, raw)
			continue
		}
		d.Sections[cur].Entries = append(d.Sections[cur].Entries, parseSectionEntry(raw))
	}
	flushExample()
	return d, sc.Err()
}

func buildAdminConfig(d *doc) AdminConfig {
	cfg := AdminConfig{Global: map[string]string{}, Core: []AdminSection{}, Leniency: []AdminSection{}, Advanced: []AdminSection{}, Examples: []AdminExample{}}
	for _, name := range d.Order {
		sec := d.Sections[name]
		keys := parseSectionKeys(sec.Entries)
		if name == "global" {
			cfg.Global = keys
			continue
		}
		rawLines := make([]string, 0, len(sec.Entries))
		for _, entry := range sec.Entries {
			rawLines = append(rawLines, entry.Raw)
		}
		as := AdminSection{Name: name, Enabled: parseEnabled(keys), Keys: keys, RawLines: rawLines}
		switch {
		case strings.HasSuffix(name, ".leniency"):
			as.Kind = "leniency"
			cfg.Leniency = append(cfg.Leniency, as)
		case name == "webdetector":
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
	for _, ex := range d.Examples {
		title := strings.TrimSpace(ex.Title)
		if title == "" {
			title = ex.ID
		}
		preview := buildExamplePreview(ex.Keys)
		cfg.Examples = append(cfg.Examples, AdminExample{
			ID:            ex.ID,
			Title:         title,
			Section:       ex.Section,
			Kind:          classifySectionKind(ex.Section),
			Preview:       preview,
			Keys:          cloneStringMap(ex.Keys),
			CommentSource: "detectors.conf comments",
		})
	}
	sort.Slice(cfg.Examples, func(i, j int) bool { return cfg.Examples[i].ID < cfg.Examples[j].ID })
	return cfg
}

func classifySectionKind(section string) string {
	s := strings.TrimSpace(strings.ToLower(section))
	switch {
	case strings.HasSuffix(s, ".leniency"):
		return "leniency"
	case s == "" || s == "global":
		return "global"
	case s == "webdetector":
		return "advanced"
	default:
		return "core"
	}
}

func buildExamplePreview(keys map[string]string) string {
	if len(keys) == 0 {
		return ""
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	parts := make([]string, 0, 3)
	for _, k := range ordered {
		v := strings.TrimSpace(keys[k])
		if v == "" {
			continue
		}
		parts = append(parts, k+"="+v)
		if len(parts) == 3 {
			break
		}
	}
	return strings.Join(parts, ", ")
}

func cloneStringMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func parseExampleTag(trim string) (map[string]string, bool) {
	if !(strings.HasPrefix(trim, ";@example") || strings.HasPrefix(trim, "#@example")) {
		return nil, false
	}
	body := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(trim, ";@example"), "#@example"))
	attrs := parseTagAttrs(body)
	if strings.TrimSpace(attrs["id"]) == "" {
		return nil, false
	}
	return attrs, true
}

func parseTagAttrs(body string) map[string]string {
	out := map[string]string{}
	i := 0
	for i < len(body) {
		for i < len(body) && body[i] == ' ' {
			i++
		}
		if i >= len(body) {
			break
		}
		start := i
		for i < len(body) && body[i] != '=' && body[i] != ' ' {
			i++
		}
		key := strings.TrimSpace(body[start:i])
		if key == "" || i >= len(body) || body[i] != '=' {
			for i < len(body) && body[i] != ' ' {
				i++
			}
			continue
		}
		i++
		if i >= len(body) {
			out[strings.ToLower(key)] = ""
			break
		}
		if body[i] == '"' {
			i++
			valueStart := i
			for i < len(body) && body[i] != '"' {
				i++
			}
			out[strings.ToLower(key)] = body[valueStart:i]
			if i < len(body) && body[i] == '"' {
				i++
			}
			continue
		}
		valueStart := i
		for i < len(body) && body[i] != ' ' {
			i++
		}
		out[strings.ToLower(key)] = body[valueStart:i]
	}
	return out
}

func parseCommentKeyValue(trim string) ([2]string, bool) {
	var empty [2]string
	if !(strings.HasPrefix(trim, ";") || strings.HasPrefix(trim, "#")) {
		return empty, false
	}
	line := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(trim, ";"), "#"))
	if line == "" || strings.HasPrefix(line, "@") {
		return empty, false
	}
	idx := strings.Index(line, "=")
	if idx <= 0 {
		return empty, false
	}
	key := strings.TrimSpace(line[:idx])
	if !isConfigKey(key) {
		return empty, false
	}
	val := strings.TrimSpace(line[idx+1:])
	return [2]string{strings.ToUpper(key), strings.Trim(val, `"`)}, true
}

func parseEnabled(keys map[string]string) bool {
	v := strings.ToLower(strings.TrimSpace(keys["ENABLED"]))
	return !(v == "0" || v == "no" || v == "false" || v == "off")
}

func parseSectionKeys(entries []sectionEntry) map[string]string {
	out := map[string]string{}
	var last string
	for _, entry := range entries {
		line := strings.TrimSpace(entry.Raw)
		if entry.Kind == sectionEntryBlank || entry.Kind == sectionEntryComment {
			continue
		}
		if entry.Kind == sectionEntryKey {
			last = entry.Key
			out[last] = entry.Value
			continue
		}
		if last != "" {
			out[last] = out[last] + "\n" + line
		}
	}
	return out
}

func renderFromDoc(d *doc, cfg AdminConfig) string {
	if d.Sections == nil {
		d.Sections = map[string]*sectionDoc{}
	}
	byName := map[string]AdminSection{}
	for _, sec := range cfg.Core {
		sec.Kind = "core"
		byName[sec.Name] = sec
	}
	for _, sec := range cfg.Leniency {
		sec.Kind = "leniency"
		byName[sec.Name] = sec
	}
	for _, sec := range cfg.Advanced {
		sec.Kind = "advanced"
		byName[sec.Name] = sec
	}
	if _, ok := byName["global"]; !ok {
		byName["global"] = AdminSection{Name: "global", Kind: "global", Keys: cfg.Global}
	}
	var b strings.Builder
	for _, l := range d.Preamble {
		b.WriteString(l + "\n")
	}
	if len(d.Preamble) > 0 && strings.TrimSpace(d.Preamble[len(d.Preamble)-1]) != "" {
		b.WriteString("\n")
	}
	rendered := map[string]bool{}
	for _, name := range d.Order {
		if name == "global" {
			renderSection(&b, "global", cfg.Global, d.Sections[name])
			rendered[name] = true
			continue
		}
		if sec, ok := byName[name]; ok {
			renderSection(&b, name, sec.Keys, d.Sections[name])
			rendered[name] = true
		} else if src := d.Sections[name]; src != nil {
			b.WriteString("[" + name + "]\n")
			for _, entry := range src.Entries {
				b.WriteString(entry.Raw + "\n")
			}
			b.WriteString("\n")
		}
	}
	for name, sec := range byName {
		if rendered[name] {
			continue
		}
		renderSection(&b, name, sec.Keys, nil)
	}
	return strings.TrimSpace(b.String()) + "\n"
}

func renderSection(b *strings.Builder, name string, keys map[string]string, src *sectionDoc) {
	b.WriteString("[" + name + "]\n")
	rendered := map[string]bool{}
	lastBlank := false
	if src != nil && len(src.Entries) > 0 {
		for _, entry := range src.Entries {
			switch entry.Kind {
			case sectionEntryKey:
				v, ok := keys[entry.Key]
				if !ok {
					continue
				}
				if strings.TrimSpace(v) == entry.Value && !strings.Contains(v, "\n") {
					b.WriteString(entry.Raw + "\n")
					lastBlank = strings.TrimSpace(entry.Raw) == ""
				} else {
					lastBlank = renderKeyValue(b, entry.Key, v)
				}
				rendered[entry.Key] = true
			default:
				b.WriteString(entry.Raw + "\n")
				lastBlank = strings.TrimSpace(entry.Raw) == ""
			}
		}
	}
	ord := make([]string, 0, len(keys))
	for k := range keys {
		if rendered[k] {
			continue
		}
		ord = append(ord, k)
	}
	sort.Strings(ord)
	for _, k := range ord {
		lastBlank = renderKeyValue(b, k, keys[k])
	}
	if !lastBlank {
		b.WriteString("\n")
	}
}

func renderKeyValue(b *strings.Builder, key, value string) bool {
	v := strings.TrimSpace(value)
	if strings.Contains(v, "\n") {
		b.WriteString(key + " =\n")
		for _, ln := range strings.Split(v, "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			b.WriteString("  " + ln + "\n")
		}
		return false
	}
	b.WriteString(key + " = " + v + "\n")
	return false
}

func parseSectionEntry(raw string) sectionEntry {
	trim := strings.TrimSpace(raw)
	if trim == "" {
		return sectionEntry{Kind: sectionEntryBlank, Raw: raw}
	}
	if strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
		return sectionEntry{Kind: sectionEntryComment, Raw: raw}
	}
	i := strings.Index(trim, "=")
	if i <= 0 {
		return sectionEntry{Kind: sectionEntryOther, Raw: raw}
	}
	key := strings.TrimSpace(trim[:i])
	if !isConfigKey(key) {
		return sectionEntry{Kind: sectionEntryOther, Raw: raw}
	}
	valuePart := strings.TrimSpace(trim[i+1:])
	return sectionEntry{
		Kind:  sectionEntryKey,
		Raw:   raw,
		Key:   strings.ToUpper(key),
		Value: parseConfigValue(valuePart),
	}
}

func parseConfigValue(raw string) string {
	s := strings.TrimSpace(raw)
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuote = !inQuote
		case '#', ';':
			if !inQuote && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
				s = strings.TrimSpace(s[:i])
				return strings.Trim(s, `"`)
			}
		}
	}
	return strings.Trim(s, `"`)
}

func isConfigKey(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

func writeFileAtomic(path string, payload []byte) (string, error) {
	// #nosec G304 -- lock file path is derived from the validated detectors.conf target path.
	lf, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return "", err
	}
	defer lf.Close()
	fd, err := fileFD(lf)
	if err != nil {
		return "", err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return "", err
	}
	defer syscall.Flock(fd, syscall.LOCK_UN) //nolint:errcheck
	backupPath := ""
	if fileExists(path) {
		backupPath = fmt.Sprintf("%s.bak-%s", path, time.Now().UTC().Format("20060102150405.000000000"))
		if err := copyFileSafe(path, backupPath); err != nil {
			return "", err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", err
	}
	return backupPath, nil
}

func backupIDFromPath(path string) string {
	if path == "" {
		return ""
	}
	idx := strings.Index(filepath.Base(path), ".bak-")
	if idx < 0 {
		return ""
	}
	return filepath.Base(path)[idx+5:]
}

func validateBackupID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", fmt.Errorf("backup id is required")
	}
	if strings.Contains(id, "/") || strings.Contains(id, "\\") || strings.Contains(id, "..") {
		return "", fmt.Errorf("invalid backup id")
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return "", fmt.Errorf("invalid backup id")
	}
	return id, nil
}

func fileFD(f *os.File) (int, error) {
	fd := f.Fd()
	if fd > math.MaxInt {
		return 0, fmt.Errorf("file descriptor overflow")
	}
	return int(fd), nil
}

func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }

func copyFileSafe(src, dst string) error {
	// #nosec G304 -- source path is derived from current/backup config paths.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	// #nosec G304 -- destination path is derived from current/backup config paths.
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := out.ReadFrom(in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
