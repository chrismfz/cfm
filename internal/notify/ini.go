package notify

import (
	"bufio"
	"os"
	"strings"
)

type iniFile struct {
	sections map[string]map[string]string
}

func parseINI(path string) (*iniFile, error) {
	f, err := os.Open(path)
	if err != nil { return nil, err }
	defer f.Close()

	ini := &iniFile{sections: map[string]map[string]string{}}
	cur := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") { continue }
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			cur = strings.TrimSpace(line[1:len(line)-1])
			if _, ok := ini.sections[cur]; !ok { ini.sections[cur] = map[string]string{} }
			continue
		}
		if i := strings.Index(line, "="); i > 0 {
			k := strings.TrimSpace(line[:i])
			v := expandEnvRef(strings.TrimSpace(line[i+1:]))
			if _, ok := ini.sections[cur]; !ok { ini.sections[cur] = map[string]string{} }
			ini.sections[cur][k] = v
		}
	}
	if err := sc.Err(); err != nil { return nil, err }
	return ini, nil
}

func expandEnvRef(s string) string {
	// supports ${ENV:VAR}
	for {
		start := strings.Index(s, "${ENV:")
		if start < 0 { break }
		end := strings.Index(s[start:], "}")
		if end < 0 { break }
		end = start + end
		key := s[start+6 : end]
		s = s[:start] + os.Getenv(strings.TrimSpace(key)) + s[end+1:]
	}
	return s
}

func (i *iniFile) getSection(name string) map[string]string { return i.sections[name] }

func (i *iniFile) sectionsWithPrefix(prefix string) map[string]map[string]string {
	out := map[string]map[string]string{}
	for k, v := range i.sections {
		if strings.HasPrefix(k, prefix) { out[k] = v }
	}
	return out
}
