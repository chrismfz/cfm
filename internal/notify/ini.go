package notify

import (
	"bufio"
	"os"
	"strings"
	"unicode"
)

type iniFile struct {
	sections map[string]map[string]string
}



// stripInlineComments removes unquoted ';' or '#' and trims spaces.
func stripInlineComments(s string) string {
	in := []rune(s)
	var out []rune
	quote := rune(0)
	for i, r := range in {
		if quote == 0 && (r == '"' || r == '\'') {
			quote = r
			out = append(out, r)
			continue
		}
		if quote != 0 {
			out = append(out, r)
			if r == quote { quote = 0 }
			continue
		}
		if r == ';' || r == '#' {
			// treat as comment if start-of-line or preceded by whitespace
			if i == 0 || unicode.IsSpace(in[i-1]) {
				break
			}
		}
		out = append(out, r)
	}
	return strings.TrimSpace(string(out))
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
                // Section header: allow trailing comments after ']'
                if strings.HasPrefix(line, "[") {
                        if idx := strings.IndexRune(line, ']'); idx > 1 {
                                cur = strings.TrimSpace(line[1:idx])
                                if _, ok := ini.sections[cur]; !ok { ini.sections[cur] = map[string]string{} }
                                continue
                        }
                }


		if i := strings.Index(line, "="); i > 0 {

                        k := strings.ToLower(strings.TrimSpace(line[:i]))
                        v := strings.TrimSpace(line[i+1:])
                        // strip inline comments (outside quotes)
                        v = stripInlineComments(v)
                        // env expansion like ${ENV:VAR}
                        v = expandEnvRef(v)
                        // trim surrounding quotes, if any
                        if len(v) >= 2 {
                                if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
                                        v = v[1:len(v)-1]
                                }
                        }
                        if _, ok := ini.sections[cur]; !ok { ini.sections[cur] = map[string]string{} }
                        ini.sections[cur][k] = strings.TrimSpace(v)
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
