package notify

import (
	"bytes"
	"fmt"
	"text/template"
	"time"
)

var defaultSubject = `[CFM] {{.Host}} — {{.Kind}} {{.SrcIP}} ({{.ASN}}, {{.Country}}) reason={{.Reason}} ttl={{.TTL}}`

var defaultBody = `{{.When}} {{.TZ}}
Host: {{.Host}}
Kind: {{.Kind}}
IP: {{.SrcIP}}
ASN: {{.ASN}}
Country: {{.Country}}
PTR: {{.PTR}}
Reason: {{.Reason}}
TTL: {{.TTL}}
Count: {{.Count}}
Section: {{.Section}}
{{- if .Samples}}

Sample lines:
{{- range .Samples}}
{{.}}
{{- end}}
{{- end}}
`

type tmplData struct{ Event; TZ string }

func render(tmplStr string, ev Event) (string, error) {
	if tmplStr == "" { tmplStr = defaultBody }
	tmpl, err := template.New("x").Parse(tmplStr)
	if err != nil { return "", err }
	_, offset := time.Now().Zone()
	tz := formatOffset(offset)
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, tmplData{Event: ev, TZ: tz})
	return buf.String(), err
}

func renderSubject(tmplStr string, ev Event) (string, error) {
	if tmplStr == "" { tmplStr = defaultSubject }
	return render(tmplStr, ev)
}

func formatOffset(sec int) string {
	sign := "+"; if sec < 0 { sign = "-"; sec = -sec }
	h := sec / 3600; m := (sec % 3600) / 60
	return fmt.Sprintf("%s%02d%02d", sign, h, m)
}
