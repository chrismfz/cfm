package dnat

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sort"
	"strings"
	"time"
)

var panelMap = map[int]int{2082: 12082, 2083: 12083, 2086: 12086, 2087: 12087, 2095: 12095, 2096: 12096, 2222: 12222}
var panelTargetPorts = []int{12082, 12083, 12086, 12087, 12095, 12096, 12222}

type panelOpts struct{ mode string; priority int; challenge string }

func runOut(name string, args ...string) string { c:=exec.Command(name,args...); var b bytes.Buffer; c.Stdout=&b; c.Stderr=&b; _=c.Run(); return b.String() }

func panelStatus() (bool,string,error) {
	out:=runOut("nft","list","table","inet","cfm_panel_redirect")
	if strings.Contains(out,"No such file") || strings.Contains(out,"does not exist") { return false,"",nil }
	if strings.TrimSpace(out)=="" { return false,"",nil }
	return true,out,nil
}

func panelScript(priority int) string {
	ports:=[]int{2082,2083,2086,2087,2095,2096,2222}
	var b strings.Builder
	fmt.Fprintf(&b,"add table inet cfm_panel_redirect\n")
	fmt.Fprintf(&b,"add chain inet cfm_panel_redirect prerouting { type nat hook prerouting priority %d; policy accept; }\n",priority)
	b.WriteString("add rule inet cfm_panel_redirect prerouting iif \"lo\" accept\n")
	for _,p:= range ports { fmt.Fprintf(&b,"add rule inet cfm_panel_redirect prerouting tcp dport %d dnat to :%d\n",p,panelMap[p]) }
	return b.String()
}

func panelOn(priority int) error {
	_ = exec.Command("nft","delete","table","inet","cfm_panel_redirect").Run()
	s:=panelScript(priority)
	c := exec.Command("nft","-f","-")
	in, _ := c.StdinPipe()
	go func() { _, _ = io.WriteString(in, s); _ = in.Close() }()
	return c.Run()
}

func panelListenerState(port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
	if err != nil {
		return "down"
	}
	_ = conn.Close()
	return "listening"
}

func detectedImunifyMappings() []string {
	rules := runOut("nft","-a","list","ruleset") + "\n" + runOut("iptables-save","-t","nat") + "\n" + runOut("ip6tables-save","-t","nat")
	pairs:=map[string]string{"2087":"52227","2083":"52229","2096":"52231","2082":"52230","2086":"52228","2095":"52232","443":"52223","80":"52224"}
	var got []string
	for s,d:= range pairs { if strings.Contains(rules, s) && strings.Contains(rules, d) { got=append(got, fmt.Sprintf("%s->%s",s,d)) } }
	sort.Strings(got); return got
}
