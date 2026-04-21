package traffic

import "testing"

func TestParseConntrackLine(t *testing.T) {
	line := "ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.10 dst=93.184.216.34 sport=54321 dport=443 packets=12 bytes=1600 src=93.184.216.34 dst=10.0.0.10 sport=443 dport=54321 packets=10 bytes=1200 [ASSURED] mark=0 use=1"

	flow, ok := parseConntrackLine(line, 1710000000)
	if !ok {
		t.Fatal("expected conntrack line to parse")
	}
	if flow.FlowID != "tcp|10.0.0.10:54321|93.184.216.34:443|ESTABLISHED" {
		t.Fatalf("unexpected flow id: %s", flow.FlowID)
	}
	if flow.Protocol != "tcp" || flow.SrcIP != "10.0.0.10" || flow.DstIP != "93.184.216.34" {
		t.Fatalf("unexpected flow tuple: %+v", flow)
	}
	if flow.SrcPort != 54321 || flow.DstPort != 443 {
		t.Fatalf("unexpected ports: %+v", flow)
	}
	if flow.InBytes != 1600 || flow.OutBytes != 1200 {
		t.Fatalf("unexpected bytes: %+v", flow)
	}
	if flow.ProcessName != "unknown" || flow.PID != 0 {
		t.Fatalf("expected unknown process mapping by default: %+v", flow)
	}
	if flow.LastSeenUnix != 1710000000 {
		t.Fatalf("unexpected LastSeenUnix: %d", flow.LastSeenUnix)
	}
}

func TestParseConntrackLineRejectsInvalid(t *testing.T) {
	if _, ok := parseConntrackLine("garbage", 0); ok {
		t.Fatal("expected invalid line to fail parse")
	}
}
