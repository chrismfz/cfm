package outbound

import (
	"encoding/binary"
	"testing"
)

func TestClassify_IgnoresUDPAndMatchesTCPSignals(t *testing.T) {
	rt := Runtime{
		SMTPPorts: map[uint16]struct{}{25: {}},
		ScanPorts: map[uint16]struct{}{22: {}},
		HTTPPorts: map[uint16]struct{}{443: {}},
	}

	if sig := classify(rawEvent{isUDP: true, dport: 53}, rt); sig != "" {
		t.Fatalf("expected udp to be ignored, got %q", sig)
	}
	if sig := classify(rawEvent{dport: 25}, rt); sig != SignalSMTP {
		t.Fatalf("expected smtp signal, got %q", sig)
	}
	if sig := classify(rawEvent{dport: 22}, rt); sig != SignalSCAN {
		t.Fatalf("expected scan signal, got %q", sig)
	}
	if sig := classify(rawEvent{dport: 443}, rt); sig != SignalHTTP {
		t.Fatalf("expected http signal, got %q", sig)
	}
}

func TestParsePacket_ReturnsBasicTupleWithoutDNSFields(t *testing.T) {
	p := make([]byte, 40)
	p[0] = 0x45
	p[9] = 6 // tcp
	copy(p[12:16], []byte{10, 0, 0, 2})
	copy(p[16:20], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(p[20:22], 40000)
	binary.BigEndian.PutUint16(p[22:24], 25)

	ipver, src, dst, sport, dport, isUDP := parsePacket(p)
	if ipver != 4 || isUDP {
		t.Fatalf("unexpected parse tuple: ipver=%d isUDP=%v", ipver, isUDP)
	}
	if src.String() != "10.0.0.2" || dst.String() != "1.1.1.1" {
		t.Fatalf("unexpected ips: src=%s dst=%s", src, dst)
	}
	if sport != 40000 || dport != 25 {
		t.Fatalf("unexpected ports: sport=%d dport=%d", sport, dport)
	}
}
