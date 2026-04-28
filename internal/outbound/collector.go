package outbound

import (
	"context"
	"encoding/binary"
	"net"
	"time"

	"github.com/miekg/dns"

	nflog "github.com/florianl/go-nflog/v2"
	"github.com/mdlayher/netlink"

	"cfm/internal/enrich"
	"cfm/internal/syslookup"
)

// CollectorConfig groups the runtime knobs the NFLOG collector needs at start
// time. It is built from config.OutboundConfig in lifecycle.go.
type CollectorConfig struct {
	Group   uint16
	Queue   int // channel buffer; default 2048
	Runtime Runtime
}

// Start begins listening on the outbound NFLOG group. It returns once the
// nflog socket is registered; the worker goroutine runs until ctx is cancelled.
//
// Phase-1 contract: this only observes — it never injects nft rules to drop
// or rate-limit. Verdicts are dispatched to the alerter goroutine which logs
// to cfm.smtp.log and emits notify events.
func Start(ctx context.Context, c CollectorConfig, alerter *Alerter) error {
	if c.Group == 0 {
		return nil
	}

	nf, err := nflog.Open(&nflog.Config{
		Group:    c.Group,
		Copymode: nflog.CopyPacket,
	})
	if err != nil {
		return err
	}

	_ = nf.Con.SetReadBuffer(512 * 1024)
	_ = nf.SetOption(netlink.NoENOBUFS, true)

	q := c.Queue
	if q <= 0 {
		q = 2048
	}
	events := make(chan rawEvent, q)

	var en *enrich.Enricher
	if c.Runtime.Enrich {
		if e, _ := enrich.New("/etc/cfm", "/var/lib/cfm/maxmind"); e != nil {
			en = e
		}
	}

	um := syslookup.New()
	pf := syslookup.NewProcFinder()
	an := NewAnalyzer(c.Runtime)
	dnsRecent := newDNSRecentRing(0, 0, 0)

	go func() {
		defer nf.Close()
		if en != nil {
			defer en.Close()
		}
		for {
			select {
			case <-ctx.Done():
				return
			case re := <-events:
				if re.ipver == 0 {
					continue
				}
				sig := classify(re, c.Runtime)
				if sig == "" {
					continue
				}
				if sig == SignalDNS {
					dnsRecent.add(re.uid, dnsSummaryFromRaw(re))
				}
				if an.IsAllowed(re.uid, re.gid) {
					continue
				}
				ev := Event{
					When:          re.when,
					UID:           re.uid,
					GID:           re.gid,
					IPVer:         re.ipver,
					SPort:         re.sport,
					DPort:         re.dport,
					IsUDP:         re.isUDP,
					Signal:        sig,
					DNSRCode:      re.dnsRCode,
					DNSRCodeKnown: re.dnsRCodeKnown,
				}
				copyIP(&ev.SrcIP, re.src)
				copyIP(&ev.DstIP, re.dst)

				v := an.Observe(ev)
				if v == nil {
					continue
				}
				ac := alertContext{
					um:    um,
					pf:    pf,
					en:    en,
					ipver: re.ipver,
					srcIP: re.src,
					dstIP: re.dst,
					sport: re.sport,
					dport: re.dport,
				}
				if v.Signal == SignalDNS {
					ac.dnsPretrigger = dnsRecent.snapshot(v.UID, v.When)
				}
				alerter.Emit(ctx, *v, ac)
			}
		}
	}()

	cb := func(a nflog.Attribute) int {
		var uid, gid uint32
		if a.UID != nil {
			uid = *a.UID
		}
		if a.GID != nil {
			gid = *a.GID
		}
		var (
			ipver         int
			src, dst      net.IP
			sport, dport  uint16
			isUDP         bool
			dnsQType      uint16
			dnsQTypeKnown bool
			dnsQName      string
			dnsRCode      uint8
			dnsRCodeKnown bool
		)
		if a.Payload != nil && len(*a.Payload) > 0 {
			ipver, src, dst, sport, dport, isUDP, dnsQName, dnsQType, dnsQTypeKnown, dnsRCode, dnsRCodeKnown = parsePacket(*a.Payload)
		}
		select {
		case events <- rawEvent{time.Now(), uid, gid, ipver, src, dst, sport, dport, isUDP, dnsQName, dnsQType, dnsQTypeKnown, dnsRCode, dnsRCodeKnown}:
		default:
			// Drop on overflow rather than block the kernel callback.
		}
		return 0
	}

	return nf.Register(ctx, cb)
}

type rawEvent struct {
	when          time.Time
	uid, gid      uint32
	ipver         int
	src, dst      net.IP
	sport, dport  uint16
	isUDP         bool
	dnsQName      string
	dnsQType      uint16
	dnsQTypeKnown bool
	dnsRCode      uint8
	dnsRCodeKnown bool
}

// alertContext carries the bits the alerter needs to render a forensic line
// without re-resolving uid/proc/enrich on its own.
type alertContext struct {
	um            *syslookup.Map
	pf            *syslookup.ProcFinder
	en            *enrich.Enricher
	ipver         int
	srcIP         net.IP
	dstIP         net.IP
	sport         uint16
	dport         uint16
	dnsPretrigger []DNSPacketSummary
}

func copyIP(dst *[16]byte, src net.IP) {
	if src == nil {
		return
	}
	if v4 := src.To4(); v4 != nil {
		// Store IPv4 in v4-mapped form so ipKey() in analyzer slices [12:16].
		copy(dst[12:16], v4)
		return
	}
	copy(dst[:], src.To16())
}

// classify maps a raw event to a Signal based on dport (and proto for DNS).
// Returns "" if the event doesn't match any configured signal.
func classify(re rawEvent, rt Runtime) Signal {
	if re.isUDP {
		// Phase 1 cares about UDP/53 only.
		if re.dport == 53 {
			return SignalDNS
		}
		return ""
	}
	if _, ok := rt.SMTPPorts[re.dport]; ok {
		return SignalSMTP
	}
	if _, ok := rt.ScanPorts[re.dport]; ok {
		return SignalSCAN
	}
	if _, ok := rt.HTTPPorts[re.dport]; ok {
		return SignalHTTP
	}
	// TCP/53 (rare) is also DNS.
	if re.dport == 53 {
		return SignalDNS
	}
	return ""
}

// parsePacket decodes IPv4/IPv6 + TCP/UDP. Returns ipver=0 on malformed input.
// We accept both protocols here (smtp_snoop.go only handled TCP).
func parsePacket(p []byte) (ipver int, src, dst net.IP, sport, dport uint16, isUDP bool, dnsQName string, dnsQType uint16, dnsQTypeKnown bool, dnsRCode uint8, dnsRCodeKnown bool) {
	if len(p) < 1 {
		return
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return
		}
		ihl := int(p[0]&0x0F) * 4
		if len(p) < ihl+4 {
			return
		}
		proto := p[9]
		if proto != 6 && proto != 17 {
			return
		}
		src = net.IPv4(p[12], p[13], p[14], p[15])
		dst = net.IPv4(p[16], p[17], p[18], p[19])
		sport = binary.BigEndian.Uint16(p[ihl : ihl+2])
		dport = binary.BigEndian.Uint16(p[ihl+2 : ihl+4])
		if (sport == 53 || dport == 53) && len(p) >= ihl {
			if payload, ok := dnsPayload(proto, p[ihl:]); ok {
				dnsQName, dnsQType, dnsQTypeKnown, dnsRCode, dnsRCodeKnown = parseDNSFields(payload)
			}
		}
		return 4, src, dst, sport, dport, proto == 17, dnsQName, dnsQType, dnsQTypeKnown, dnsRCode, dnsRCodeKnown
	case 6:
		if len(p) < 40 {
			return
		}
		proto := p[6]
		if proto != 6 && proto != 17 {
			return
		}
		src = net.IP(p[8:24])
		dst = net.IP(p[24:40])
		if len(p) < 44 {
			return
		}
		sport = binary.BigEndian.Uint16(p[40:42])
		dport = binary.BigEndian.Uint16(p[42:44])
		if sport == 53 || dport == 53 {
			if payload, ok := dnsPayload(proto, p[40:]); ok {
				dnsQName, dnsQType, dnsQTypeKnown, dnsRCode, dnsRCodeKnown = parseDNSFields(payload)
			}
		}
		return 6, src, dst, sport, dport, proto == 17, dnsQName, dnsQType, dnsQTypeKnown, dnsRCode, dnsRCodeKnown
	}
	return
}

func dnsPayload(proto byte, l4 []byte) ([]byte, bool) {
	switch proto {
	case 17:
		if len(l4) < 8 {
			return nil, false
		}
		return l4[8:], true
	case 6:
		if len(l4) < 20 {
			return nil, false
		}
		off := int((l4[12] >> 4) * 4)
		if len(l4) < off+2 {
			return nil, false
		}
		dnsStart := l4[off:]
		if len(dnsStart) < 2 {
			return nil, false
		}
		msgLen := int(binary.BigEndian.Uint16(dnsStart[:2]))
		if msgLen <= 0 || len(dnsStart) < 2+msgLen {
			return nil, false
		}
		return dnsStart[2 : 2+msgLen], true
	default:
		return nil, false
	}
}

func parseDNSFields(payload []byte) (qname string, qtype uint16, qtypeKnown bool, rcode uint8, rcodeKnown bool) {
	if len(payload) < 12 {
		return
	}
	var msg dns.Msg
	if err := msg.Unpack(payload); err != nil {
		return
	}
	if len(msg.Question) > 0 {
		qname = msg.Question[0].Name
		qtype = msg.Question[0].Qtype
		qtypeKnown = true
	}
	if msg.Response {
		rcode = uint8(msg.Rcode)
		rcodeKnown = true
	}
	return
}
