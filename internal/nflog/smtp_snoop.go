// internal/nflog/smtp_snoop.go
package nflog

import (
	"context"
	"encoding/binary"
	"net"
	"time"

	nflog "github.com/florianl/go-nflog/v2"

	"cfm/internal/config"
	"cfm/internal/enrich"
	"cfm/internal/logging"
)

// SnoopConfig holds runtime settings for the NFLOG SMTP snooper.
type SnoopConfig struct {
	Group  uint16
	Enrich bool
	Queue  int
}

// Start begins listening to NFLOG for SMTP block events.
func Start(ctx context.Context, c SnoopConfig) error {
	if c.Group == 0 {
		return nil
	}

	// Minimal config. If your go-nflog version supports payload copy,
	// uncomment the relevant field below.
	nf, err := nflog.Open(&nflog.Config{
		Group: c.Group,
		// Copysize:  0xFFFF, // some v2.x releases
		// CopyRange: 0xFFFF, // others use CopyRange
	})
	if err != nil {
		return err
	}

	q := c.Queue
	if q <= 0 {
		q = 1024
	}
	events := make(chan evt, q)

	// Optional enricher (GeoIP/ASN/etc.)
	var en *enrich.Enricher
	if c.Enrich {
		if e, _ := enrich.New("/etc/cfm", "./configs"); e != nil {
			en = e
		}
	}

	// Worker goroutine: consumes events and writes logs
	go func() {
		defer nf.Close()
		if en != nil {
			defer en.Close()
		}
		for {
			select {
			case <-ctx.Done():
				return
			case e := <-events:
				if e.ipver != 0 {
					if en != nil {
						info := en.Lookup(e.dst.String())
						logging.LogfSMTP(
							"blocked uid=%d gid=%d TCP %s:%d -> %s:%d | ASN=%s (%d) CC=%s City=%s PTR=%s",
							e.uid, e.gid,
							e.src.String(), e.sport,
							e.dst.String(), e.dport,
							info.ASNName, info.ASN, info.Country, info.City, info.PTR,
						)
					} else {
						logging.LogfSMTP(
							"blocked uid=%d gid=%d TCP %s:%d -> %s:%d",
							e.uid, e.gid,
							e.src.String(), e.sport,
							e.dst.String(), e.dport,
						)
					}
				} else {
					// No payload data captured
					logging.LogfSMTP(
						"blocked uid=%d gid=%d (no payload; NFLOG payload copy may be disabled)",
						e.uid, e.gid,
					)
				}
			}
		}
	}()

	// Callback from kernel
	cb := func(a nflog.Attribute) int {
		var uid, gid uint32
		if a.UID != nil {
			uid = *a.UID
		}
		if a.GID != nil {
			gid = *a.GID
		}

		// Defaults if no payload
		ipver := 0
		var src, dst net.IP
		var sport, dport uint16

		if a.Payload != nil && len(*a.Payload) > 0 {
			ipver, src, dst, sport, dport = parseTCP(*a.Payload)
		}

		select {
		case events <- evt{time.Now(), uid, gid, ipver, src, dst, sport, dport}:
		default:
			// drop if queue is full
		}
		return 0
	}

	return nf.Register(context.Background(), cb)
}

// evt holds one NFLOG event
type evt struct {
	when         time.Time
	uid, gid     uint32
	ipver        int
	src, dst     net.IP
	sport, dport uint16
}

// parseTCP decodes IPv4/IPv6 TCP headers from a raw packet.
func parseTCP(p []byte) (ipver int, src, dst net.IP, sport, dport uint16) {
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
		if p[9] != 6 {
			return
		}
		src = net.IPv4(p[12], p[13], p[14], p[15])
		dst = net.IPv4(p[16], p[17], p[18], p[19])
		sport = binary.BigEndian.Uint16(p[ihl : ihl+2])
		dport = binary.BigEndian.Uint16(p[ihl+2 : ihl+4])
		return 4, src, dst, sport, dport
	case 6:
		if len(p) < 40 {
			return
		}
		if p[6] != 6 {
			return
		}
		src = net.IP(p[8:24])
		dst = net.IP(p[24:40])
		if len(p) < 44 {
			return
		}
		sport = binary.BigEndian.Uint16(p[40:42])
		dport = binary.BigEndian.Uint16(p[42:44])
		return 6, src, dst, sport, dport
	default:
		return
	}
}

// FromConfig converts SMTPBlockConfig into SnoopConfig.
func FromConfig(c *config.SMTPBlockConfig) SnoopConfig {
	return SnoopConfig{
		Group:  uint16(c.LogNFLOG),
		Enrich: c.LogEnrich,
	}
}
