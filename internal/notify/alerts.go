package notify

import (
	"fmt"

	"cfm/internal/alerts"
)

// recordAlert hands ev to the alert store (internal/alerts) with what the
// notifier decided about delivering it. A no-op when the store is not open
// (tests, or a node whose store failed to open).
func recordAlert(ev Event, delivery, eventID string) {
	if alerts.Default() == nil {
		return
	}
	// Emit already did this; the Enqueue paths (queue_full, never started)
	// did not, and without it the store would stamp the raw os.Hostname and
	// ignore notify.conf's hostname_override.
	if ev.Host == "" {
		ev.Host = hostname
	}
	r := alerts.Record{
		TsUnix:   ev.When.Unix(),
		Host:     ev.Host,
		Kind:     ev.Kind,
		Severity: ev.Severity,
		IP:       ev.SrcIP,
		Country:  ev.Country,
		ASN:      ev.ASN,
		PTR:      ev.PTR,
		Reason:   ev.Reason,
		TTLSec:   int64(ev.TTL.Seconds()),
		Count:    ev.Count,
		Section:  ev.Section,
		Delivery: delivery,
		EventID:  eventID,
		Samples:  ev.Samples,
		Extra:    ev.Extra,
	}
	if ev.When.IsZero() {
		r.TsUnix = 0 // the store stamps it
	}
	// The display country ("Athens, Greece") is for humans; filtering and
	// grouping need the ISO code. Enqueue's lookup usually set it; otherwise
	// (callers that enrich themselves, or call Emit directly) the enricher's
	// cache has the IP from that lookup; a miss costs one mmdb read — no DNS,
	// and no background lookup started just to fill a country code.
	r.CountryISO = ev.CountryISO
	if r.CountryISO == "" && ev.SrcIP != "" {
		if enr := enricher; enr != nil {
			res := enr.LookupCachedOrGeo(ev.SrcIP)
			r.CountryISO = res.CountryISO
			if r.ASN == "" && res.ASN > 0 {
				r.ASN = fmt.Sprintf("AS%d %s", res.ASN, res.ASNName)
			}
		}
	}
	alerts.Add(r)
}
