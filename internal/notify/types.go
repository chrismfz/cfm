package notify

import "time"

type Event struct {
	Host    string // titan.myip.gr
	Kind    string // "autoblock" | "portscan" | "ssh_authfail" ...
	When    time.Time
	SrcIP   string // source IP for source-oriented detectors; destination details belong in Extra for outbound alerts
	Reason  string // "SYN flood", "portscan 8 ports", ...
	TTL     time.Duration
	Count   int
	PTR     string
	ASN     string
	Country string
	// CountryISO is the ISO-2 code ("GR") for the alert store's country
	// filter; Enqueue fills it from the same lookup that fills Country.
	CountryISO string
	Section    string
	Samples    []string
	Extra      map[string]string
	Severity   string // "info" | "warning" | "critical"
	// Mute records the event in the alert store as muted and sends nothing,
	// like a [detector] override with notify = 0. Set by the detector sink
	// for an alert carrying core.ExtraNotify = no: the alert log must still
	// show every ban.
	Mute bool
}

type Channel interface {
	Name() string
	Send(ev Event, subj string, body string) error
}
