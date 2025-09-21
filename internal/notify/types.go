package notify

import "time"

type Event struct {
	Host     string            // titan.myip.gr
	Kind     string            // "autoblock" | "portscan" | "ssh_authfail" ...
	When     time.Time
	SrcIP    string
	Reason   string            // "SYN flood", "portscan 8 ports", ...
	TTL      time.Duration
	Count    int
	PTR      string
	ASN      string
	Country  string
	Section  string
	Samples  []string
	Extra    map[string]string
	Severity string // "info" | "warning" | "critical"
}

type Channel interface {
	Name() string
	Send(ev Event, subj string, body string) error
}
