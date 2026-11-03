package mcpserver

// alerts.go — read-only MCP tools over the node's alert store
// (internal/alerts, GET /api/v1/alerts and /api/v1/alerts/summary): every
// event the detectors raised for the notifier, recorded whether or not a mail
// went out.

import (
	"context"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type alertsFilterInput struct {
	Hours       int    `json:"hours,omitempty" jsonschema:"look back this many hours (default 24, max 2160 = 90 days; the store keeps 30 days by default)"`
	Category    string `json:"category,omitempty" jsonschema:"comma list of families, e.g. WAF,WEB,MODSEC,MYSQL,CLAM,SSH,DOVECOT,PORTSCAN — the part of the kind before the slash"`
	Kind        string `json:"kind,omitempty" jsonschema:"comma list of exact kinds, e.g. WAF/SQLI,WEB/MALPATH"`
	MinSeverity string `json:"min_severity,omitempty" jsonschema:"info | warning | critical floor"`
	IP          string `json:"ip,omitempty" jsonschema:"one client address"`
	Country     string `json:"country,omitempty" jsonschema:"ISO-2 code (GR) or part of the country name"`
	ASN         string `json:"asn,omitempty" jsonschema:"AS number (6799 or AS6799) or part of the network name"`
	Vhost       string `json:"vhost,omitempty" jsonschema:"one website the event was about"`
	Mode        string `json:"mode,omitempty" jsonschema:"ttl | permanent (bans only)"`
	Delivery    string `json:"delivery,omitempty" jsonschema:"comma list: notified, send_failed, deduped, notifier_off, no_channels, muted, below_severity, queue_full"`
	Query       string `json:"q,omitempty" jsonschema:"text to find in reason, kind, PTR, ASN, vhost or sample lines"`
}

func (in alertsFilterInput) values() url.Values {
	q := url.Values{}
	setInt(q, "hours", in.Hours)
	setStr(q, "category", in.Category)
	setStr(q, "kind", in.Kind)
	setStr(q, "min_severity", in.MinSeverity)
	setStr(q, "ip", in.IP)
	setStr(q, "country", in.Country)
	setStr(q, "asn", in.ASN)
	setStr(q, "vhost", in.Vhost)
	setStr(q, "mode", in.Mode)
	setStr(q, "delivery", in.Delivery)
	setStr(q, "q", in.Query)
	return q
}

type alertsListInput struct {
	alertsFilterInput
	Limit  int    `json:"limit,omitempty" jsonschema:"rows per page (default 100, max 500)"`
	Cursor string `json:"cursor,omitempty" jsonschema:"next_cursor from the previous page"`
}

type alertsSummaryInput struct {
	alertsFilterInput
	GroupBy string `json:"group_by,omitempty" jsonschema:"comma list of up to 3 of: category, kind, severity, ip, country, asn, vhost, reason, mode, delivery, section, hour, day (default category)"`
	Top     int    `json:"top,omitempty" jsonschema:"groups to return (default 50, max 500)"`
}

func registerAlerts(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "alerts",
		Description: "This node's alert log: every event its detectors raised for the notifier (WAF/WEB/MODSEC blocks, autoblock bans, portscans, SSH/Dovecot auth failures, MySQL governor, ClamAV, outbound abuse, LSM, …), newest first — the same events that used to arrive only as '[CFM] host — KIND ip …' mails, but recorded even when no mail channel is set up, and including the ones dedupe or a detector override did not send. Each row: time, category (the kind's family), kind, severity, ip with country (+ ISO code), ASN and PTR, the vhost it was about when known, reason, ban mode/ttl, count, delivery (what the notifier did: notified, send_failed (every channel errored), deduped, notifier_off, no_channels, muted, below_severity, queue_full), up to 5 sample log lines and the detector's extra fields. Filter by hours, category, kind, severity, ip, country, asn, vhost, mode, delivery or free text; page with cursor. For counts and 'which kind/country/network/site is this mostly?' use alerts_summary instead of paging through rows.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in alertsListInput) (*mcp.CallToolResult, any, error) {
		q := in.values()
		setInt(q, "limit", in.Limit)
		setStr(q, "cursor", in.Cursor)
		return dispatchJSON(ctx, d, "/api/v1/alerts", q)
	})
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "alerts_summary",
		Description: "Group this node's alert log (see `alerts`) by up to three dimensions — category, kind, severity, ip, country (ISO-2), asn, vhost, reason, mode, delivery, section, or hour/day buckets — with the same filters, returning per group the count, distinct IPs, first/last time and a label (ASN or country name). Answers questions like 'which detectors blocked Greek clients this week and from which networks?' (country=GR, group_by=kind,asn), 'is one site drawing most WAF hits?' (category=WAF, group_by=vhost), 'when did the portscan bans start?' (category=PORTSCAN, group_by=hour) or 'what never reached a mailbox?' (group_by=delivery). Top groups by count; time buckets in time order. For fleet-wide questions call it with node=\"all\".",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in alertsSummaryInput) (*mcp.CallToolResult, any, error) {
		q := in.values()
		setStr(q, "group_by", in.GroupBy)
		setInt(q, "top", in.Top)
		return dispatchJSON(ctx, d, "/api/v1/alerts/summary", q)
	})
}
