package mcpserver

import (
	"encoding/json"
	"testing"
)

// A small ban list mirroring the real /api/v1/firewall/list shape: mostly
// permanent, GeoIP country as a full NAME, ASN + ASN name present, comments
// usually empty (as on a live node).
var fwSample = []byte(`{
  "ok": true, "total": 6, "permanent": 5,
  "rows": [
    {"ip":"1.1.1.1","country":"Greece","asn":6799,"asn_name":"OTEnet","permanent":true},
    {"ip":"1.1.1.2","country":"Greece","asn":6799,"asn_name":"OTEnet","permanent":true},
    {"ip":"1.1.1.3","country":"Greece","asn":14061,"asn_name":"DigitalOcean","permanent":true,"comment":"ssh brute"},
    {"ip":"2.2.2.1","country":"China","asn":4134,"asn_name":"Chinanet","permanent":true},
    {"ip":"2.2.2.2","country":"China","asn":4134,"asn_name":"Chinanet","permanent":true},
    {"ip":"3.3.3.1","country":"United States","asn":14061,"asn_name":"DigitalOcean","permanent":false,"expires_in_sec":3600}
  ]
}`)

func TestSummarizeFirewallBlocks_Summary(t *testing.T) {
	out := summarizeFirewallBlocks(fwSample, firewallBlocksInput{})
	if out["view"] != "summary" {
		t.Fatalf("view = %v, want summary", out["view"])
	}
	if out["total"] != 6 || out["permanent"] != 5 || out["temporary"] != 1 {
		t.Fatalf("counts wrong: total=%v perm=%v temp=%v", out["total"], out["permanent"], out["temporary"])
	}
	if out["countries_total"] != 3 {
		t.Fatalf("countries_total = %v, want 3", out["countries_total"])
	}
	bc := out["by_country"].([]fwCountRow)
	// China and Greece both 3 → tie broken alphabetically (China first).
	if len(bc) != 3 || bc[0].Count != 3 {
		t.Fatalf("by_country wrong: %+v", bc)
	}
	// No raw rows leak into the summary.
	if _, ok := out["rows"]; ok {
		t.Fatalf("summary must not embed rows")
	}
}

func TestSummarizeFirewallBlocks_CountryDrilldown(t *testing.T) {
	// Case-insensitive country match — the FP-review workflow ("show my own
	// country's bans"), with an ASN breakdown that separates residential ISP
	// (OTEnet, likely FP) from a VPS network (DigitalOcean, likely real).
	out := summarizeFirewallBlocks(fwSample, firewallBlocksInput{Country: "greece"})
	if out["view"] != "drilldown" {
		t.Fatalf("view = %v, want drilldown", out["view"])
	}
	if out["matched"] != 3 || out["returned"] != 3 {
		t.Fatalf("matched/returned wrong: %v/%v", out["matched"], out["returned"])
	}
	rows := out["rows"].([]fwBlockRow)
	if len(rows) != 3 {
		t.Fatalf("rows len = %d, want 3", len(rows))
	}
	byASN := out["by_asn"].([]fwASNRow)
	if len(byASN) != 2 || byASN[0].ASNName != "OTEnet" || byASN[0].Count != 2 {
		t.Fatalf("by_asn should rank OTEnet(2) first: %+v", byASN)
	}
}

func TestSummarizeFirewallBlocks_ReasonAndLimit(t *testing.T) {
	// reason= filters on the comment substring; the limit caps + flags truncation.
	out := summarizeFirewallBlocks(fwSample, firewallBlocksInput{Reason: "ssh"})
	if out["matched"] != 1 {
		t.Fatalf("reason=ssh matched = %v, want 1", out["matched"])
	}

	out2 := summarizeFirewallBlocks(fwSample, firewallBlocksInput{Country: "china", Limit: 1})
	if out2["matched"] != 2 || out2["returned"] != 1 || out2["truncated"] != true {
		t.Fatalf("limit not applied: matched=%v returned=%v trunc=%v",
			out2["matched"], out2["returned"], out2["truncated"])
	}
}

// The summary must stay small regardless of ban-list size (the whole point).
func TestSummarizeFirewallBlocks_SummaryStaysCompact(t *testing.T) {
	rows := make([]map[string]any, 0, 5000)
	for i := 0; i < 5000; i++ {
		rows = append(rows, map[string]any{"ip": "10.0.0.1", "country": "China", "asn": 4134, "permanent": true})
	}
	body, _ := json.Marshal(map[string]any{"rows": rows, "total": 5000, "permanent": 5000})
	out := summarizeFirewallBlocks(body, firewallBlocksInput{})
	b, _ := json.Marshal(out)
	if len(b) > 4096 {
		t.Fatalf("summary of 5000 bans should stay compact, got %d bytes", len(b))
	}
}
