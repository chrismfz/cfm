package agent

// Fingerprint-policy feed pull (master plan E3, node slice). cfm-web serves
// the ACTIVE, serve-time-gated per-fingerprint enforcement policies at
// GET /api/fingerprint-policies/fetch (see cfm-web
// docs/fingerprint-reputation.md §7); this client pulls them on the agent
// channel — same base URL + Token header as the heartbeat. Parsing is
// deliberately defensive (fleets run mixed versions): an unknown field is
// ignored, a malformed expires_at reads as permanent-until-next-pull rather
// than dropping the row, and the withheld list is ignored here (it is an
// operator diagnostic, not node input).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FingerprintPolicyRow is the feed DTO. Kept agent-local so this package and
// the enforcement store (internal/webdetector) stay import-independent; the
// wiring in cmd/cfm converts.
type FingerprintPolicyRow struct {
	Fingerprint string
	Kind        string // "" reads as "tls"; "country"/"asn" are the geo kinds
	Action      string
	ExpiresAt   time.Time // zero = until disarmed
}

func (c *APIClient) FetchFingerprintPolicies(ctx context.Context) ([]FingerprintPolicyRow, error) {
	u := c.endpoint("/api/fingerprint-policies/fetch")

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch fingerprint policies build request: %w", err)
	}
	req.Header.Set("Token", c.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Agent-Version", "CFM-Agent-Go")

	resp, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var out struct {
		Policies []struct {
			Fingerprint string `json:"fingerprint"`
			PolicyKind  string `json:"policy_kind"` // absent on older cfm-web → tls
			Action      string `json:"action"`
			ExpiresAt   string `json:"expires_at"`
		} `json:"policies"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("fetch fingerprint policies decode: %w", err)
	}

	rows := make([]FingerprintPolicyRow, 0, len(out.Policies))
	for _, p := range out.Policies {
		row := FingerprintPolicyRow{Fingerprint: p.Fingerprint, Kind: p.PolicyKind, Action: p.Action}
		if p.ExpiresAt != "" {
			// cfm-web emits ISO-8601; a malformed value degrades to
			// permanent-until-next-pull (the feed re-validates server-side and
			// stops serving an expired policy anyway) instead of dropping the row.
			if t, err := time.Parse(time.RFC3339, p.ExpiresAt); err == nil {
				row.ExpiresAt = t
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}
