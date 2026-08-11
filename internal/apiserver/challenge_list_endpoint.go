// internal/apiserver/challenge_list_endpoint.go
//
// GET /api/v1/firewall/challenge/list — read-only dump of the DNAT challenge
// sets (challenge_v4 / challenge_v6) with each member's remaining TTL. This is
// the live instrument for the "stuck in an endless Checking-your-browser loop"
// class of bug on a DNAT node: is a just-solved IP still a member (RemoveChallenge
// failed to commit → nftlib delete bug) or does it keep reappearing with a fresh
// TTL (the engine re-challenges it → missing solve cooldown)? Poll it: a TTL that
// counts DOWN across calls is the same entry aging out; a TTL that RESETS is a
// re-add. Empty sets are normal in edge/OpenResty mode (there the gate is the Lua
// clearance cookie, not an nft set).
//
// Admin-only like the other global firewall routes — a node-wide challenge set is
// meaningless to a scoped vhost token.

package apiserver

import (
	"encoding/json"
	"net/http"
	"time"

	"cfm/internal/firewall"
)

// challengeSetNames are the DNAT challenge sets dumped by this endpoint. Kept in
// sync with internal/firewall/nftlib/backend.go (setChalV4/setChalV6).
var challengeSetNames = []string{"challenge_v4", "challenge_v6"}

type challengeRow struct {
	IP        string `json:"ip"`
	TTLSec    int64  `json:"ttl_sec,omitempty"` // remaining TTL; 0/omitted = no timeout
	Permanent bool   `json:"permanent"`
	Country   string `json:"country,omitempty"`
	ASN       uint   `json:"asn,omitempty"`
	ASNName   string `json:"asn_name,omitempty"`
}

type challengeSetDump struct {
	Count int            `json:"count"`
	Rows  []challengeRow `json:"rows"`
	Error string         `json:"error,omitempty"`
}

// RegisterChallengeList adds GET /api/v1/firewall/challenge/list.
func RegisterChallengeList(m *http.ServeMux, be firewall.Backend) {
	if m == nil {
		return
	}
	m.Handle("/api/v1/firewall/challenge/list", adminOnlyHandler(makeChallengeListHandler(be)))
}

func makeChallengeListHandler(be firewall.Backend) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
			return
		}
		if be == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "no firewall backend"})
			return
		}

		engine := "unknown"
		if m, ok := be.(interface{ Engine() string }); ok {
			engine = m.Engine()
		}
		enr := be.GetEnricher()

		sets := make(map[string]challengeSetDump, len(challengeSetNames))
		total := 0
		for _, name := range challengeSetNames {
			elems, err := be.ListSetElementsTimed(name)
			if err != nil {
				// A missing set (e.g. an IPv6-disabled node with no challenge_v6) is
				// reported per-set, not fatal to the whole response.
				sets[name] = challengeSetDump{Error: err.Error()}
				continue
			}
			rows := make([]challengeRow, 0, len(elems))
			for _, e := range elems {
				row := challengeRow{IP: e.Elem, Permanent: e.Expires <= 0}
				if e.Expires > 0 {
					row.TTLSec = int64(e.Expires / time.Second)
				}
				if enr != nil {
					g := enr.LookupCachedOrAsync(e.Elem)
					row.Country = g.Country
					row.ASN = g.ASN
					row.ASNName = g.ASNName
				}
				rows = append(rows, row)
			}
			sets[name] = challengeSetDump{Count: len(rows), Rows: rows}
			total += len(rows)
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":     true,
			"engine": engine,
			"total":  total,
			"sets":   sets,
			"note":   "empty sets are normal in edge/OpenResty mode (there the gate is the Lua clearance cookie, not an nft set); a member whose ttl_sec RESETS across polls is being re-challenged, one that counts DOWN is aging out",
		})
	}
}
