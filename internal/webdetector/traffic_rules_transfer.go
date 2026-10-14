// internal/webdetector/traffic_rules_transfer.go
//
// Export / import of traffic rules between nodes (moving a site from one
// server to another without retyping its rules).
//
//   GET  /api/v1/webdet/rules/export[?vhost=a&vhost=b]
//   POST /api/v1/webdet/rules/import[?dry_run=1]   body: the export document
//
// The document is portable: no ids, no timestamps (the target assigns them).
// Import validates every rule with normalizeTrafficRule — the same validator
// as /rules/add, never a second copy — and is all-or-nothing: one invalid or
// out-of-scope rule rejects the whole document and nothing is written. A rule
// identical to one already on the node (same vhosts, match and action) is
// skipped, so importing the same file twice adds nothing. A priority shared
// with an existing rule on an overlapping vhost is only a warning (ties are
// allowed; the editor warns the same way).
//
// Scope: export is scope-filtered like the list; every imported rule must be
// inside the caller's vhost allowlist like /rules/add (scopeAllowsVhosts).

package webdetector

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	trafficRulesExportFormat  = "cfm-traffic-rules"
	trafficRulesExportVersion = 1
	maxRuleImportBodyBytes    = 2 << 20 // 2 MiB: a site's rules many times over (a whole node can exceed it: "request body too large")
)

// TrafficRuleExport is one rule as it travels between nodes.
type TrafficRuleExport struct {
	Enabled  bool              `json:"enabled"`
	Priority int               `json:"priority"`
	Scope    TrafficRuleScope  `json:"scope"`
	Match    TrafficRuleMatch  `json:"match"`
	Action   TrafficRuleAction `json:"action"`
	Note     string            `json:"note,omitempty"`

	// unknownFields: the rule's match or scope carries a key this build
	// does not know (a newer cfm's selector, or a typo). Dropping it would
	// widen the rule, possibly to every request, so such a rule is invalid.
	unknownFields bool
}

// TrafficRulesExportDoc is the export / import document.
type TrafficRulesExportDoc struct {
	Format     string              `json:"format"`
	Version    int                 `json:"version"`
	ExportedAt time.Time           `json:"exported_at"`
	Node       string              `json:"node,omitempty"`
	Vhosts     []string            `json:"vhosts,omitempty"` // the export filter, if any
	Rules      []TrafficRuleExport `json:"rules"`
	// Skipped counts rules left out because this build cannot read them
	// (written by a newer cfm); they stay on the source node.
	Skipped int `json:"skipped_unsupported,omitempty"`
}

// TrafficRuleImportItem is the plan for one rule of the document.
type TrafficRuleImportItem struct {
	Index    int         `json:"index"`
	Status   string      `json:"status"` // "add" | "duplicate" | "invalid"
	Rule     TrafficRule `json:"rule"`
	Error    string      `json:"error,omitempty"`
	Warnings []string    `json:"warnings,omitempty"`
	// DuplicateOf is the existing rule an identical import matches.
	DuplicateOf string `json:"duplicate_of,omitempty"`
}

// TrafficRuleImportResult answers /rules/import.
type TrafficRuleImportResult struct {
	DryRun     bool                    `json:"dry_run"`
	Items      []TrafficRuleImportItem `json:"items"`
	Add        int                     `json:"add"`
	Duplicates int                     `json:"duplicates"`
	Invalid    int                     `json:"invalid"`
	Added      []string                `json:"added,omitempty"` // new ids (not on a dry run)
	Error      string                  `json:"error,omitempty"`

	outOfScope int // invalid only because a vhost is outside the caller's scope
}

// exportTrafficRules builds the document from the node's rules. With vhosts
// set, a rule is kept when its scope names one of them exactly (after the
// same host normalization the scope uses); a wildcard or "*" rule is only
// kept when asked for by that exact value.
func exportTrafficRules(rules []TrafficRule, vhosts []string, node string, now time.Time) TrafficRulesExportDoc {
	want := map[string]bool{}
	var filter []string
	for _, h := range vhosts {
		if h = normalizeControlHost(h); h != "" && !want[h] {
			want[h] = true
			filter = append(filter, h)
		}
	}
	doc := TrafficRulesExportDoc{
		Format:     trafficRulesExportFormat,
		Version:    trafficRulesExportVersion,
		ExportedAt: now.UTC(),
		Node:       node,
		Vhosts:     filter,
		Rules:      []TrafficRuleExport{},
	}
	for _, r := range rules {
		if len(want) > 0 && !scopeNamesAny(r.Scope.Vhosts, want) {
			continue
		}
		if r.Unsupported {
			doc.Skipped++
			continue
		}
		doc.Rules = append(doc.Rules, TrafficRuleExport{
			Enabled:  r.Enabled,
			Priority: r.Priority,
			Scope:    r.Scope,
			Match:    r.Match,
			Action:   r.Action,
			Note:     r.Note,
		})
	}
	return doc
}

func scopeNamesAny(scope []string, want map[string]bool) bool {
	for _, h := range scope {
		if want[normalizeControlHost(h)] {
			return true
		}
	}
	return false
}

// trafficRuleKey identifies a rule by what it does (vhosts, match, action),
// ignoring id, priority, enabled, note and timestamps. The list selectors are
// sets, so they are compared sorted.
func trafficRuleKey(r TrafficRule) string {
	sorted := func(in []string) []string {
		out := append([]string(nil), in...)
		sort.Strings(out)
		return out
	}
	m := r.Match
	m.CountryIn = sorted(m.CountryIn)
	m.CountryNotIn = sorted(m.CountryNotIn)
	m.IPAny = sorted(m.IPAny)
	m.UAAny = sorted(m.UAAny)
	m.PathAny = sorted(m.PathAny)
	m.Methods = sorted(m.Methods)
	b, _ := json.Marshal(struct {
		V []string          `json:"v"`
		M TrafficRuleMatch  `json:"m"`
		A TrafficRuleAction `json:"a"`
	}{sorted(r.Scope.Vhosts), m, r.Action})
	return string(b)
}

func vhostsOverlap(a, b []string) bool {
	set := map[string]bool{}
	for _, h := range a {
		set[h] = true
	}
	for _, h := range b {
		if set[h] {
			return true
		}
	}
	return false
}

// planTrafficRuleImport validates the document against the node's current
// rules. inScope reports whether the caller may write a rule for these vhosts
// (nil = unrestricted). disabled imports every rule with enabled=false.
// Each note gets the document's origin appended (withImportNote).
func planTrafficRuleImport(existing []TrafficRule, doc TrafficRulesExportDoc, disabled bool, inScope func([]string) bool) (TrafficRuleImportResult, error) {
	res := TrafficRuleImportResult{Items: []TrafficRuleImportItem{}}
	if doc.Format != trafficRulesExportFormat {
		return res, fmt.Errorf("not a traffic rules export (format %q, want %q)", doc.Format, trafficRulesExportFormat)
	}
	if doc.Version != trafficRulesExportVersion {
		return res, fmt.Errorf("unsupported export version %d (this cfm reads version %d)", doc.Version, trafficRulesExportVersion)
	}
	if len(doc.Rules) == 0 {
		return res, errors.New("the document has no rules")
	}
	if len(doc.Rules) > maxRulesGlobal {
		return res, fmt.Errorf("too many rules in the document (max %d)", maxRulesGlobal)
	}
	byKey := map[string]TrafficRule{}
	for _, r := range existing {
		if !r.Unsupported {
			byKey[trafficRuleKey(r)] = r
		}
	}
	var added []TrafficRule // this file's rules planned so far, for priority ties
	origin := importNoteSuffix(doc)
	seen := map[string]int{}
	for i, x := range doc.Rules {
		item := TrafficRuleImportItem{Index: i}
		in := TrafficRule{
			Enabled:  x.Enabled && !disabled,
			Priority: x.Priority,
			Scope:    x.Scope,
			Match:    x.Match,
			Action:   x.Action,
			Note:     withImportNote(x.Note, origin),
		}
		norm, err := normalizeTrafficRule(in, true)
		switch {
		case x.unknownFields:
			item.Status, item.Error = "invalid", "uses match or scope fields this cfm does not understand (a newer cfm, or a typo); importing it without them would widen the rule"
			item.Rule = in
		case err != nil:
			item.Status, item.Error = "invalid", err.Error()
			item.Rule = in
		case inScope != nil && !inScope(norm.Scope.Vhosts):
			item.Status, item.Error = "invalid", "vhost not in scope"
			item.Rule = norm
			res.outOfScope++
		default:
			norm.ID = "" // assigned when added
			item.Rule = norm
			k := trafficRuleKey(norm)
			if ex, ok := byKey[k]; ok {
				item.Status, item.DuplicateOf = "duplicate", ex.ID
				// The key ignores enabled and priority: say so when the rule
				// already here would not behave like the imported one.
				if norm.Enabled && !ex.Enabled {
					item.Warnings = append(item.Warnings, fmt.Sprintf("%s is DISABLED here; it is not enabled by this import", ex.ID))
				}
				if norm.Priority != ex.Priority {
					item.Warnings = append(item.Warnings, fmt.Sprintf("%s has priority %d here, the file says %d; it is not changed by this import", ex.ID, ex.Priority, norm.Priority))
				}
			} else if j, ok := seen[k]; ok {
				item.Status, item.DuplicateOf = "duplicate", fmt.Sprintf("rule #%d of this file", j+1)
			} else {
				item.Status = "add"
				seen[k] = i
				for _, r := range existing {
					if !r.Unsupported && r.Priority == norm.Priority && vhostsOverlap(r.Scope.Vhosts, norm.Scope.Vhosts) {
						item.Warnings = append(item.Warnings, fmt.Sprintf("priority %d is also used by %s on the same vhost (ties resolve by id)", norm.Priority, r.ID))
					}
				}
				for _, r := range added {
					if r.Priority == norm.Priority && vhostsOverlap(r.Scope.Vhosts, norm.Scope.Vhosts) {
						item.Warnings = append(item.Warnings, fmt.Sprintf("priority %d is also used by another rule of this file on the same vhost (ties resolve by id, which is random)", norm.Priority))
						break
					}
				}
				added = append(added, norm)
			}
		}
		switch item.Status {
		case "add":
			res.Add++
		case "duplicate":
			res.Duplicates++
		default:
			res.Invalid++
		}
		res.Items = append(res.Items, item)
	}
	if res.Add > 0 && len(existing)+res.Add > maxRulesGlobal {
		return res, fmt.Errorf("importing %d rule(s) would exceed the limit of %d rules", res.Add, maxRulesGlobal)
	}
	return res, nil
}

// decodeTrafficRulesDoc reads an export document. Each rule's match and scope
// are probed for unknown keys with decodeStoredRule, the store's own guard:
// the typed decode drops them silently, and a dropped selector widens the rule.
func decodeTrafficRulesDoc(r io.Reader) (TrafficRulesExportDoc, error) {
	var raw struct {
		TrafficRulesExportDoc
		Rules []json.RawMessage `json:"rules"`
	}
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return TrafficRulesExportDoc{}, err
	}
	doc := raw.TrafficRulesExportDoc
	doc.Rules = make([]TrafficRuleExport, 0, len(raw.Rules))
	for i, rr := range raw.Rules {
		var x TrafficRuleExport
		if err := json.Unmarshal(rr, &x); err != nil {
			return TrafficRulesExportDoc{}, fmt.Errorf("rule #%d: %w", i+1, err)
		}
		if _, unknown := decodeStoredRule(rr); unknown {
			x.unknownFields = true
		}
		doc.Rules = append(doc.Rules, x)
	}
	return doc, nil
}

func importNoteSuffix(doc TrafficRulesExportDoc) string {
	s := "imported"
	if n := strings.TrimSpace(doc.Node); n != "" {
		s += " from " + n
	}
	if !doc.ExportedAt.IsZero() {
		s += " " + doc.ExportedAt.UTC().Format("2006-01-02")
	}
	return s
}

// withImportNote appends "(imported from <node> <date>)" when it fits the
// note limit; otherwise the original note is kept unchanged.
func withImportNote(note, origin string) string {
	note = strings.TrimSpace(note)
	out := "(" + origin + ")"
	if note != "" {
		out = note + " " + out
	}
	if len(out) > maxRuleNoteLen {
		return note
	}
	return out
}

// errRulesChanged: an identical rule appeared between the import's plan and
// its write (another import ran meanwhile). Nothing is written.
var errRulesChanged = errors.New("an identical rule was added meanwhile (another import?); nothing was imported, preview again")

// AddMany adds rules atomically: all are normalized first, then stored and
// saved once. One failure adds nothing.
func (s *trafficRuleStore) AddMany(in []TrafficRule) ([]TrafficRule, error) {
	norms := make([]TrafficRule, 0, len(in))
	for _, r := range in {
		r.Unsupported = false
		r.ID = ""
		n, err := normalizeTrafficRule(r, true)
		if err != nil {
			return nil, err
		}
		norms = append(norms, n)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rules)+len(norms) > maxRulesGlobal {
		return nil, fmt.Errorf("too many rules (max %d)", maxRulesGlobal)
	}
	// The import planned its duplicates on a snapshot; a concurrent import
	// of the same file must not add them twice.
	have := map[string]bool{}
	for _, r := range s.rules {
		if !r.Unsupported {
			have[trafficRuleKey(r)] = true
		}
	}
	for _, n := range norms {
		if _, exists := s.rules[n.ID]; exists {
			return nil, errors.New("rule id already exists")
		}
		if have[trafficRuleKey(n)] {
			return nil, errRulesChanged
		}
	}
	for _, n := range norms {
		s.rules[n.ID] = n
	}
	s.recountLocked()
	if err := s.saveLocked(); err != nil {
		for _, n := range norms {
			delete(s.rules, n.ID)
		}
		s.recountLocked()
		return nil, err
	}
	return norms, nil
}

func (e *Engine) TrafficRuleAddMany(rules []TrafficRule) ([]TrafficRule, error) {
	if e == nil || e.trafficRules == nil {
		return nil, fmt.Errorf("traffic rules store unavailable")
	}
	return e.trafficRules.AddMany(rules)
}

func nodeHostname() string {
	h, _ := os.Hostname()
	return strings.TrimSpace(h)
}

// GET /api/v1/webdet/rules/export[?vhost=a&vhost=b]
// Scoped tokens export only the rules they can list.
func (e *Engine) handleWebdetRulesExport(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "engine unavailable"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var vhosts []string
	for _, v := range r.URL.Query()["vhost"] {
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				vhosts = append(vhosts, h)
			}
		}
	}
	rows := scopeFilterRules(e.TrafficRuleList(), r)
	if scope := vhostScopeFromContext(r.Context()); scope != nil {
		// A rule the operator shares with other tenants' vhosts is listed
		// for this tenant, but its file must carry only the tenant's own
		// vhosts: it would leak the others, and could not be imported back
		// by the same tenant (import checks every vhost).
		for i := range rows {
			own := make([]string, 0, len(rows[i].Scope.Vhosts))
			for _, h := range rows[i].Scope.Vhosts {
				if vhostAllowed(strings.ToLower(h), scope) {
					own = append(own, h)
				}
			}
			rows[i].Scope.Vhosts = own
		}
	}
	writeJSON(w, http.StatusOK, exportTrafficRules(rows, vhosts, nodeHostname(), time.Now()))
}

// POST /api/v1/webdet/rules/import[?dry_run=1][&disabled=1]
// Every rule must be in the caller's scope (as /rules/add); all-or-nothing.
func (e *Engine) handleWebdetRulesImport(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, TrafficRuleImportResult{Error: "engine unavailable"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, TrafficRuleImportResult{Error: "method not allowed"})
		return
	}
	q := r.URL.Query()
	dryRun := truthyParam(q.Get("dry_run"))
	disabled := truthyParam(q.Get("disabled"))

	doc, err := decodeTrafficRulesDoc(http.MaxBytesReader(w, r.Body, maxRuleImportBodyBytes))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, TrafficRuleImportResult{DryRun: dryRun, Error: "invalid json: " + err.Error()})
		return
	}
	inScope := func(v []string) bool { return scopeAllowsVhosts(r, v) }
	plan, err := planTrafficRuleImport(e.TrafficRuleList(), doc, disabled, inScope)
	plan.DryRun = dryRun
	if err != nil {
		plan.Error = err.Error()
		writeJSON(w, http.StatusBadRequest, plan)
		return
	}
	if plan.Invalid > 0 {
		status := http.StatusBadRequest
		if plan.Invalid == plan.outOfScope {
			status = http.StatusForbidden // as /rules/add for a vhost outside the token
		}
		if dryRun {
			plan.Error = fmt.Sprintf("%d rule(s) are invalid; nothing can be imported", plan.Invalid)
		} else {
			plan.Error = fmt.Sprintf("%d rule(s) are invalid; nothing was imported", plan.Invalid)
		}
		writeJSON(w, status, plan)
		return
	}
	if dryRun || plan.Add == 0 {
		writeJSON(w, http.StatusOK, plan)
		return
	}
	toAdd := make([]TrafficRule, 0, plan.Add)
	for _, it := range plan.Items {
		if it.Status == "add" {
			toAdd = append(toAdd, it.Rule)
		}
	}
	added, err := e.TrafficRuleAddMany(toAdd)
	if err != nil {
		plan.Error = err.Error()
		status := http.StatusBadRequest
		if errors.Is(err, errRulesChanged) {
			status = http.StatusConflict
		}
		writeJSON(w, status, plan)
		return
	}
	k := 0
	for i := range plan.Items {
		if plan.Items[i].Status == "add" && k < len(added) {
			plan.Items[i].Rule = added[k]
			plan.Added = append(plan.Added, added[k].ID)
			k++
		}
	}
	writeJSON(w, http.StatusOK, plan)
}

func truthyParam(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
