package apiserver

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"cfm/internal/logging"
	"cfm/internal/notify"
)

type notifierHistoryItem struct {
	Cursor        string         `json:"cursor"`
	Time          string         `json:"time"`
	Host          string         `json:"host,omitempty"`
	Kind          string         `json:"kind,omitempty"`
	SrcIP         string         `json:"srcip,omitempty"`
	Reason        string         `json:"reason,omitempty"`
	Channel       string         `json:"channel,omitempty"`
	Status        string         `json:"status"`
	Error         string         `json:"error,omitempty"`
	Latency       string         `json:"latency,omitempty"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	Payload       map[string]any `json:"payload"`
}

type notifierHistoryResponse struct {
	Rows          []notifierHistoryItem `json:"rows"`
	Limit         int                   `json:"limit"`
	HasMore       bool                  `json:"has_more"`
	NextCursor    string                `json:"next_cursor,omitempty"`
	TotalEstimate int                   `json:"total_estimate"`
}

type notifierHistoryCursor struct {
	TSUnixNano int64
	Offset     int
}

type notifierHistoryParsedRow struct {
	TSUnixNano int64
	Offset     int
	Raw        map[string]any
}

func handleNotifierHistory(w http.ResponseWriter, r *http.Request, cfgDir string) {
	if r.Method != http.MethodGet {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	q := r.URL.Query()
	limit := clampInt(q.Get("limit"), 50, 1, 500)
	queryText := strings.TrimSpace(q.Get("q"))
	srcIPFilter := strings.TrimSpace(q.Get("src_ip"))
	countryFilter := strings.TrimSpace(q.Get("country"))
	asnFilter := strings.TrimSpace(q.Get("asn"))
	ptrFilter := strings.TrimSpace(q.Get("ptr"))
	kindFilter := strings.TrimSpace(q.Get("kind"))
	channelFilter := strings.TrimSpace(q.Get("channel"))
	statusFilter := strings.ToLower(strings.TrimSpace(q.Get("status")))
	if statusFilter == "" {
		statusFilter = "all"
	}
	if statusFilter != "all" && statusFilter != "success" && statusFilter != "error" {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "status must be one of all, success, error"})
		return
	}

	fromTime, err := parseNotifierHistoryTime(strings.TrimSpace(q.Get("from")))
	if err != nil {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid from timestamp; expected RFC3339 or RFC3339Nano"})
		return
	}
	toTime, err := parseNotifierHistoryTime(strings.TrimSpace(q.Get("to")))
	if err != nil {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid to timestamp; expected RFC3339 or RFC3339Nano"})
		return
	}
	if !fromTime.IsZero() && !toTime.IsZero() && fromTime.After(toTime) {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "from must be <= to"})
		return
	}

	var cursor *notifierHistoryCursor
	rawCursor := strings.TrimSpace(q.Get("cursor"))
	if rawCursor == "" {
		rawCursor = strings.TrimSpace(q.Get("before"))
	}
	if rawCursor != "" {
		parsed, err := decodeNotifierHistoryCursor(rawCursor)
		if err != nil {
			writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid cursor"})
			return
		}
		cursor = &parsed
	}

	var since *notifierHistoryCursor
	if rawSince := strings.TrimSpace(q.Get("since")); rawSince != "" {
		parsed, err := decodeNotifierHistoryCursor(rawSince)
		if err != nil {
			writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid since cursor"})
			return
		}
		since = &parsed
	}

	adminCfg, _, err := notify.LoadAdminConfig(cfgDir)
	if err != nil {
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	path := strings.TrimSpace(adminCfg.Notifier.JSONLPath)
	if path == "" {
		path = "/var/lib/cfm/notify.log.jsonl"
	}

	rows, err := readNotifierHistoryRows(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeNotifierJSON(w, http.StatusOK, notifierHistoryResponse{Rows: []notifierHistoryItem{}, Limit: limit})
			return
		}
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": fmt.Sprintf("failed reading notifier history: %v", err)})
		return
	}

	out := make([]notifierHistoryItem, 0, limit)
	hasMore := false
	totalEstimate := 0
	for _, row := range rows {
		if cursor != nil && !notifierHistoryRowIsBefore(row, *cursor) {
			continue
		}
		if since != nil && !notifierHistoryRowIsAfter(row, *since) {
			continue
		}
		ts := time.Unix(0, row.TSUnixNano).UTC()
		if !fromTime.IsZero() && ts.Before(fromTime) {
			continue
		}
		if !toTime.IsZero() && ts.After(toTime) {
			continue
		}
		item := rowToNotifierHistoryItem(row)
		if srcIPFilter != "" && !strings.EqualFold(item.SrcIP, srcIPFilter) {
			continue
		}
		if countryFilter != "" && !strings.EqualFold(strings.TrimSpace(toString(row.Raw["country"])), countryFilter) {
			continue
		}
		if asnFilter != "" && !strings.EqualFold(strings.TrimSpace(toString(row.Raw["asn"])), asnFilter) {
			continue
		}
		if ptrFilter != "" && !strings.EqualFold(strings.TrimSpace(toString(row.Raw["ptr"])), ptrFilter) {
			continue
		}
		if kindFilter != "" && !strings.EqualFold(item.Kind, kindFilter) {
			continue
		}
		if channelFilter != "" {
			if !strings.EqualFold(item.Channel, channelFilter) && !containsFold(notifierRecordChannels(row.Raw), channelFilter) {
				continue
			}
		}
		if statusFilter != "all" && item.Status != statusFilter {
			continue
		}
		if queryText != "" && !notifierHistoryMatchesQuery(row.Raw, item, queryText) {
			continue
		}

		totalEstimate++

		if len(out) >= limit {
			hasMore = true
			break
		}
		out = append(out, item)
	}

	resp := notifierHistoryResponse{Rows: out, Limit: limit, HasMore: hasMore, TotalEstimate: totalEstimate}
	if hasMore && len(out) > 0 {
		resp.NextCursor = out[len(out)-1].Cursor
	}
	writeNotifierJSON(w, http.StatusOK, resp)
}

func handleNotifierHistoryTruncate(w http.ResponseWriter, r *http.Request, cfgDir string) {
	if r.Method != http.MethodPost {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		Confirmation string `json:"confirmation"`
		Token        string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		return
	}
	confirm := strings.ToUpper(strings.TrimSpace(req.Confirmation))
	if confirm == "" {
		confirm = strings.ToUpper(strings.TrimSpace(req.Token))
	}
	if confirm != "TRUNCATE" {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "confirmation token mismatch"})
		return
	}

	adminCfg, _, err := notify.LoadAdminConfig(cfgDir)
	if err != nil {
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	path := strings.TrimSpace(adminCfg.Notifier.JSONLPath)
	if path == "" {
		path = "/var/lib/cfm/notify.log.jsonl"
	}
	deletedCount, err := truncateNotifierHistoryFile(path)
	if err != nil {
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": fmt.Sprintf("truncate failed: %v", err)})
		return
	}

	at := time.Now().UTC()
	actor := notifierHistoryActor(r)
	logging.LogfAPI("[audit] event=notifier_history_truncate actor=%q src_ip=%s timestamp=%s deleted_count=%d path=%q",
		actor, realIPFromRequest(r), at.Format(time.RFC3339Nano), deletedCount, path)

	writeNotifierJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"deleted_count": deletedCount,
		"actor":         actor,
		"timestamp":     at.Format(time.RFC3339Nano),
	})
}

func truncateNotifierHistoryFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	deleted := 0
	s := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	s.Buffer(buf, 2*1024*1024)
	for s.Scan() {
		if strings.TrimSpace(s.Text()) != "" {
			deleted++
		}
	}
	if err := s.Err(); err != nil {
		return 0, err
	}
	if err := os.Truncate(path, 0); err != nil {
		return 0, err
	}
	return deleted, nil
}

func notifierHistoryActor(r *http.Request) string {
	if user, ok := authUserFromContext(r.Context()); ok {
		if name := strings.TrimSpace(user.Username); name != "" {
			return name
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Forwarded-User")); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get("X-CFM-Actor")); v != "" {
		return v
	}
	return "unknown"
}

func clampInt(raw string, def, min, max int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
		if n < min {
			return min
		}
		if n > max {
			return max
		}
		return n
	}
	return def
}

func notifierHistoryRowIsAfter(row notifierHistoryParsedRow, cursor notifierHistoryCursor) bool {
	if row.TSUnixNano > cursor.TSUnixNano {
		return true
	}
	if row.TSUnixNano < cursor.TSUnixNano {
		return false
	}
	return row.Offset > cursor.Offset
}

func readNotifierHistoryRows(path string) ([]notifierHistoryParsedRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rows := make([]notifierHistoryParsedRow, 0, 256)
	s := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	s.Buffer(buf, 2*1024*1024)
	offset := 0
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			offset++
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			offset++
			continue
		}
		ts := notifierRecordTime(raw)
		if ts.IsZero() {
			offset++
			continue
		}
		rows = append(rows, notifierHistoryParsedRow{
			TSUnixNano: ts.UTC().UnixNano(),
			Offset:     offset,
			Raw:        raw,
		})
		offset++
	}
	if err := s.Err(); err != nil {
		return nil, err
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].TSUnixNano == rows[j].TSUnixNano {
			return rows[i].Offset > rows[j].Offset
		}
		return rows[i].TSUnixNano > rows[j].TSUnixNano
	})
	return rows, nil
}

func rowToNotifierHistoryItem(row notifierHistoryParsedRow) notifierHistoryItem {
	status := "success"
	errVal := strings.TrimSpace(toString(row.Raw["err"]))
	statusRaw := strings.ToLower(strings.TrimSpace(toString(row.Raw["status"])))
	if statusRaw == "success" || statusRaw == "error" || statusRaw == "failure" {
		if statusRaw == "failure" {
			status = "error"
		} else {
			status = statusRaw
		}
	}
	if notifierRecordIsError(row.Raw) {
		status = "error"
	}
	channel := strings.TrimSpace(toString(row.Raw["channel"]))
	if channel == "" {
		if list := notifierRecordChannels(row.Raw); len(list) > 0 {
			channel = list[0]
		}
	}
	payload := cloneMap(row.Raw)
	return notifierHistoryItem{
		Cursor:        encodeNotifierHistoryCursor(notifierHistoryCursor{TSUnixNano: row.TSUnixNano, Offset: row.Offset}),
		Time:          time.Unix(0, row.TSUnixNano).UTC().Format(time.RFC3339Nano),
		Host:          strings.TrimSpace(toString(row.Raw["host"])),
		Kind:          strings.TrimSpace(toString(row.Raw["kind"])),
		SrcIP:         strings.TrimSpace(toString(row.Raw["srcip"])),
		Reason:        strings.TrimSpace(toString(row.Raw["reason"])),
		Channel:       channel,
		Status:        status,
		Error:         errVal,
		Latency:       strings.TrimSpace(toString(row.Raw["latency"])),
		CorrelationID: strings.TrimSpace(toString(row.Raw["correlation_id"])),
		Payload:       payload,
	}
}

func containsFold(values []string, want string) bool {
	for _, v := range values {
		if strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}

func notifierHistoryMatchesQuery(raw map[string]any, item notifierHistoryItem, query string) bool {
	needle := strings.ToLower(strings.TrimSpace(query))
	if needle == "" {
		return true
	}
	haystack := strings.ToLower(strings.Join([]string{
		item.SrcIP,
		strings.TrimSpace(toString(raw["country"])),
		strings.TrimSpace(toString(raw["asn"])),
		strings.TrimSpace(toString(raw["ptr"])),
		item.Reason,
		item.Kind,
	}, " "))
	return strings.Contains(haystack, needle)
}

func parseNotifierHistoryTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return ts.UTC(), nil
	}
	if ts, err := time.Parse(time.RFC3339, raw); err == nil {
		return ts.UTC(), nil
	}
	return time.Time{}, errors.New("invalid time format")
}

func notifierHistoryRowIsBefore(row notifierHistoryParsedRow, before notifierHistoryCursor) bool {
	if row.TSUnixNano < before.TSUnixNano {
		return true
	}
	if row.TSUnixNano > before.TSUnixNano {
		return false
	}
	return row.Offset < before.Offset
}

func encodeNotifierHistoryCursor(c notifierHistoryCursor) string {
	raw := fmt.Sprintf("%d:%d", c.TSUnixNano, c.Offset)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeNotifierHistoryCursor(raw string) (notifierHistoryCursor, error) {
	buf, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return notifierHistoryCursor{}, err
	}
	parts := strings.Split(string(buf), ":")
	if len(parts) != 2 {
		return notifierHistoryCursor{}, errors.New("invalid cursor")
	}
	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return notifierHistoryCursor{}, err
	}
	offset, err := strconv.Atoi(parts[1])
	if err != nil {
		return notifierHistoryCursor{}, err
	}
	return notifierHistoryCursor{TSUnixNano: ts, Offset: offset}, nil
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
