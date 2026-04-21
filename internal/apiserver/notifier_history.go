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

	"cfm/internal/notify"
)

type notifierHistoryItem struct {
	Cursor  string         `json:"cursor"`
	Time    string         `json:"time"`
	Host    string         `json:"host,omitempty"`
	Kind    string         `json:"kind,omitempty"`
	SrcIP   string         `json:"srcip,omitempty"`
	Reason  string         `json:"reason,omitempty"`
	Channel string         `json:"channel,omitempty"`
	Status  string         `json:"status"`
	Error   string         `json:"error,omitempty"`
	Payload map[string]any `json:"payload"`
}

type notifierHistoryResponse struct {
	Rows       []notifierHistoryItem `json:"rows"`
	Limit      int                   `json:"limit"`
	HasMore    bool                  `json:"has_more"`
	NextCursor string                `json:"next_cursor,omitempty"`
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

	var before *notifierHistoryCursor
	if rawBefore := strings.TrimSpace(q.Get("before")); rawBefore != "" {
		parsed, err := decodeNotifierHistoryCursor(rawBefore)
		if err != nil {
			writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid before cursor"})
			return
		}
		before = &parsed
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
	for _, row := range rows {
		if before != nil && !notifierHistoryRowIsBefore(row, *before) {
			continue
		}
		item := rowToNotifierHistoryItem(row)
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

		if len(out) >= limit {
			hasMore = true
			break
		}
		out = append(out, item)
	}

	resp := notifierHistoryResponse{Rows: out, Limit: limit, HasMore: hasMore}
	if hasMore && len(out) > 0 {
		resp.NextCursor = out[len(out)-1].Cursor
	}
	writeNotifierJSON(w, http.StatusOK, resp)
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
		Cursor:  encodeNotifierHistoryCursor(notifierHistoryCursor{TSUnixNano: row.TSUnixNano, Offset: row.Offset}),
		Time:    time.Unix(0, row.TSUnixNano).UTC().Format(time.RFC3339Nano),
		Host:    strings.TrimSpace(toString(row.Raw["host"])),
		Kind:    strings.TrimSpace(toString(row.Raw["kind"])),
		SrcIP:   strings.TrimSpace(toString(row.Raw["srcip"])),
		Reason:  strings.TrimSpace(toString(row.Raw["reason"])),
		Channel: channel,
		Status:  status,
		Error:   errVal,
		Payload: payload,
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
