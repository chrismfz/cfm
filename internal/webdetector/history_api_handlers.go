package webdetector

import (
	"net/http"
	"strconv"
	"strings"
)

func (e *Engine) handleHistoryEvents(w http.ResponseWriter, r *http.Request) {
	if e == nil || e.history == nil {
		writeJSON(w, http.StatusOK, []HistoryEvent{})
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	rows, err := e.history.QueryEvents(q.Get("host"), q.Get("ip"), q.Get("type"), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"rows": rows})
}

func (e *Engine) handleHistorySummary(w http.ResponseWriter, r *http.Request) {
	if e == nil || e.history == nil {
		writeJSON(w, http.StatusOK, HistorySummary{})
		return
	}
	q := r.URL.Query()
	hours, _ := strconv.Atoi(q.Get("hours"))
	res, err := e.history.Summarize(q.Get("host"), q.Get("ip"), hours)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (e *Engine) handleHistoryChallengeOutcomes(w http.ResponseWriter, r *http.Request) {
	if e == nil || e.history == nil {
		writeJSON(w, http.StatusOK, map[string][]HistoryEvent{"solved": {}, "unsolved": {}})
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	issued, err := e.history.QueryEvents(q.Get("host"), q.Get("ip"), "challenge_issued", limit*4)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	solvedRows, _ := e.history.QueryEvents(q.Get("host"), q.Get("ip"), "challenge_solved", limit*4)
	solvedSet := make(map[string]struct{}, len(solvedRows))
	for _, ev := range solvedRows {
		k := strings.TrimSpace(ev.IP) + "|" + cleanHost(ev.Host)
		solvedSet[k] = struct{}{}
	}
	solved := make([]HistoryEvent, 0, limit)
	unsolved := make([]HistoryEvent, 0, limit)
	for _, ev := range issued {
		k := strings.TrimSpace(ev.IP) + "|" + cleanHost(ev.Host)
		if _, ok := solvedSet[k]; ok {
			if len(solved) < limit {
				solved = append(solved, ev)
			}
		} else if len(unsolved) < limit {
			unsolved = append(unsolved, ev)
		}
		if len(solved) >= limit && len(unsolved) >= limit {
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"solved": solved, "unsolved": unsolved})
}

func (e *Engine) handleHistoryPrune(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if e == nil || e.history == nil {
		writeJSON(w, http.StatusOK, map[string]int64{"rows_deleted": 0})
		return
	}
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 {
		days = 30
	}
	n, err := e.history.Prune(days)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"rows_deleted": n, "days": days})
}

func (e *Engine) handleHistoryTruncate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if r.URL.Query().Get("confirm") != "yes" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing confirm=yes"})
		return
	}
	if e == nil || e.history == nil {
		writeJSON(w, http.StatusOK, map[string]int64{"rows_deleted": 0})
		return
	}
	n, err := e.history.Truncate()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"rows_deleted": n})
}

func (e *Engine) handleHistoryStats(w http.ResponseWriter, r *http.Request) {
	if e == nil || e.history == nil {
		writeJSON(w, http.StatusOK, HistoryStats{})
		return
	}
	st, err := e.history.Stats()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, st)
}
