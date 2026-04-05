package webdetector

import (
	"encoding/json"
	"net/http"
	"strings"
)

type trafficRuleListResponse struct {
	Rows []TrafficRule `json:"rows"`
}

type trafficRuleResultResponse struct {
	Rule  TrafficRule `json:"rule,omitempty"`
	Error string      `json:"error,omitempty"`
}

func (e *Engine) handleWebdetRulesList(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusOK, trafficRuleListResponse{Rows: nil})
		return
	}
	writeJSON(w, http.StatusOK, trafficRuleListResponse{Rows: e.TrafficRuleList()})
}

func (e *Engine) handleWebdetRulesGet(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusNotFound, trafficRuleResultResponse{Error: "engine unavailable"})
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, trafficRuleResultResponse{Error: "missing id"})
		return
	}
	rule, ok := e.TrafficRuleGet(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, trafficRuleResultResponse{Error: "rule not found"})
		return
	}
	writeJSON(w, http.StatusOK, trafficRuleResultResponse{Rule: rule})
}

func (e *Engine) handleWebdetRulesAdd(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, trafficRuleResultResponse{Error: "engine unavailable"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, trafficRuleResultResponse{Error: "method not allowed"})
		return
	}
	var req TrafficRule
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, trafficRuleResultResponse{Error: "invalid json"})
		return
	}
	rule, err := e.TrafficRuleAdd(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, trafficRuleResultResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, trafficRuleResultResponse{Rule: rule})
}

func (e *Engine) handleWebdetRulesUpdate(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, trafficRuleResultResponse{Error: "engine unavailable"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, trafficRuleResultResponse{Error: "method not allowed"})
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, trafficRuleResultResponse{Error: "missing id"})
		return
	}
	var req TrafficRule
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, trafficRuleResultResponse{Error: "invalid json"})
		return
	}
	rule, err := e.TrafficRuleUpdate(id, req)
	if err != nil {
		code := http.StatusBadRequest
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			code = http.StatusNotFound
		}
		writeJSON(w, code, trafficRuleResultResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, trafficRuleResultResponse{Rule: rule})
}

func (e *Engine) handleWebdetRulesRemove(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "engine unavailable"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing id"})
		return
	}
	if !e.TrafficRuleRemove(id) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (e *Engine) handleWebdetRulesSimulate(w http.ResponseWriter, r *http.Request) {
	if e == nil || e.trafficRules == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "traffic rules store unavailable"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req TrafficRuleEvalInput
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if strings.TrimSpace(req.Host) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}
	res := e.trafficRules.Simulate(req)
	writeJSON(w, http.StatusOK, res)
}
