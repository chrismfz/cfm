package webdetector

import (
    "net/http"
    "strconv"
)

func (e *Engine) handleChallengeSummary(w http.ResponseWriter, r *http.Request) {
    if e == nil || e.chalAPI == nil {
        writeJSON(w, http.StatusOK, ChallengeSummary{})
        return
    }
    writeJSON(w, http.StatusOK, e.chalAPI.Summary())
}

func (e *Engine) handleChallengeVhosts(w http.ResponseWriter, r *http.Request) {
    status := r.URL.Query().Get("status") // active|inactive|all
    mode := r.URL.Query().Get("mode")     // auto|manual|all
    limit := 200
    if v := r.URL.Query().Get("limit"); v != "" {
        if n, err := strconv.Atoi(v); err == nil && n > 0 {
            limit = n
        }
    }
    if e == nil || e.chalAPI == nil {
        writeJSON(w, http.StatusOK, []ChallengeVhostState{})
        return
    }
    writeJSON(w, http.StatusOK, e.chalAPI.ListVhosts(status, mode, limit))
}

func (e *Engine) handleChallengeVhost(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    if host == "" {
        writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
        return
    }
    if e == nil || e.chalAPI == nil {
        writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
        return
    }
    v, ok := e.chalAPI.GetVhost(host)
    if !ok {
        writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
        return
    }
    writeJSON(w, http.StatusOK, v)
}

func (e *Engine) handleChallengeIPs(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    state := r.URL.Query().Get("state") // challenge|block|ok|all
    limit := 500
    if v := r.URL.Query().Get("limit"); v != "" {
        if n, err := strconv.Atoi(v); err == nil && n > 0 {
            limit = n
        }
    }
    if e == nil || e.chalAPI == nil {
       writeJSON(w, http.StatusOK, []ChallengeIPState{})
        return
    }
    writeJSON(w, http.StatusOK, e.chalAPI.ListIPs(host, state, limit))
}

func (e *Engine) handleChallengeIP(w http.ResponseWriter, r *http.Request) {
    ip := r.URL.Query().Get("ip")
    if ip == "" {
        writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing ip"})
        return
    }
    if e == nil || e.chalAPI == nil {
        writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
        return
    }
    v, ok := e.chalAPI.GetIP(ip)
    if !ok {
        writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
        return
    }
    writeJSON(w, http.StatusOK, v)
}

func (e *Engine) handleChallengeEvents(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    ip := r.URL.Query().Get("ip")
    rule := r.URL.Query().Get("rule")
    typ := r.URL.Query().Get("type")
    limit := 200
    if v := r.URL.Query().Get("limit"); v != "" {
        if n, err := strconv.Atoi(v); err == nil && n > 0 {
            limit = n
        }
    }
    if e == nil || e.chalAPI == nil {
        writeJSON(w, http.StatusOK, []ChallengeEvent{})
        return
    }
    writeJSON(w, http.StatusOK, e.chalAPI.Events(host, ip, rule, typ, limit))
}
