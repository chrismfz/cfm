package webdetector

import (
	"net/http"
	"strings"
)

func readExcludeParams(r *http.Request) (string, string) {
	typ := strings.TrimSpace(r.URL.Query().Get("type"))
	if typ == "" {
		typ = "host"
	}
	value := strings.TrimSpace(r.URL.Query().Get("value"))
	return typ, value
}

func (e *Engine) handleChallengeExcludeList(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusOK, []excludeEntry{})
		return
	}
	writeJSON(w, http.StatusOK, e.ChallengeExcludeList())
}

func (e *Engine) handleChallengeExcludeAdd(w http.ResponseWriter, r *http.Request) {
	typ, value := readExcludeParams(r)
	if strings.TrimSpace(value) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing value"})
		return
	}
	if ok := e.ChallengeExcludeAdd(typ, value); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to add exclude (invalid or exists)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (e *Engine) handleChallengeExcludeRemove(w http.ResponseWriter, r *http.Request) {
	typ, value := readExcludeParams(r)
	if strings.TrimSpace(value) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing value"})
		return
	}
	if ok := e.ChallengeExcludeRemove(typ, value); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to remove exclude (invalid or not found)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (e *Engine) handleWAFExcludeList(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusOK, []excludeEntry{})
		return
	}
	writeJSON(w, http.StatusOK, e.WAFExcludeList())
}

func (e *Engine) handleWAFExcludeAdd(w http.ResponseWriter, r *http.Request) {
	typ, value := readExcludeParams(r)
	if strings.TrimSpace(value) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing value"})
		return
	}
	if ok := e.WAFExcludeAdd(typ, value); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to add exclude (invalid or exists)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (e *Engine) handleWAFExcludeRemove(w http.ResponseWriter, r *http.Request) {
	typ, value := readExcludeParams(r)
	if strings.TrimSpace(value) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing value"})
		return
	}
	if ok := e.WAFExcludeRemove(typ, value); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to remove exclude (invalid or not found)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
