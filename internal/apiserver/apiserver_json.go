// internal/apiserver/apiserver_json.go
package apiserver

import "encoding/json"

// mustJSON marshals v to a JSON byte slice.
// On error it returns a safe fallback so handlers never panic.
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"error":"json marshal failed"}`)
	}
	return b
}
