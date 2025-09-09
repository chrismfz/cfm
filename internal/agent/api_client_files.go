package agent

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
	"io"
)

type FileUpdatesRequest struct {
    Files []string `json:"files"`
}
type ConfigUpdate struct {
    TargetPath        string  `json:"target_path"`
    Content           string  `json:"content"`
    Hash              string  `json:"hash"`
    PostUpdateCommand *string `json:"post_update_command"`
}

func (c *APIClient) GetUpdates(paths []string) ([]ConfigUpdate, error) {
    if len(paths) == 0 { return nil, nil }
    u := strings.TrimRight(c.BaseURL, "/") + "/api/agent/get-updates"
    body, _ := json.Marshal(FileUpdatesRequest{Files: paths})
    req, _ := http.NewRequest("POST", u, bytes.NewReader(body))
    req.Header.Set("Token", c.Token)
    req.Header.Set("Accept", "application/json")
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Agent-Version", "CFM-Agent-Go")
    resp, err := c.http().Do(req)
    if err != nil { return nil, err }
    defer resp.Body.Close()
    if resp.StatusCode >= 300 { return nil, fmt.Errorf("http %d", resp.StatusCode) }
    var out struct{ Configs []ConfigUpdate `json:"configs"` }
    if err := json.NewDecoder(resp.Body).Decode(&out); err != nil { return nil, err }
    return out.Configs, nil
}



func (c *APIClient) ListTrackedFiles() (map[string]string, error) {
	u := strings.TrimRight(c.BaseURL, "/") + "/api/agent/list-files"
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Token", c.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Agent-Version", "CFM-Agent-Go")

	resp, err := c.http().Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(b))
	}

	// 1) Προσπάθησε ως object/map (ισχύει στο web app)
	type respMap struct {
		Tracked map[string]string `json:"tracked_files"`
	}
	var r1 respMap
	if err := json.Unmarshal(b, &r1); err == nil {
		// even if empty map, this is valid schema
		if r1.Tracked == nil {
			return map[string]string{}, nil
		}
		return r1.Tracked, nil
	}

	// 2) Fallback: array of objects
	type fileObj struct {
		Path       string  `json:"path"`
		TargetPath string  `json:"target_path"`
		Hash       string  `json:"hash"`
		SHA1       string  `json:"sha1"`
	}
	var r2 struct {
		Tracked []fileObj `json:"tracked_files"`
	}
	if err := json.Unmarshal(b, &r2); err == nil {
		out := make(map[string]string, len(r2.Tracked))
		for _, it := range r2.Tracked {
			p := it.Path
			if p == "" { p = it.TargetPath }
			h := it.Hash
			if h == "" { h = it.SHA1 }
			if p != "" && h != "" {
				out[p] = h
			}
		}
		return out, nil // even if empty
	}

	// 3) Fallback: array of pairs
	var r3 struct {
		Tracked [][]string `json:"tracked_files"`
	}
	if err := json.Unmarshal(b, &r3); err == nil {
		out := make(map[string]string, len(r3.Tracked))
		for _, pair := range r3.Tracked {
			if len(pair) >= 2 && pair[0] != "" && pair[1] != "" {
				out[pair[0]] = pair[1]
			}
		}
		return out, nil // even if empty
	}

	return nil, fmt.Errorf("unexpected tracked_files schema")
}
