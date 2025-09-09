package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type ExecItem struct {
	Command string `json:"command"`
}

func (c *APIClient) FetchExecutionTargets() ([]ExecItem, error) {
	u := strings.TrimRight(c.BaseURL, "/") + "/api/agent/execution-check"
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Token", c.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Agent-Version", "CFM-Agent-Go")

	resp, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(b))
	}

	var out struct {
		Executions []ExecItem `json:"executions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Executions, nil
}
