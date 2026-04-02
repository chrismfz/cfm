package agent

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strconv"
    "strings"
    "time"

    "cfm/internal/reporting"
    "cfm/internal/logging"

    "bytes"
    "context"
)

type APIClient struct {
    BaseURL string
    Token   string
    HTTP    *http.Client
}

func (c *APIClient) http() *http.Client {
    if c.HTTP != nil { return c.HTTP }
    return &http.Client{ Timeout: 10 * time.Second }
}

func (c *APIClient) doPOST(path string, form url.Values) ([]byte, error) {
    u := strings.TrimRight(c.BaseURL, "/") + path
    req, err := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
    if err != nil { return nil, fmt.Errorf("doPOST build request: %w", err) }
    req.Header.Set("Token", c.Token)
    req.Header.Set("Accept", "application/json")
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    req.Header.Set("X-Agent-Version", "CFM-Agent-Go")

    resp, err := c.http().Do(req)
    if err != nil { return nil, err }
    defer resp.Body.Close()
    b, _ := io.ReadAll(resp.Body)
    if resp.StatusCode >= 300 {
        return b, fmt.Errorf("http %d: %s", resp.StatusCode, string(b))
    }
    return b, nil
}

// Υλοποίηση του reporting.Reporter μέσα στο agent
var _ reporting.Reporter = (*APIClient)(nil)


func (c *APIClient) ReportBlock(ip, reason, source, mode string, ttlSec int) error {
    p := url.Values{
        "ip":          {ip},
        "comment":     {reason},
        "description": {reason},
        "timestamp":   {time.Now().Format(time.RFC3339)},
    }
    if ttlSec > 0 {
        p.Set("ttl", strconv.Itoa(ttlSec)) // e.g. 3600
    }
    logging.LogfAPI("[api] → /api/blocklist/report ip=%s ttl=%d", ip, ttlSec)
    _, err := c.doPOST("/api/blocklist/report", p)
    if err != nil {
        logging.LogfAPI("[api] report block FAILED ip=%s err=%v", ip, err)
        return err
    }
    logging.LogfAPI("[api] ← report block OK ip=%s ttl=%d", ip, ttlSec)
    return nil
}


func (c *APIClient) ReportUnblock(ip, source, why string) error {
    p := url.Values{
        "ip":     {ip},
        "source": {source}, // "manual"
        "reason": {why},    // optional
    }
    logging.LogfAPI("[api] → /api/blocklist/unblock ip=%s source=%s", ip, source)
    _, err := c.doPOST("/api/blocklist/unblock", p)
    if err != nil {
        logging.LogfAPI("[api] report unblock FAILED ip=%s err=%v", ip, err)
        return err
    }
    logging.LogfAPI("[api] ← report unblock OK ip=%s", ip)
    return nil
}





// Pending unblock flow ------------------------------------------------------

type PendingUnblock struct {
    ID int    `json:"id"`
    IP string `json:"ip"`
}



func (c *APIClient) FetchPendingUnblocks() ([]PendingUnblock, error) {
	u := strings.TrimRight(c.BaseURL, "/") + "/api/blocklist/pending-unblocks"
	//logging.LogfAPI("[api] → GET %s", u)

    req, err := http.NewRequest("GET", u, nil)
    if err != nil { return nil, fmt.Errorf("fetch pending unblocks build request: %w", err) }
    req.Header.Set("Token", c.Token)
    req.Header.Set("Accept", "application/json")
    req.Header.Set("X-Agent-Version", "CFM-Agent-Go")

    resp, err := c.http().Do(req)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(b))
	}

	var out struct {
		Pending []PendingUnblock `json:"pending_unblocks"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}

	//logging.LogfAPI("[api] ← pending_unblocks=%d", len(out.Pending))
	return out.Pending, nil
}


func (c *APIClient) ConfirmUnblock(id int, ip string, success bool) error {
    u := strings.TrimRight(c.BaseURL, "/") + "/api/blocklist/unblock-confirm"

    bodyBytes, _ := json.Marshal(map[string]any{"id": id, "ip": ip, "success": success})
    req, err := http.NewRequest("POST", u, bytes.NewReader(bodyBytes))
    if err != nil { return fmt.Errorf("confirm unblock build request: %w", err) }
    req.Header.Set("Token", c.Token)

    req.Header.Set("Accept", "application/json")
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Agent-Version", "CFM-Agent-Go")
    resp, err := c.http().Do(req)
    if err != nil { return err }
    defer resp.Body.Close()
    if resp.StatusCode >= 300 {
        b, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("http %d: %s", resp.StatusCode, string(b))
    }
    return nil
}



type HeartbeatRequest struct {
	DNATEnabled *bool `json:"dnat_enabled,omitempty"`
}

func (c *APIClient) SendHeartbeat(ctx context.Context, version, userAgent string, dnatEnabled *bool) error {
	u := strings.TrimRight(c.BaseURL, "/") + "/api/agent/heartbeat"

	body, err := json.Marshal(HeartbeatRequest{
		DNATEnabled: dnatEnabled,
	})
	if err != nil {
		return fmt.Errorf("marshal heartbeat: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Token", c.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	if version != "" {
		req.Header.Set("X-Agent-Version", version)
	}
	if userAgent != "" {
		req.Header.Set("agent", userAgent)
		req.Header.Set("version", version)
	}

	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("http %d: %s", resp.StatusCode, string(b))
	}

	return nil
}
