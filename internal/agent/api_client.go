package agent

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
//    "strconv"
    "strings"
    "time"

    "cfm/internal/reporting"
    "cfm/internal/logging"
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
    req, _ := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
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
    // Στέλνουμε reason ως comment/description· timestamp = now()
    p := url.Values{
        "ip":          {ip},
        "comment":     {reason},
        "description": {reason},
        "timestamp":   {time.Now().Format(time.RFC3339)},
    }
    logging.Logf("[api] → /api/blocklist/report ip=%s", ip)
    _, err := c.doPOST("/api/blocklist/report", p)
    if err != nil {
        logging.Logf("[api] report block FAILED ip=%s err=%v", ip, err)
        return err
    }
    logging.Logf("[api] ← report block OK ip=%s", ip)
    return nil
}


func (c *APIClient) ReportUnblock(ip, source, why string) error {
    p := url.Values{
        "ip":     {ip},
        "source": {source}, // "manual"
        "reason": {why},    // optional
    }
    logging.Logf("[api] → /api/blocklist/unblock ip=%s source=%s", ip, source)
    _, err := c.doPOST("/api/blocklist/unblock", p)
    if err != nil {
        logging.Logf("[api] report unblock FAILED ip=%s err=%v", ip, err)
        return err
    }
    logging.Logf("[api] ← report unblock OK ip=%s", ip)
    return nil
}





// Pending unblock flow ------------------------------------------------------

type PendingUnblock struct {
    ID int    `json:"id"`
    IP string `json:"ip"`
}


func (c *APIClient) FetchPendingUnblocks() ([]PendingUnblock, error) {
    u := strings.TrimRight(c.BaseURL, "/") + "/api/blocklist/pending-unblocks"
    req, _ := http.NewRequest("GET", u, nil)
    req.Header.Set("Token", c.Token)
    req.Header.Set("Accept", "application/json")
    req.Header.Set("X-Agent-Version", "CFM-Agent-Go")
    resp, err := c.http().Do(req)
    if err != nil { return nil, err }
    defer resp.Body.Close()
    if resp.StatusCode >= 300 {
        b, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(b))
    }
    var out struct {
        Pending []PendingUnblock `json:"pending_unblocks"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
        return nil, err
    }
    return out.Pending, nil
}


func (c *APIClient) ConfirmUnblock(id int, ip string, success bool) error {
    u := strings.TrimRight(c.BaseURL, "/") + "/api/blocklist/unblock-confirm"
    body := fmt.Sprintf(`{"id":%d,"ip":"%s","success":%t}`, id, ip, success)
    req, _ := http.NewRequest("POST", u, strings.NewReader(body))
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
