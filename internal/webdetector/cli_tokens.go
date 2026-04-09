// internal/webdetector/cli_tokens.go
package webdetector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"cfm/internal/clihttp"
)

func runTokensWebTop(baseURL string, args []string) error {
	if len(args) == 0 || args[0] == "list" {
		return runTokensList(baseURL)
	}
	switch args[0] {
	case "create":
		return runTokensCreate(baseURL, args[1:])
	case "revoke":
		return runTokensRevoke(baseURL, args[1:])
	case "me":
		return runTokensMe(baseURL)
	default:
		return fmt.Errorf("unknown tokens subcommand %q\nusage: cfm webtop tokens [list|create|revoke|me]", args[0])
	}
}

// ── list ──────────────────────────────────────────────────────────────────────

type tokenInfoRow struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Vhosts    []string  `json:"vhosts"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Expired   bool      `json:"expired"`
}

func runTokensList(baseURL string) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/tokens/list"
	resp, err := clihttp.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("admin access required to list tokens")
	}

	var rows []tokenInfoRow
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Println("No scoped tokens issued.")
		return nil
	}

	fmt.Printf("%-14s %-24s %-8s %-40s %s\n", "ID", "LABEL", "ROLE", "VHOSTS", "EXPIRES")
	fmt.Printf("%-14s %-24s %-8s %-40s %s\n",
		strings.Repeat("-", 14), strings.Repeat("-", 24), "--------",
		strings.Repeat("-", 40), "-------------------")
	for _, row := range rows {
		label := row.Label
		if label == "" {
			label = "(unlabelled)"
		}
		vhosts := strings.Join(row.Vhosts, ",")
		if len(vhosts) > 38 {
			vhosts = vhosts[:35] + "..."
		}
		exp := row.ExpiresAt.Local().Format("2006-01-02 15:04:05")
		if row.Expired {
			exp += " [EXPIRED]"
		}
		fmt.Printf("%-14s %-24s %-8s %-40s %s\n", row.ID, label, row.Role, vhosts, exp)
	}
	return nil
}

// ── create ────────────────────────────────────────────────────────────────────

func runTokensCreate(baseURL string, args []string) error {
	var vhosts, label, ttl, role string
	role = "viewer"
	ttl = "8760h"

	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--vhosts" || args[i] == "-v":
			if i+1 >= len(args) {
				return fmt.Errorf("--vhosts requires a value")
			}
			vhosts = args[i+1]
			i++
		case args[i] == "--label" || args[i] == "-l":
			if i+1 >= len(args) {
				return fmt.Errorf("--label requires a value")
			}
			label = args[i+1]
			i++
		case args[i] == "--ttl" || args[i] == "-t":
			if i+1 >= len(args) {
				return fmt.Errorf("--ttl requires a value")
			}
			ttl = args[i+1]
			i++
		case args[i] == "--role" || args[i] == "-r":
			if i+1 >= len(args) {
				return fmt.Errorf("--role requires a value")
			}
			role = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--vhosts="):
			vhosts = strings.TrimPrefix(args[i], "--vhosts=")
		case strings.HasPrefix(args[i], "--label="):
			label = strings.TrimPrefix(args[i], "--label=")
		case strings.HasPrefix(args[i], "--ttl="):
			ttl = strings.TrimPrefix(args[i], "--ttl=")
		case strings.HasPrefix(args[i], "--role="):
			role = strings.TrimPrefix(args[i], "--role=")
		}
	}

	if vhosts == "" {
		return fmt.Errorf("--vhosts is required, e.g. --vhosts mysite.com,other.com")
	}

	vhostList := strings.Split(vhosts, ",")
	for i, v := range vhostList {
		vhostList[i] = strings.TrimSpace(v)
	}

	payload := map[string]interface{}{
		"vhosts": vhostList,
		"role":   role,
		"ttl":    ttl,
		"label":  label,
	}

	u := strings.TrimRight(baseURL, "/") + "/api/v1/auth/token"
	resp, err := tokensPostJSON(u, payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if errMsg, ok := result["error"].(string); ok {
		return fmt.Errorf("create error: %s", errMsg)
	}

	fmt.Printf("✓ Token created\n")
	fmt.Printf("  ID      : %s\n", result["id"])
	fmt.Printf("  Token   : %s\n", result["token"])
	fmt.Printf("  Label   : %s\n", result["label"])
	fmt.Printf("  Role    : %s\n", result["role"])
	if vhs, ok := result["vhosts"].([]interface{}); ok {
		parts := make([]string, len(vhs))
		for i, v := range vhs {
			parts[i] = fmt.Sprintf("%v", v)
		}
		fmt.Printf("  Vhosts  : %s\n", strings.Join(parts, ", "))
	}
	fmt.Printf("  Expires : %s\n", result["expires_at"])
	return nil
}

// ── revoke ────────────────────────────────────────────────────────────────────

func runTokensRevoke(baseURL string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: cfm webtop tokens revoke <id>")
	}
	id := args[0]

	u := strings.TrimRight(baseURL, "/") + "/api/v1/tokens/revoke"
	resp, err := tokensPostJSON(u, map[string]string{"id": id})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("admin access required to revoke tokens")
	}

	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if errMsg, ok := result["error"].(string); ok {
		return fmt.Errorf("revoke error: %s", errMsg)
	}
	fmt.Printf("✓ Token %s revoked\n", id)
	return nil
}

// ── me ────────────────────────────────────────────────────────────────────────

func runTokensMe(baseURL string) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/tokens/me"
	resp, err := clihttp.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if errMsg, ok := result["error"].(string); ok {
		return fmt.Errorf("error: %s", errMsg)
	}

	scoped, _ := result["scoped"].(bool)
	if !scoped {
		fmt.Println("Authenticated as: admin (unrestricted)")
		return nil
	}
	fmt.Printf("Token ID : %s\n", result["id"])
	fmt.Printf("Label    : %s\n", result["label"])
	fmt.Printf("Role     : %s\n", result["role"])
	if vhs, ok := result["vhosts"].([]interface{}); ok {
		parts := make([]string, len(vhs))
		for i, v := range vhs {
			parts[i] = fmt.Sprintf("%v", v)
		}
		fmt.Printf("Vhosts   : %s\n", strings.Join(parts, ", "))
	}
	fmt.Printf("Expires  : %s\n", result["expires_at"])
	return nil
}

// ── internal POST helper — uses clihttp so Bearer token is injected ───────────

func tokensPostJSON(rawURL string, payload interface{}) (*http.Response, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return clihttp.Post(rawURL, "application/json", bytes.NewReader(data))
}
