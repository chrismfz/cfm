package agent

import (
    "context"
    "errors"
    "os/exec"
    "regexp"
    "strings"
    "time"

    "cfm/internal/logging"
)

var dangerous = regexp.MustCompile("[;&|><\x60$()]")
var allowedPrefixes = regexp.MustCompile("^[[:space:]]*(csf|imunify[0-9]*-agent|systemctl|nixpal|cfm|/scripts/).+")


func isCommandAllowed(cmd string) bool {
    if dangerous.MatchString(cmd) { return false }
    return allowedPrefixes.MatchString(cmd)
}

func runCommand(ctx context.Context, command string) error {
    if !isCommandAllowed(command) {
        return errors.New("command not allowed")
    }
    // split safely: first token binary, the rest args (simple, not shell)
    parts := strings.Fields(command)
    if len(parts) == 0 { return errors.New("empty command") }
    name, args := parts[0], parts[1:]

    c := exec.CommandContext(ctx, name, args...)
    out, err := c.CombinedOutput()
    if err != nil {
        logging.LogfAPI("[exec] %s FAILED: %v (out: %s)", command, err, strings.TrimSpace(string(out)))
        return err
    }
    if len(out) > 0 {
        logging.LogfAPI("[exec] %s OK: %s", command, strings.TrimSpace(string(out)))
    } else {
        logging.LogfAPI("[exec] %s OK", command)
    }
    return nil
}

// Καλείται από τον runner
func (r *Runner) pollExecutions(ctx context.Context) {
    cfg := r.cur()
    if cfg.BaseURL == "" || cfg.Token == "" { return }
    api := &APIClient{BaseURL: cfg.BaseURL, Token: cfg.Token, HTTP: r.client}
    items, err := api.FetchExecutionTargets()
    if err != nil { logging.LogfAPI("[exec] fetch failed: %v", err); return }
    for _, it := range items {
        // timeout ανά command (π.χ. 20s)
        cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
        _ = runCommand(cctx, it.Command)
        cancel()
    }
}
