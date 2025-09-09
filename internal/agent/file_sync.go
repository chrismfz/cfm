package agent

import (
    "context"
    "crypto/sha1"
    "encoding/hex"
    "io"
    "os"
    "path/filepath"
    "strings"

    "cfm/internal/logging"
)

func sha1File(p string) string {
    f, err := os.Open(p)
    if err != nil { return "" }
    defer f.Close()
    h := sha1.New()
    if _, err := io.Copy(h, f); err != nil { return "" }
    return hex.EncodeToString(h.Sum(nil))
}

func atomicWrite(path string, data []byte, perm os.FileMode) error {
    dir := filepath.Dir(path)
    base := filepath.Base(path)
    tmp := filepath.Join(dir, "."+base+".tmp")
    if err := os.WriteFile(tmp, data, perm); err != nil { return err }
    return os.Rename(tmp, path)
}

func (r *Runner) syncConfigs(ctx context.Context) {
    cfg := r.cur()
    if cfg.BaseURL == "" || cfg.Token == "" { return }
    api := &APIClient{BaseURL: cfg.BaseURL, Token: cfg.Token, HTTP: r.client}


tracked, err := api.ListTrackedFiles()
if err != nil {
    logging.Logf("[files] list failed: %v", err)
    return
}
if len(tracked) == 0 {
    logging.Logf("[files] no tracked files (nothing to do)")
    return
}

    // figure out diffs
    var need []string
    for path, remoteHash := range tracked {
        if local := sha1File(path); !strings.EqualFold(local, remoteHash) {
            need = append(need, path)
        }
    }
    if len(need) == 0 { return }

    updates, err := api.GetUpdates(need)
    if err != nil { logging.Logf("[files] updates failed: %v", err); return }

    // apply + dedup post-update commands
    dedup := map[string]struct{}{}
    var cmds []string

    for _, u := range updates {
        // only write if hash differs (double check)
        if local := sha1File(u.TargetPath); strings.EqualFold(local, u.Hash) {
            continue
        }
        if err := os.MkdirAll(filepath.Dir(u.TargetPath), 0755); err != nil {
            logging.Logf("[files] mkdir %s: %v", filepath.Dir(u.TargetPath), err)
            continue
        }
        if err := atomicWrite(u.TargetPath, []byte(u.Content), 0644); err != nil {
            logging.Logf("[files] write %s: %v", u.TargetPath, err)
            continue
        }
        logging.Logf("[files] updated %s", u.TargetPath)
        if u.PostUpdateCommand != nil && *u.PostUpdateCommand != "" {
            if _, ok := dedup[*u.PostUpdateCommand]; !ok {
                dedup[*u.PostUpdateCommand] = struct{}{}
                cmds = append(cmds, *u.PostUpdateCommand)
            }
        }
    }

    // run each command once
    for _, c := range cmds {
        _ = runCommand(ctx, c) // uses same allow-list
    }
}
