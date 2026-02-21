package vhostmap

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type Config struct {
	Enable    bool
	WritePath string        // required
	TTL       time.Duration // default 10m if zero
	VarName   string        // default origin_http_ip
	Source    string        // optional override; default auto-detect
	DefaultIP string        // optional override; default auto-detect
	ReloadCmd string        // default: systemctl reload openresty
}

type Logger interface {
	Logf(format string, args ...any)
}

func Run(ctx context.Context, cfg Config, log Logger) error {
	if !cfg.Enable {
		return nil
	}
	if cfg.WritePath == "" {
		return fmt.Errorf("vhostmap: WritePath is required")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	if cfg.VarName == "" {
		cfg.VarName = "origin_http_ip"
	}
	if cfg.ReloadCmd == "" {
		cfg.ReloadCmd = "systemctl reload openresty"
	}

	apply := func() {
		res, err := BuildNginxMap(BuildOptions{
			SourcePath: cfg.Source,
			VarName:    cfg.VarName,
			DefaultIP:  cfg.DefaultIP,
		})
		if err != nil {
			log.Logf("[vhostmap] build error: %v", err)
			return
		}
		changed, err := writeIfChanged(cfg.WritePath, res.Content)
		if err != nil {
			log.Logf("[vhostmap] write error: %v", err)
			return
		}
		if !changed {
			return
		}
		if err := reload(cfg.ReloadCmd); err != nil {
			log.Logf("[vhostmap] reload error: %v", err)
			return
		}
		log.Logf("[vhostmap] updated provider=%s default=%s entries=%d write=%s",
			res.Provider, res.DefaultIP, res.EntryCount, cfg.WritePath)
	}

	// initial apply
	apply()

	t := time.NewTicker(cfg.TTL)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			apply()
		}
	}
}

func writeIfChanged(path string, content []byte) (bool, error) {
	prev, _ := os.ReadFile(path)
	if bytes.Equal(prev, content) {
		return false, nil
	}
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, content, 0644); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}

func reload(cmdStr string) error {
	cmd := exec.Command("sh", "-c", cmdStr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
