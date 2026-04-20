package apiserver

import (
	"context"
	"database/sql"
	"net"
	"strings"
	"time"

	cfgpkg "cfm/internal/config"
	"cfm/internal/firewall"
	"cfm/internal/logging"

	_ "modernc.org/sqlite"
)

const (
	authAutoblockReason     = "cfm_auth_brute"
	authAutoblockFailLimit  = 10
	authAutoblockWindow     = 10 * time.Minute
	authAutoblockPollEvery  = 2 * time.Second
	authAutoblockQueryBatch = 500
)

func startAuthAutoblock(ctx context.Context, cfg *cfgpkg.Config, be firewall.Backend) {
	if cfg == nil || be == nil || strings.TrimSpace(cfg.Debug.AuthDBPath) == "" {
		return
	}
	go runAuthAutoblock(ctx, cfg, be)
}

func runAuthAutoblock(ctx context.Context, cfg *cfgpkg.Config, be firewall.Backend) {
	db, err := sql.Open("sqlite", cfg.Debug.AuthDBPath)
	if err != nil {
		logging.LogfAPI("[apiserver][auth-autoblock] sqlite open failed: %v", err)
		return
	}
	defer db.Close()
	_, _ = db.Exec(`PRAGMA busy_timeout = 3000`)

	var lastID int64
	if err := db.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM auth_log`).Scan(&lastID); err != nil {
		logging.LogfAPI("[apiserver][auth-autoblock] cursor init failed: %v", err)
		lastID = 0
	}
	failTSByIP := map[string][]int64{}
	lastBlock := map[string]time.Time{}
	ticker := time.NewTicker(authAutoblockPollEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		rows, err := db.Query(`SELECT id, ts, event, ip FROM auth_log WHERE id > ? AND event IN ('FAIL','RATELIMIT') ORDER BY id ASC LIMIT ?`, lastID, authAutoblockQueryBatch)
		if err != nil {
			logging.LogfAPI("[apiserver][auth-autoblock] query failed: %v", err)
			continue
		}

		for rows.Next() {
			var (
				id    int64
				ts    int64
				event string
				ipRaw string
			)
			if err := rows.Scan(&id, &ts, &event, &ipRaw); err != nil {
				continue
			}
			lastID = id

			ip := net.ParseIP(strings.TrimSpace(ipRaw))
			if ip == nil || strings.EqualFold(event, "RATELIMIT") {
				continue
			}
			key := ip.String()
			cut := ts - int64(authAutoblockWindow.Seconds())
			series := append(failTSByIP[key], ts)
			n := 0
			for _, t := range series {
				if t >= cut {
					series[n] = t
					n++
				}
			}
			series = series[:n]
			failTSByIP[key] = series
			if len(series) < authAutoblockFailLimit || time.Since(lastBlock[key]) < authAutoblockWindow {
				continue
			}

			mode := strings.ToLower(strings.TrimSpace(cfg.Throttle.Mode))
			if mode == "" {
				mode = "permanent"
			}
			if mode == "alert" {
				mode = "dryrun"
			}
			if mode != "ttl" && mode != "dryrun" {
				mode = "permanent"
			}
			var ttlPtr *time.Duration
			ttlSec := 0
			if mode == "ttl" {
				ttl := time.Duration(cfg.Throttle.TTLSeconds) * time.Second
				if ttl <= 0 {
					ttl = 24 * time.Hour
				}
				ttlPtr = &ttl
				ttlSec = int(ttl.Seconds())
			}

			if mode == "dryrun" || be.AddBlock(ip, authAutoblockReason, ttlPtr) == nil {
				if mode != "dryrun" {
					lastBlock[key] = time.Now()
				}
				_ = be.ReportBlock(key, authAutoblockReason, "detector", mode, ttlSec)
				logging.LogfAPI("[apiserver][auth-autoblock] ip=%s fails=%d/%dm -> %s (%s)", key, len(series), int(authAutoblockWindow.Minutes()), mode, authAutoblockReason)
			}
		}
		_ = rows.Close()
	}
}
