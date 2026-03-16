package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

const historyRetentionDaysDefault = 30

type GovernorHistoryEvent struct {
	ID        int64          `json:"id"`
	TsUnix    int64          `json:"ts_unix"`
	EventType string         `json:"event_type"`
	User      string         `json:"user,omitempty"`
	DB        string         `json:"db,omitempty"`
	Action    string         `json:"action,omitempty"`
	Reason    string         `json:"reason,omitempty"`
	Result    string         `json:"result,omitempty"`
	PID       int64          `json:"pid,omitempty"`
	RuntimeMs int64          `json:"runtime_ms,omitempty"`
	Unblocked int            `json:"unblocked,omitempty"`
	ConnPct   float64        `json:"conn_pct,omitempty"`
	TotalConn int            `json:"total_conn,omitempty"`
	MaxConn   int            `json:"max_conn,omitempty"`
	Payload   map[string]any `json:"payload,omitempty"`
}

type GovernorHistorySummary struct {
	FromUnix         int64 `json:"from_unix"`
	ToUnix           int64 `json:"to_unix"`
	TotalEvents      int   `json:"total_events"`
	KillQuery        int   `json:"kill_query"`
	KillConnection   int   `json:"kill_connection"`
	SleepReap        int   `json:"sleep_reap"`
	ConnPressureWarn int   `json:"conn_pressure_warn"`
	ConnPressureCrit int   `json:"conn_pressure_critical"`
}

func (g *Governor) ensureHistoryTable(ctx context.Context) error {
	if g == nil || g.db == nil {
		return nil
	}
	_, err := g.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS cfm_mysql_governor_history (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  ts_unix BIGINT NOT NULL,
  event_type VARCHAR(64) NOT NULL,
  user_name VARCHAR(191) NOT NULL DEFAULT '',
  db_name VARCHAR(191) NOT NULL DEFAULT '',
  action VARCHAR(64) NOT NULL DEFAULT '',
  reason TEXT,
  result VARCHAR(191) NOT NULL DEFAULT '',
  pid BIGINT NOT NULL DEFAULT 0,
  runtime_ms BIGINT NOT NULL DEFAULT 0,
  unblocked INT NOT NULL DEFAULT 0,
  conn_pct DOUBLE NOT NULL DEFAULT 0,
  total_conn INT NOT NULL DEFAULT 0,
  max_conn INT NOT NULL DEFAULT 0,
  payload_json LONGTEXT,
  PRIMARY KEY (id),
  KEY idx_cfm_mysql_gov_hist_ts (ts_unix),
  KEY idx_cfm_mysql_gov_hist_type_ts (event_type, ts_unix),
  KEY idx_cfm_mysql_gov_hist_user_ts (user_name, ts_unix),
  KEY idx_cfm_mysql_gov_hist_db_ts (db_name, ts_unix)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`)
	return err
}

func (g *Governor) appendHistoryEvent(ev GovernorHistoryEvent) {
	if g == nil || g.db == nil || ev.EventType == "" {
		return
	}
	if ev.TsUnix <= 0 {
		ev.TsUnix = time.Now().Unix()
	}
	var payloadText sql.NullString
	if len(ev.Payload) > 0 {
		if b, err := json.Marshal(ev.Payload); err == nil {
			payloadText = sql.NullString{String: string(b), Valid: true}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = g.db.ExecContext(ctx, `
INSERT INTO cfm_mysql_governor_history
(ts_unix, event_type, user_name, db_name, action, reason, result, pid, runtime_ms, unblocked, conn_pct, total_conn, max_conn, payload_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.TsUnix, ev.EventType, ev.User, ev.DB, ev.Action, ev.Reason, ev.Result,
		ev.PID, ev.RuntimeMs, ev.Unblocked, ev.ConnPct, ev.TotalConn, ev.MaxConn, payloadText)
}

func (g *Governor) QueryHistoryEvents(user, dbName, eventType string, limit int) ([]GovernorHistoryEvent, error) {
	if g == nil || g.db == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	q := `SELECT id, ts_unix, event_type, user_name, db_name, action, reason, result, pid, runtime_ms, unblocked, conn_pct, total_conn, max_conn, payload_json
FROM cfm_mysql_governor_history WHERE 1=1`
	args := make([]any, 0, 4)
	if user != "" {
		q += " AND user_name = ?"
		args = append(args, user)
	}
	if dbName != "" {
		q += " AND db_name = ?"
		args = append(args, dbName)
	}
	if eventType != "" {
		q += " AND event_type = ?"
		args = append(args, eventType)
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := g.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	capHint := limit
	if capHint > 256 {
		capHint = 256
	}
	out := make([]GovernorHistoryEvent, 0, capHint)
	for rows.Next() {
		var ev GovernorHistoryEvent
		var payload sql.NullString
		if err := rows.Scan(&ev.ID, &ev.TsUnix, &ev.EventType, &ev.User, &ev.DB, &ev.Action,
			&ev.Reason, &ev.Result, &ev.PID, &ev.RuntimeMs, &ev.Unblocked,
			&ev.ConnPct, &ev.TotalConn, &ev.MaxConn, &payload); err != nil {
			return nil, err
		}
		if payload.Valid && payload.String != "" {
			_ = json.Unmarshal([]byte(payload.String), &ev.Payload)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (g *Governor) SummarizeHistory(hours int) (GovernorHistorySummary, error) {
	res := GovernorHistorySummary{}
	if g == nil || g.db == nil {
		return res, nil
	}
	if hours <= 0 {
		hours = 24
	}
	to := time.Now()
	from := to.Add(-time.Duration(hours) * time.Hour)
	res.FromUnix = from.Unix()
	res.ToUnix = to.Unix()

	rows, err := g.db.Query(`
SELECT event_type, action, COUNT(*)
FROM cfm_mysql_governor_history
WHERE ts_unix BETWEEN ? AND ?
GROUP BY event_type, action`, res.FromUnix, res.ToUnix)
	if err != nil {
		return res, err
	}
	defer rows.Close()
	for rows.Next() {
		var eventType, action string
		var n int
		if err := rows.Scan(&eventType, &action, &n); err != nil {
			return res, err
		}
		res.TotalEvents += n
		switch {
		case eventType == "kill_action" && action == "KILL QUERY":
			res.KillQuery += n
		case eventType == "kill_action" && action == "KILL CONNECTION":
			res.KillConnection += n
		case eventType == "kill_action" && action == "SLEEP REAP":
			res.SleepReap += n
		case eventType == "conn_pressure" && action == "warn":
			res.ConnPressureWarn += n
		case eventType == "conn_pressure" && action == "critical":
			res.ConnPressureCrit += n
		}
	}
	return res, rows.Err()
}

func (g *Governor) PruneHistory(days int) (int64, error) {
	if g == nil || g.db == nil {
		return 0, nil
	}
	if days <= 0 {
		days = historyRetentionDaysDefault
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	res, err := g.db.Exec(`DELETE FROM cfm_mysql_governor_history WHERE ts_unix < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (g *Governor) TruncateHistory() (int64, error) {
	if g == nil || g.db == nil {
		return 0, nil
	}
	res, err := g.db.Exec(`DELETE FROM cfm_mysql_governor_history`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (g *Governor) autoPruneHistory() {
	if _, err := g.PruneHistory(historyRetentionDaysDefault); err != nil {
		_ = fmt.Sprintf("%v", err)
	}
}
