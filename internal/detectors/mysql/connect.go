package mysql

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

func ResolveForAuto() string { return resolveMySQLErrorLog() }

// errNoCredentials: no credential source produced a DSN (most likely a node
// without a database). The lifecycle retries it slowly; see lifecycle.go.
var errNoCredentials = errors.New("no MySQL credentials found (tried DSN, /root/.my.cnf, /etc/cfm/mysql_governor.cnf, DirectAdmin conf)")

// connectError: a credential source produced a DSN but the connect failed.
// Its text names the source and the driver error, never the DSN (it holds a
// password).
type connectError struct {
	source string
	err    error // nil when the DSN itself did not parse
}

func (e *connectError) Error() string {
	if e.err == nil {
		return "invalid DSN from " + e.source
	}
	return "connect via " + e.source + " failed: " + e.err.Error()
}

func (e *connectError) Unwrap() error { return e.err }

// openPingTimeout bounds each connect+ping, so a DSN pointing at a host that
// never answers cannot stall the connect loop.
var openPingTimeout = 5 * time.Second

// Credential file locations, in priority order after an explicit DSN. Vars so
// tests can point them at fixtures.
var (
	rootMyCnfPath     = "/root/.my.cnf"
	governorCnfPath   = "/etc/cfm/mysql_governor.cnf"
	daMySQLConfigPath = "/usr/local/directadmin/conf/mysql.conf"
)

// openDB tries credential sources in priority order. It returns
// errNoCredentials when none produced a DSN, else the last source's
// *connectError.
func openDB(cfg GovernorConfig) (*sql.DB, error) {
	type source struct {
		name string
		dsn  func() (string, error)
	}
	sources := []source{
		{"DSN", func() (string, error) {
			if cfg.DSN != "" {
				return cfg.DSN, nil
			}
			return "", fmt.Errorf("no explicit DSN")
		}},
		{rootMyCnfPath, func() (string, error) { return dsnFromMyCNF(rootMyCnfPath) }},
		{governorCnfPath, func() (string, error) { return dsnFromMyCNF(governorCnfPath) }},
		{"DirectAdmin conf", dsnFromDAConf},
	}

	var lastErr error
	for _, src := range sources {
		dsn, err := src.dsn()
		if err != nil || dsn == "" {
			continue
		}
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			// The parse error can quote the DSN: drop it.
			lastErr = &connectError{source: src.name}
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), openPingTimeout)
		err = db.PingContext(ctx)
		cancel()
		if err != nil {
			db.Close()
			lastErr = &connectError{source: src.name, err: err}
			continue
		}
		return db, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errNoCredentials
}

func dsnFromMyCNF(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var user, pass, host, port, socket string
	inClient := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inClient = line == "[client]" || line == "[mysql]"
			continue
		}
		if !inClient {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "user":
			user = v
		case "password":
			pass = v
		case "host":
			host = v
		case "port":
			port = v
		case "socket":
			socket = v
		}
	}

	if user == "" {
		return "", fmt.Errorf("no user in %s", path)
	}

	if socket != "" {
		return fmt.Sprintf("%s:%s@unix(%s)/", user, pass, socket), nil
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if port == "" {
		port = "3306"
	}
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/", user, pass, host, port), nil
}

func dsnFromDAConf() (string, error) {
	// DirectAdmin stores MySQL root credentials here
	f, err := os.Open(daMySQLConfigPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	vals := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}

	user := vals["user"]
	pass := vals["passwd"]
	if user == "" {
		return "", fmt.Errorf("no user in DA conf")
	}
	return fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/", user, pass), nil
}
