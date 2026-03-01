package mysql

import (
    "bufio"
    "database/sql"
    "fmt"
    "os"
    "strings"
)

func ResolveForAuto() string { return resolveMySQLErrorLog() }

// openDB tries credential sources in priority order.
func openDB(cfg GovernorConfig) (*sql.DB, error) {
    sources := []func() (string, error){
        func() (string, error) {
            if cfg.DSN != "" { return cfg.DSN, nil }
            return "", fmt.Errorf("no explicit DSN")
        },
        func() (string, error) { return dsnFromMyCNF("/root/.my.cnf") },
        func() (string, error) { return dsnFromMyCNF("/etc/cfm/mysql_governor.cnf") },
        func() (string, error) { return dsnFromDAConf() },
    }

    for _, src := range sources {
        dsn, err := src()
        if err != nil || dsn == "" { continue }
        db, err := sql.Open("mysql", dsn)
        if err != nil { continue }
        if err := db.Ping(); err != nil { db.Close(); continue }
        return db, nil
    }
    return nil, fmt.Errorf("no working credentials found; tried DSN, /root/.my.cnf, /etc/cfm/mysql_governor.cnf, DirectAdmin conf")
}

func dsnFromMyCNF(path string) (string, error) {
    f, err := os.Open(path)
    if err != nil { return "", err }
    defer f.Close()

    var user, pass, host, port, socket string
    inClient := false
    sc := bufio.NewScanner(f)
    for sc.Scan() {
        line := strings.TrimSpace(sc.Text())
        if line == "" || strings.HasPrefix(line, "#") { continue }
        if strings.HasPrefix(line, "[") {
            inClient = line == "[client]" || line == "[mysql]"
            continue
        }
        if !inClient { continue }
        k, v, ok := strings.Cut(line, "=")
        if !ok { continue }
        k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
        switch k {
        case "user":     user = v
        case "password": pass = v
        case "host":     host = v
        case "port":     port = v
        case "socket":   socket = v
        }
    }

    if user == "" { return "", fmt.Errorf("no user in %s", path) }

    if socket != "" {
        return fmt.Sprintf("%s:%s@unix(%s)/", user, pass, socket), nil
    }
    if host == "" { host = "127.0.0.1" }
    if port == "" { port = "3306" }
    return fmt.Sprintf("%s:%s@tcp(%s:%s)/", user, pass, host, port), nil
}

func dsnFromDAConf() (string, error) {
    // DirectAdmin stores MySQL root credentials here
    path := "/usr/local/directadmin/conf/mysql.conf"
    f, err := os.Open(path)
    if err != nil { return "", err }
    defer f.Close()

    vals := map[string]string{}
    sc := bufio.NewScanner(f)
    for sc.Scan() {
        line := strings.TrimSpace(sc.Text())
        k, v, ok := strings.Cut(line, "=")
        if !ok { continue }
        vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
    }

    user := vals["user"]
    pass := vals["passwd"]
    if user == "" { return "", fmt.Errorf("no user in DA conf") }
    return fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/", user, pass), nil
}
