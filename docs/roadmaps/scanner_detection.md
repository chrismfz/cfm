# CFM — Scanner & Detection Roadmap

**Scope:** Filesystem monitoring, malware scanning, surgical cleaning,
WordPress/CMS integrity, database scanning.

---

## Table of Contents

1. [What already exists](#1-what-already-exists)
2. [Feature 1 — fanotify Monitor (filewatch extension)](#2-feature-1--fanotify-monitor-filewatch-extension)
3. [Feature 2 — YARA rules via nixpal-clamav package](#3-feature-2--yara-rules-via-nixpal-clamav-package)
4. [Feature 3 — Scanner Pipeline](#4-feature-3--scanner-pipeline)
5. [Feature 4 — Surgical PHP Cleaning](#5-feature-4--surgical-php-cleaning)
6. [Feature 5 — WordPress & CMS Integrity](#6-feature-5--wordpress--cms-integrity)
7. [Feature 6 — Database Scanning & Cleaning](#7-feature-6--database-scanning--cleaning)
8. [Under Consideration — PAM Detector](#8-under-consideration--pam-detector)
9. [Progress tracking](#9-progress-tracking)

---

## 1. What already exists

Before any new code, this is what is already complete and production-ready.
New features build on top of this — none of it needs to change.

### ClamAV — fully wired

`internal/clam/` is complete. The full chain works today:

```
WAF upload intercept (cfm_waf.lua)
    │  POST with suspicious file
    ▼
nginx bridge (SetClamManager wired)
    │  job.Path = temp copy, job.TempCopy = true
    ▼
clam.Manager (worker pool, async queue)
    │  client.ScanFile(path) → clamd socket
    ▼
clamd
    │  INFECTED / OK
    ▼
Manager.process()
    ├── if clean:    delete temp copy
    └── if infected: move to InfectedDir, notify, log
```

What exists:
- `clam.Client` — `ScanFile`, `ScanPath`, `ContScan`, `Ping`, `Version`
- `clam.Manager` — async job queue, worker pool, enricher support
- `clam.Job` — carries `Path`, `IP`, `Host`, `URI`, `Reason`, `TempCopy`, `InfectedDir`
- `clam.Config` — `PendingDir` (`/var/lib/cfm/scanner/pending`), `InfectedDir` (`/var/lib/cfm/scanner/infected`)
- `clam.Enqueuer` interface — used by bridge and future scanner pipeline
- Registry wiring — `SetClamManager`, `TryWireClamBridge`, `ResetClamBridgeWireState`
- CLI — `cfm clam ping`, `cfm clam version`, `cfm clam scan <path>`
- Config — `CLAMD_ENABLED`, `CLAMD_SOCKET`, `CLAMD_PENDING_DIR`, `CLAMD_INFECTED_DIR`
- Directories — `/var/lib/cfm/scanner/pending` and `/var/lib/cfm/scanner/infected` created at startup

**The only thing missing from `internal/clam/`:** a `Reload()` method.
Everything else is done.

### filewatch — polling watcher

`internal/filewatch/watcher.go` — watches a single file for content changes
via mtime + SHA-256 polling. Used by dyndns and config reload. Intentionally
dependency-free. Will be extended with `Monitor` (Feature 1) in the same
package without touching the existing `Watcher`.

---

## 2. Feature 1 — fanotify Monitor (filewatch extension)

### What it does

fanotify is a Linux kernel API that delivers filesystem events — file created,
file written and closed — in under one second, by watching entire mount points.
When a PHP webshell lands in `/home/user/public_html/uploads/`, the kernel
notifies CFM before any HTTP request touches it.

**This is the event source for the scanner pipeline.** Without it, scanning is
periodic (poll every N hours). With it, detection is under one second.

### Where it lives — same package, new files

`internal/filewatch/` already exists. The `Monitor` lives alongside the
existing `Watcher` without changing it:

```
internal/filewatch/
  watcher.go          ← existing, unchanged — polling Watcher for single files
  monitor.go          ← new — Monitor interface + FileEvent + MonitorConfig
  monitor_linux.go    ← //go:build linux — fanotify implementation
  monitor_other.go    ← //go:build !linux — stub, returns ErrNotSupported
  filter.go           ← new — extension + size + path exclusion checks
```

The existing `Watcher` is polling-based and watches one file. The new
`Monitor` is event-driven and watches entire directories. Different
mechanisms, same conceptual home — "watching files for changes."

### Config

Two independent toggles — IO impact is very different for each mode:

```ini
# cfm.conf

[scanner]
ENABLED              = 1         ; master switch

; Real-time kernel events. Can be heavy on IO-intensive servers
; (mass cPanel restores, backup jobs, very active sites).
; Disable on IO-constrained servers, keep PERIODIC_ENABLED=1.
FANOTIFY_ENABLED     = 1
WATCH_PATHS          = /home, /tmp, /dev/shm

; Scheduled full walk of WATCH_PATHS. Set PERIODIC_START_HOUR for off-peak.
; Catches files that existed before CFM was installed.
PERIODIC_ENABLED     = 1
PERIODIC_EVERY       = 6h
PERIODIC_START_HOUR  = 2         ; 2am if set, otherwise start immediately

; WAF-triggered upload scanning. Already works today via the bridge.
; Listed here for completeness — no new code needed for this mode.
SCAN_ON_UPLOAD       = 1         ; zero additional IO — WAF already captures it

; File filter — applied in all three modes
WATCH_EXTENSIONS     = .php,.phtml,.php5,.php7,.html,.htm,.js,.htaccess,.user.ini
MAX_FILE_SIZE        = 2097152   ; 2MB — skip large legitimate files (WP backups etc.)
```

Typical operator choices:

| Server type | Config |
|---|---|
| Normal cPanel, moderate load | All three enabled |
| High IO (heavy backups, mass restores) | `FANOTIFY_ENABLED=0`, `PERIODIC_ENABLED=1` off-peak |
| Minimal footprint | `SCAN_ON_UPLOAD=1` only — upload protection, zero extra IO |
| Post-incident full sweep | `PERIODIC_ENABLED=1`, `PERIODIC_EVERY=24h` |

### Implementation

**`monitor.go`** — platform-neutral interface and types:

```go
package filewatch

// FileEvent is a single filesystem event from the kernel.
type FileEvent struct {
    Path      string
    EventType EventType  // EventCreate or EventCloseWrite
    PID       int32      // process that wrote the file
}

type EventType uint8

const (
    EventCreate     EventType = 1
    EventCloseWrite EventType = 2
)

// MonitorConfig controls what the Monitor watches and filters.
type MonitorConfig struct {
    WatchPaths  []string        // directories or mount points to monitor
    Extensions  map[string]bool // lowercase with dot, e.g. ".php"
    MaxFileSize int64           // files larger than this are dropped (default 2MB)
    ChannelSize int             // event channel buffer (default 4096)
}

// Monitor watches directories for file events using a kernel mechanism.
// Create with NewMonitor, call Start to begin receiving events.
type Monitor struct {
    cfg    MonitorConfig
    events chan FileEvent
    impl   monitorImpl
}

func NewMonitor(cfg MonitorConfig) (*Monitor, error) {
    return newMonitor(cfg)  // platform-specific in monitor_linux.go / monitor_other.go
}

func (m *Monitor) Events() <-chan FileEvent { return m.events }
func (m *Monitor) Start(ctx context.Context) { m.impl.start(ctx) }
func (m *Monitor) Close() error              { return m.impl.close() }
```

**`monitor_linux.go`** — fanotify via `golang.org/x/sys/unix` (already in go.mod):

```go
//go:build linux

package filewatch

import "golang.org/x/sys/unix"

func newMonitor(cfg MonitorConfig) (*Monitor, error) {
    if cfg.ChannelSize <= 0 { cfg.ChannelSize = 4096 }
    if cfg.MaxFileSize <= 0 { cfg.MaxFileSize = 2 * 1024 * 1024 }

    fd, err := unix.FanotifyInit(
        unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK,
        unix.O_RDONLY|unix.O_LARGEFILE,
    )
    if err != nil {
        return nil, fmt.Errorf("fanotify_init: %w (needs CAP_SYS_ADMIN)", err)
    }

    mask := uint64(unix.FAN_CLOSE_WRITE | unix.FAN_CREATE)
    for _, path := range cfg.WatchPaths {
        // Try filesystem-level mark first; fall back to mount-level
        if err := unix.FanotifyMark(fd,
            unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM,
            mask, unix.AT_FDCWD, path,
        ); err != nil {
            _ = unix.FanotifyMark(fd,
                unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT,
                mask, unix.AT_FDCWD, path,
            )
        }
    }

    m := &Monitor{cfg: cfg, events: make(chan FileEvent, cfg.ChannelSize)}
    m.impl = &linuxMonitor{fd: fd, m: m}
    return m, nil
}
```

**`monitor_other.go`** — clean stub for non-Linux builds:

```go
//go:build !linux

package filewatch

import "errors"

var ErrNotSupported = errors.New("filewatch: fanotify not available on this platform")

func newMonitor(cfg MonitorConfig) (*Monitor, error) {
    return nil, ErrNotSupported
}
```

### What events to watch

| Extension | Why |
|---|---|
| `.php` `.phtml` `.php5` `.php7` | Webshells, backdoors, droppers |
| `.html` `.htm` | Phishing pages, injected JavaScript |
| `.js` | Card skimmers, redirectors |
| `.htaccess` | Redirect hacks, PHP execution rule injection |
| `.user.ini` | PHP-FPM equivalent of `.htaccess` tampering |

**Silently dropped in the filter stage:**
- All other extensions (binary, image, archive, data)
- Files larger than `MAX_FILE_SIZE` (WP backup zips, large media)
- Files in `.git/`, `node_modules/`, `.cache/` directories

### Files to create

```
internal/filewatch/monitor.go           ← FileEvent, MonitorConfig, Monitor interface
internal/filewatch/monitor_linux.go     ← //go:build linux
internal/filewatch/monitor_other.go     ← //go:build !linux stub
internal/filewatch/filter.go            ← extension + size + path filtering
```

---

## 3. Feature 2 — YARA rules via nixpal-clamav package

### The approach

ClamAV natively loads `.yar` / `.yara` files from its database directory
alongside `main.cvd`, `daily.cvd`, and `bytecode.cvd`. Since nixpal-clamav
is a custom repackage of ClamAV, ship YARA rule files as package-owned files:

```
nixpal-clamav RPM/deb:
  /usr/sbin/clamd
  /usr/sbin/freshclam
  /etc/clamav/clamd.conf
  /etc/clamav/freshclam.conf              ← includes DatabaseCustomURL
  /var/lib/clamav/main.cvd               ← standard ClamAV
  /var/lib/clamav/daily.cvd              ← standard ClamAV
  /var/lib/clamav/bytecode.cvd           ← standard ClamAV
  /var/lib/clamav/nixpal.yar             ← NixPal custom YARA rules   (new)
  /var/lib/clamav/yara-forge-core.yar    ← YARA Forge core tier       (new)
```

When the package updates, the YARA rules update. When clamd starts, it loads
everything in `/var/lib/clamav/` including `.yar` files. The existing
`ScanFile` call benefits from YARA detection automatically — no code change
needed for the scan itself.

### Two update channels

**Channel 1 — RPM/deb package update (baseline)**
`nixpal.yar` and `yara-forge-core.yar` are RPM-owned files. Package update
= rule update. Existing package infrastructure handles distribution and signing.

**Channel 2 — freshclam `DatabaseCustomURL` (fast lane)**
For rule updates between package releases:

```
# /etc/clamav/freshclam.conf — managed by nixpal-clamav package
DatabaseCustomURL https://repo.nixpal.com/clamav/nixpal-yara.cvd
```

freshclam checks this URL on its normal schedule (every few hours) and
downloads when updated. Build the CVD on the repo server when rules change:

```bash
cat nixpal.yar yara-forge-core.yar > combined.yar
sigtool --build nixpal-yara.cvd --sign combined.yar
# deploy to repo.nixpal.com/clamav/
```

### ClamAV YARA limitations — none that affect CFM's use case

| Limitation | Impact for PHP/web malware |
|---|---|
| No `pe` module | None — scanning PHP/HTML/JS, not Windows executables |
| No `dotnet` module | None |
| Limited `math` module | Minor — YARA Forge `core` tier avoids `math.entropy()` by design |
| No `include` directives | None — YARA Forge ships as a single compiled `.yar` |

YARA Forge `core` tier is specifically curated for maximum ClamAV compatibility.

### The only code change needed in CFM

Add `Reload()` to `internal/clam/clam.go` and expose it in the CLI:

```go
// internal/clam/clam.go — add one method

// Reload sends RELOAD to clamd, causing it to reload all databases
// including new or updated .yar files. Called after rule updates.
func (c *Client) Reload() error {
    resp, err := c.cmd("RELOAD")
    if err != nil {
        return err
    }
    if !strings.Contains(resp, "RELOADING") {
        return fmt.Errorf("unexpected response: %q", resp)
    }
    return nil
}
```

```go
// internal/cli/clam.go — add one case to the existing switch

case "reload":
    if err := client.Reload(); err != nil {
        fmt.Fprintf(os.Stderr, "clam reload failed: %v\n", err)
        return 1
    }
    fmt.Println("OK — clamd reloading databases")
    return 0
```

```bash
cfm clam reload   # sends RELOAD to clamd → new YARA rules active immediately
```

### Files that change

```
internal/clam/clam.go     ← add Reload() method (~10 lines)
internal/cli/clam.go      ← add "reload" case (~8 lines)
nixpal-clamav package     ← add nixpal.yar, yara-forge-core.yar
configs/freshclam.conf    ← add DatabaseCustomURL line
```

---

## 4. Feature 3 — Scanner Pipeline

### What it does

Connects the fanotify `Monitor` (Feature 1) to the existing `clam.Manager`.
fanotify fires a `FileEvent`, the pipeline filters it, deduplicates it, and
hands it to ClamAV as a `clam.Job`. Findings flow into actions: quarantine
or surgical cleaning, plus alerts through the existing notify pipeline.

### Pipeline

```
Source 1: filewatch.Monitor (fanotify realtime events)
Source 2: periodic walk of WATCH_PATHS (scanner/periodic.go)
Source 3: clam.Manager WAF bridge (already works, unchanged)
    │
    ▼
internal/scanner/pipeline.go
    │
    ├── filter.go: extension, size, path exclusions
    │
    ├── dedup.go: same path+sha256 within 10s window
    │           (editors write+rename multiple times per save)
    │
    └── clam.Manager.Enqueue(job)   ← existing Enqueuer interface, no changes
              │
              ▼
           clamd
           (YARA rules + standard ClamAV signatures)
              │
         Result: INFECTED / OK
              │
    ┌─────────┴──────────────────┐
    ▼                            ▼
action.go                  Log + notify
(quarantine or clean)      (existing pipeline)
```

### What's new vs. what's reused

| Component | Status | Notes |
|---|---|---|
| `clam.Manager` / `clam.Enqueuer` | ✅ exists | No changes |
| `clam.Job` | ✅ exists | `Reason` field carries `"fanotify"` or `"periodic"` |
| `clam.Manager.process()` | ✅ exists | Handles infected moves to `InfectedDir` |
| `filewatch.Monitor` | **build** (Feature 1) | Event source |
| `internal/scanner/pipeline.go` | **build** | Connects Monitor → Manager |
| `internal/scanner/dedup.go` | **build** | path+sha256 dedup window |
| `internal/scanner/periodic.go` | **build** | Scheduled directory walk |
| `internal/scanner/quarantine.go` | **build** | Metadata quarantine + JSON sidecar |
| `internal/scanner/action.go` | **build** | Quarantine vs. clean decision |
| `internal/scanner/filter.go` | **build** | Shared filter for all three sources |

### Quarantine

The existing `clam.Manager` already moves infected WAF upload copies to
`InfectedDir` (`TempCopy=true` jobs). For filesystem scan jobs
(`TempCopy=false`), the file must not simply be moved — that breaks the site.
Instead: copy to quarantine with full metadata, replace the original with a
safe placeholder:

```go
// internal/scanner/quarantine.go

type QuarantineRecord struct {
    OriginalPath  string    `json:"original_path"`
    QuarantinedAt time.Time `json:"quarantined_at"`
    OwnerUID      int       `json:"owner_uid"`
    OwnerGID      int       `json:"owner_gid"`
    Permissions   string    `json:"permissions"`
    Signature     string    `json:"signature"`   // ClamAV signature name
    Source        string    `json:"source"`      // "fanotify" | "periodic" | "upload"
}

func Quarantine(path, signature, source string) error {
    stat, _ := os.Stat(path)

    // 1. Copy to quarantine with timestamp prefix and safe filename
    ts := time.Now().Format("20060102-150405")
    safeName := strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "_")
    dest := filepath.Join("/var/lib/cfm/quarantine", ts+"_"+safeName)
    copyFile(path, dest)

    // 2. Write JSON metadata sidecar
    sysStat := stat.Sys().(*syscall.Stat_t)
    writeJSON(dest+".meta", QuarantineRecord{
        OriginalPath:  path,
        QuarantinedAt: time.Now(),
        OwnerUID:      int(sysStat.Uid),
        OwnerGID:      int(sysStat.Gid),
        Permissions:   stat.Mode().String(),
        Signature:     signature,
        Source:        source,
    })

    // 3. Replace with safe placeholder — site keeps running, file not re-executed
    if isWebExecutable(path) {
        os.WriteFile(path, []byte("<?php // removed by cfm scanner ?>"), stat.Mode())
    } else {
        os.Remove(path)
    }
    return nil
}
```

### Files to create

```
internal/scanner/
  pipeline.go     ← main loop: Monitor events → filter → dedup → Enqueue
  dedup.go        ← path+sha256 deduplication window
  periodic.go     ← scheduled directory walk feeding the same pipeline
  quarantine.go   ← metadata-preserving quarantine with JSON sidecar
  action.go       ← quarantine vs. clean decision logic
  filter.go       ← extension + size + path exclusion (shared by all sources)
```

---

## 5. Feature 4 — Surgical PHP Cleaning

### What it does

Instead of quarantining a WordPress plugin file that has three injected lines
of base64-encoded eval code at the top — which breaks the site — the cleaner
removes only the injection and leaves the rest intact.

**Zero new dependencies.** Pure Go string processing. Always creates a backup
before touching the file. Returns what was removed or reports that the file
needs manual review if no known pattern is found.

### The 7 strategies

Applied in order. A single file can trigger multiple strategies simultaneously.

| Strategy | Pattern | Example |
|---|---|---|
| 1. `@include` injection | Lines loading external files via `@include` | `@include('/tmp/x.php')` |
| 2. Prepend injection | High-entropy block at file start, before real code | Base64 blob before first function/class |
| 3. Append injection | Code after closing `?>` or at end of PSR-12 file | Obfuscated blob at bottom |
| 4. Inline `eval` | Single-line `eval(base64_decode(...))` anywhere | `$x=eval;$x(base64_decode('...'))` |
| 5. Base64 chains | Multi-layer decode ladders | `eval(base64_decode(base64_decode(...)))` |
| 6. `chr()/pack()` | Character-by-character string assembly | `chr(115).chr(121).chr(115)...` ("sys...") |
| 7. Hex variables | Hex-encoded string assignments near exec calls | `$f="\x65\x76\x61\x6c"; $f(...)` |

Strategy 2 uses **Shannon entropy** to validate: injected prepend code
typically has entropy ~4.5–5.0 (obfuscated); real PHP code is ~3.5–4.2.

```go
// internal/cleaner/cleaner.go

func CleanFile(path string) CleanResult {
    data, _ := os.ReadFile(path)
    backup := createBackup(path, data)  // always — no backup = no clean

    content := string(data)
    var removals []string

    // All strategies tried in order — multiple can fire on one file
    for _, strategy := range []strategyFn{
        removeIncludeInjections,
        removePrependInjection,
        removeAppendInjection,
        removeInlineEval,
        removeBase64Chains,
        removeChrPack,
        removeHexVars,
    } {
        var removed []string
        content, removed = strategy(content)
        removals = append(removals, removed...)
    }

    if len(removals) == 0 {
        return CleanResult{Error: "no known injection patterns — quarantine manually"}
    }

    os.WriteFile(path, []byte(content), preservedMode(path))
    return CleanResult{Cleaned: true, BackupPath: backup, Removals: removals}
}
```

Backups go to `/var/lib/cfm/quarantine/pre_clean/YYYYMMDD-HHMMSS_path` with
a JSON sidecar carrying original path, uid/gid, permissions, and timestamp.
Fully restorable via CLI and web UI.

### When to clean vs. quarantine

```go
// internal/scanner/action.go

func decideAction(path, signature string) Action {
    name := strings.ToLower(filepath.Base(path))

    // Standalone webshell by known name → quarantine (the file IS the malware)
    if knownWebshellNames[name] { return ActionQuarantine }

    // WP core/plugin/theme file → try to clean (removing breaks the site)
    if isWPCoreFile(path) || isWPPluginFile(path) || isWPThemeFile(path) {
        return ActionClean
    }

    // Unknown standalone file → quarantine
    return ActionQuarantine
}
```

### Connection to existing WAF

`cfm_waf.lua` already detects `eval`, `base64_decode`, `chr()` chains, hex
injections, and webshell patterns in HTTP request bodies. The cleaning
strategies are the same patterns applied to static files on disk rather than
live request bodies. The WAF catches the probe; the cleaner removes the artifact.

### Files to create

```
internal/cleaner/
  cleaner.go      ← CleanFile(), CleanResult, ShouldClean()
  strategies.go   ← all 7 strategy functions
  entropy.go      ← Shannon entropy calculator
  backup.go       ← backup creation + JSON metadata sidecar
  restore.go      ← restore from pre-clean backup
```

---

## 6. Feature 5 — WordPress & CMS Integrity

### What it does

When fanotify sees a write to a WordPress core file, CFM fetches the official
MD5 checksums from `api.wordpress.org` and compares. Tampered core files are
flagged immediately.

**The API is completely free, no key required:**
```
https://api.wordpress.org/core/checksums/1.0/?version=6.4.3&locale=en_US
→ {"checksums": {"wp-login.php": "abc123...", "wp-includes/functions.php": "def456..."}}
```

### How it works

```
fanotify event: /home/user/public_html/wp-includes/functions.php written
    │
    ▼
detectWPRoot(path)           → /home/user/public_html
readWPVersion(root)          → version=6.4.3, locale=en_US  (from wp-includes/version.php)
fetchChecksums(ver, locale)  → map[relpath]md5  (disk-cached, 7 day TTL)
    │
    ├── relPath   = "wp-includes/functions.php"
    ├── expected  = checksums["wp-includes/functions.php"] = "abc123..."
    ├── actual    = md5sum(path) = "xyz789..."   ← MISMATCH
    └── emit alert: WP_CORE_TAMPERED
```

### Cache strategy

- Response cached to `/var/lib/cfm/wp-checksums/<version>-<locale>.json`
- 7 day TTL — checksums never change for released versions
- 404 responses (paid/private plugins absent from wp.org) cached 72 hours
  to avoid hammering the API on every scan for plugins that won't be found

### CMS roadmap

| CMS | Phase | Method |
|---|---|---|
| WordPress core | 1 | `api.wordpress.org` — free, no key |
| WordPress plugins | 2 | `api.wordpress.org/plugins` — free |
| Joomla | 3 | `update.joomla.org` checksums |
| Drupal | 3 | `drupal.org` package verification |
| Magento 2 | 3 | Composer hash verification |
| OpenCart | 3 | Hash-on-install baseline |

Phase 1 covers WordPress only — 60–70% of shared hosting sites.
Interface is the same regardless of CMS: `CheckFile(path) → CheckResult`.

### Files to create

```
internal/wpintegrity/
  detect.go     ← detectWPRoot(), readWPVersion()
  fetch.go      ← api.wordpress.org HTTP fetch
  check.go      ← CheckFile(), CheckResult
  cache.go      ← on-disk checksum cache with TTL
  plugins.go    ← plugin integrity (Phase 2)

internal/cmsintegrity/      ← Phase 3
  joomla.go
  drupal.go
```

---

## 7. Feature 6 — Database Scanning & Cleaning

### What it does

Attackers who compromise a WordPress site inject content directly into the
database: casino/Viagra spam posts, injected admin users, malicious JavaScript
in theme options, redirect hacks. These survive file scanning — the PHP files
look clean but the site still serves malware.

**CFM already has a live MySQL connection via the MySQL Governor.** Database
scanning reuses that connection. No new MySQL setup or credentials needed.

### Discovery

On cPanel: `username_dbname` naming convention. Enumerate from
`/var/cpanel/users/<username>` or filter `SHOW DATABASES` by prefix.

### WordPress scanning — read-only queries

**Injected admin users:**
```sql
SELECT ID, user_login, user_email, user_registered
FROM wp_users
WHERE user_registered > NOW() - INTERVAL 7 DAY
ORDER BY user_registered DESC;
```

**Spam content (casino, Viagra, malicious JS):**
```sql
SELECT ID, post_title, post_status, LEFT(post_content, 200) AS preview
FROM wp_posts
WHERE post_status = 'publish'
  AND (
      post_content LIKE '%casino%'
   OR post_content LIKE '%viagra%'
   OR post_content REGEXP '<script[^>]+src=["\\\'][^"\\\']*\\.(ru|cn|xyz)["\\\']'
  );
```

**Malicious options (redirect hacks, injected JavaScript):**
```sql
SELECT option_name, LEFT(option_value, 300) AS preview
FROM wp_options
WHERE option_value REGEXP '(eval\\(|base64_decode|document\\.write|unescape\\()'
  AND option_name IN ('siteurl','home','blogdescription','widget_text','active_plugins');
```

**Backdoor cron jobs:**
```sql
SELECT option_name, option_value
FROM wp_options
WHERE option_name LIKE '%cron%' AND option_value LIKE '%eval%';
```

### Cleaning — conservative by design

| Finding | Default action | Aggressive (`AUTO_CLEAN=1`) |
|---|---|---|
| Injected admin user | Flag for review | Auto-delete |
| Spam post | Mark as `draft` | Mark as `draft` (never auto-delete posts) |
| Malicious option | Backup + restore safe default | Same |
| Backdoor cron | Remove entry | Remove entry |

Always `mysqldump` the affected table before any modification.
Never auto-delete posts — too much risk of legitimate content loss.

### detectors.conf section

```ini
[dbscanner]
ENABLED            = 1
EVERY              = 24h        ; scan all discovered databases daily
AUTO_CLEAN_USERS   = 0          ; 0 = flag only; 1 = auto-delete injected users
AUTO_DRAFT_POSTS   = 1          ; auto-mark spam posts as draft
SCAN_PREFIXES      = wp_        ; future: joomla_, oc_, drupal_
ALERT_THRESHOLD    = 1
```

### Files to create

```
internal/dbscanner/
  discover.go      ← cPanel database discovery
  wp.go            ← WordPress scan queries (read-only)
  wp_clean.go      ← WordPress cleaning actions
  backup.go        ← mysqldump before any modification
  result.go        ← DBScanResult, finding types

internal/detectors/dbscanner/
  detector.go      ← PeriodicDetector wrapper
  register.go      ← Register() call
```

---

## 8. Under Consideration — PAM Detector

**Status: deferred.** CFM already detects SSH, FTP, Dovecot, and cPanel
brute force via log parsing. PAM adds ~1–4 seconds of speed but does not
close a genuine detection gap for the services that matter.

The obstacle: `pam_exec.so` spawns a binary on every auth event. The CFM
binary starts in ~17ms. Under active bot traffic this adds measurable overhead.
A dedicated Go binary starts in ~2–3ms but adds a deployment artifact.
A C PAM shared library starts in microseconds but requires a C build step.

**If built, the correct implementation:**

A tiny dedicated C PAM module (~150 lines). Loads once into the authenticating
process as a shared library — no fork, no exec, no startup overhead. Each
auth event is one function call + one Unix socket write (~50 microseconds).

```c
// pam/pam_cfm.c
// Build:   gcc -shared -fPIC -o pam_cfm.so pam_cfm.c -lpam
// Package: /lib64/security/pam_cfm.so  in nixpal-clamav or cfm RPM
// Protocol: "AUTH ip=1.2.3.4 user=root service=sshd\n"
//           to /var/run/cfm/pam.sock
// Safety:  optional in PAM stack — never blocks logins
//          100ms connect timeout — no login delay if CFM is down
```

Two entries in `password-auth` only (covers SSH + Dovecot + FTP via include):

```
auth     optional  pam_cfm.so   ← every auth attempt
session  optional  pam_cfm.so   ← successful auth only (clears failure count)
```

CFM manages these entries idempotently on each daemon start (same pattern
as `EnsureBase()` for nftables): scan for `pam_cfm` in the file, add if
enabled and missing, remove if disabled. Watch `password-auth` with the
existing `filewatch.Watcher` to re-apply after authselect regenerates it.

---

## 9. Progress tracking

### Feature 1 — fanotify Monitor

| Task | File | Status |
|---|---|---|
| Create `monitor.go` | FileEvent, MonitorConfig, Monitor interface | ☐ |
| Create `monitor_linux.go` | `//go:build linux` fanotify implementation | ☐ |
| Create `monitor_other.go` | `//go:build !linux` stub | ☐ |
| Create `filter.go` | extension + size + path exclusion | ☐ |
| Add `ScannerConfig` struct to config | `internal/config/config.go` | ☐ |
| Wire Monitor into daemon startup | `internal/agent/agent.go` | ☐ |

### Feature 2 — YARA via nixpal-clamav

| Task | File | Status |
|---|---|---|
| Add `Reload()` method | `internal/clam/clam.go` | ☐ |
| Add `cfm clam reload` subcommand | `internal/cli/clam.go` | ☐ |
| Add `nixpal.yar` to package | nixpal-clamav RPM/deb spec | ☐ |
| Add `yara-forge-core.yar` to package | nixpal-clamav RPM/deb spec | ☐ |
| Add `DatabaseCustomURL` to freshclam.conf template | `configs/freshclam.conf` | ☐ |
| Set up CVD build pipeline on repo server | infra | ☐ |

### Feature 3 — Scanner Pipeline

| Task | File | Status |
|---|---|---|
| Create `internal/scanner/filter.go` | shared extension + size + path checks | ☐ |
| Create `internal/scanner/dedup.go` | path+sha256 dedup window | ☐ |
| Create `internal/scanner/pipeline.go` | Monitor → filter → dedup → Enqueue | ☐ |
| Create `internal/scanner/periodic.go` | scheduled directory walk | ☐ |
| Create `internal/scanner/quarantine.go` | metadata quarantine + JSON sidecar | ☐ |
| Create `internal/scanner/action.go` | quarantine vs. clean decision | ☐ |
| Wire pipeline into daemon | `internal/agent/agent.go` | ☐ |
| Add `cfm scan <path>` CLI | `internal/cli/scan.go` | ☐ |
| Add quarantine list + restore to web UI | `internal/webui/static/` | ☐ |

### Feature 4 — Surgical Cleaning

| Task | File | Status |
|---|---|---|
| Create `internal/cleaner/entropy.go` | Shannon entropy calculator | ☐ |
| Create `internal/cleaner/strategies.go` | all 7 strategy functions | ☐ |
| Create `internal/cleaner/cleaner.go` | CleanFile(), CleanResult, ShouldClean() | ☐ |
| Create `internal/cleaner/backup.go` | backup + JSON metadata sidecar | ☐ |
| Create `internal/cleaner/restore.go` | restore from pre-clean backup | ☐ |
| Wire into `internal/scanner/action.go` | call CleanFile() on ActionClean | ☐ |
| Add `cfm clean file <path>` CLI | `internal/cli/clean.go` | ☐ |
| Add `cfm clean restore <backup>` CLI | `internal/cli/clean.go` | ☐ |

### Feature 5 — WordPress Integrity

| Task | File | Status |
|---|---|---|
| Create `internal/wpintegrity/detect.go` | detectWPRoot(), readWPVersion() | ☐ |
| Create `internal/wpintegrity/fetch.go` | api.wordpress.org + disk cache | ☐ |
| Create `internal/wpintegrity/check.go` | CheckFile(), CheckResult | ☐ |
| Create `internal/wpintegrity/cache.go` | on-disk checksum cache with TTL | ☐ |
| Wire into scanner pipeline on WP file events | `internal/scanner/pipeline.go` | ☐ |
| Add `cfm wp check <path>` CLI | `internal/cli/wp.go` | ☐ |
| Phase 2: plugin integrity | `internal/wpintegrity/plugins.go` | ☐ |
| Phase 3: Joomla / Drupal / Magento | `internal/cmsintegrity/` | ☐ |

### Feature 6 — Database Scanning

| Task | File | Status |
|---|---|---|
| Create `internal/dbscanner/discover.go` | cPanel database discovery | ☐ |
| Create `internal/dbscanner/wp.go` | WordPress scan queries (read-only) | ☐ |
| Create `internal/dbscanner/wp_clean.go` | WordPress cleaning with backup | ☐ |
| Create `internal/dbscanner/backup.go` | mysqldump before modification | ☐ |
| Create `internal/dbscanner/result.go` | DBScanResult, finding types | ☐ |
| Create `internal/detectors/dbscanner/detector.go` | PeriodicDetector wrapper | ☐ |
| Create `internal/detectors/dbscanner/register.go` | Register() call | ☐ |
| Add `[dbscanner]` to `configs/detectors.conf` | | ☐ |
| Add `cfm db scan <user>` CLI | `internal/cli/db.go` | ☐ |
| Add `cfm db clean <user> --dry-run` CLI | `internal/cli/db.go` | ☐ |
| Add DB scan results to web UI | `internal/webui/static/` | ☐ |
| Phase 2: Joomla, Drupal, Magento, OpenCart | `internal/dbscanner/` | ☐ |
