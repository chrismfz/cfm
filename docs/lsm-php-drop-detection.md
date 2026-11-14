# PHP-drop safety net — cfm-lsm signal → ClamAV → edge attribution

**Status:** Design, not started (2026-11-14). No code. This is the "separate,
named proposal" `docs/cfm-lsm.md` requires for any policy beyond its
catalogue. It proposes **`CFML-FS-009` — PHP-executable file written under a
docroot by the PHP tier** and the daemon-side pipeline behind it.

**One line:** whatever bug lets an attacker in, the attack ends with the site's
PHP process writing a `.php` (or `.htaccess` / `.user.ini`) file into the
account's docroot. Catch that write in the kernel, scan exactly that file with
ClamAV, and tie it back to the edge request that caused it, so the IP can be
banned.

---

## Table of contents

1. [Why — the 2026-11-12 incident](#1-why--the-2026-11-12-incident)
2. [Position in the stack and prior decisions](#2-position-in-the-stack-and-prior-decisions)
3. [Signal — the BPF side](#3-signal--the-bpf-side)
4. [Noise budget — legitimate writers](#4-noise-budget--legitimate-writers)
5. [Action — scan, record, attribute](#5-action--scan-record-attribute)
6. [Safety](#6-safety)
7. [Coexistence — Imunify360, CageFS, the edge WAF](#7-coexistence--imunify360-cagefs-the-edge-waf)
8. [Rollout — phases and promotion metrics](#8-rollout--phases-and-promotion-metrics)
9. [Known gaps (honest limits)](#9-known-gaps-honest-limits)
10. [Alternatives considered](#10-alternatives-considered)
11. [Open questions for the operator](#11-open-questions-for-the-operator)
12. [Implementation slices (when approved)](#12-implementation-slices-when-approved)

---

## 1. Why — the 2026-11-12 incident

On node **earth**, dmkomotinis.gr (Joomla, Fabrik 3.10) was compromised through
CVE-2026-67282, the Fabrik `listfilter` eval:

| Step | What happened | What a write-net sees |
|---|---|---|
| 1 | PHP `eval` in the query string writes `up.php` | `php-fpm`/`lsphp` (account uid) **creates** `…/public_html/up.php` |
| 2 | `up.php` writes `php://input` to `$_GET['f']` | — (`up.php` is now a dropper) |
| 3 | `yavuzshell.php` uploaded as `application/octet-stream` to **six** paths | six more **creates** by the PHP tier, each driven by a request to `up.php`, a file the PHP tier itself created minutes earlier |
| 4 | Defacement (publicly reported in the press) | **overwrite** of an existing `index.php` / template `.php` |

The edge WAF saw nothing at the time. chrismfz/cfm#1657 added the logonly rules
332 (PHP code in the query) and 416 (a PHP file as a raw body). They would have
logged steps 1 and 3. But edge rules always trail new encodings and new entry
points: an unknown CVE, a body the WAF can't read, a path it doesn't inspect.
All four steps above end in one **CMS-independent** syscall shape:

> a PHP SAPI process, running as the account user, creates, overwrites or
> renames into a PHP-executable file under that account's docroot.

That step is what this design watches. The net would have seen up to eight
events. Two of them are high-confidence even if ClamAV knew neither file
(§5.4, the "dropper chain" tell).

## 2. Position in the stack and prior decisions

| Layer | Sees | Misses |
|---|---|---|
| Edge WAF (`cfm_waf.lua`) | the request | new encodings, bodies past the window, unknown CVEs |
| ClamAV upload scan (`cfm_clamav.lua` → `internal/clam`) | multipart file parts at the edge (`CLAM_SCAN_SCOPE` = archives by default) | raw bodies, `php://input` droppers, files PHP *generates* |
| Imunify PD (Zend extension, where licensed) | PHP calls it has rules for | non-Imunify hosts; calls not in its rules |
| **This: `CFML-FS-009` + scanner** | **the resulting file on disk, whoever wrote it** | content that never lands as a PHP-executable file (§9) |

**Prior decision this revisits.** `docs/cfm-lsm.md` "Out of scope" lists
`CFML-FS-003` (web-root suspicious file creation), because "the correlation
value belongs in `webdetector`, not in an LSM hook. The LSM hook would only
generate the event". This design **agrees with that split** and builds it:
the BPF program only emits a fact, and every judgement (noise context,
scanning, request attribution, banning) happens in the daemon. It takes a new
ID (`FS-009`) rather than reviving `FS-003`, so the old out-of-scope rationale
stays readable as history. The FS-003 paragraph in `cfm-lsm.md` already
points here. When this ships, the policy also joins that doc's catalogue in
the same PR (CLAUDE.md §5: keep docs in sync).

**CLAUDE.md §6 "cfm-lsm — signal, then noise".** Every LSM rule so far shipped
noisy and needed a tuning pass. This one runs on the noisiest surface there is:
shared-hosting PHP apps rewrite `.php` files constantly (§4). So the plan is
staged: **count-only first, then scan, then attribute, then (maybe) ban**. A
fleet count gates each step (§8). Kernel-side deny (`-EPERM`) is **not
proposed** at all (§3.7).

## 3. Signal — the BPF side

### 3.1 Hooks

| Hook | Covers | Why it's needed |
|---|---|---|
| `lsm/file_open` with `f_mode & FMODE_WRITE` | **create-by-open** (`FMODE_CREATED` set) and **overwrite / truncate / append** of an existing file | The defacement step is an overwrite. `fopen(…,'w')`, `file_put_contents`, a cross-filesystem `move_uploaded_file` (copy), `copy()`, `sendfile` destinations and `O_TMPFILE`'s first open all pass through here. `FMODE_CREATED` (4.19+, i.e. every BPF-LSM kernel) tells create from overwrite without a second program. |
| `lsm/inode_rename` | **rename-into**: `move_uploaded_file` on the same filesystem, atomic tmp→final writers, `shell.jpg` → `shell.php` | No open happens on the final name. Already attached by FS-005 on the fleet's kernels, so its signature drift is known. |
| `lsm/inode_link` | **hard-link-into**, including `O_TMPFILE` + `linkat(AT_EMPTY_PATH)` | Rare; cheap to include; closes the "anonymous file linked in" trick. |
| `lsm/path_truncate` *(optional)* | `truncate(2)` by path with no open | Truncation alone doesn't add code; listed for completeness, off unless it proves useful. |
| `lsm/bprm_check_security` + `lsm/task_alloc` | the **PHP-lineage** task mark (§3.3) | Reuses the FS-005 origin-tracker pattern (task storage + fork inheritance). |

**`inode_create` is deliberately not used.** It fires before content exists,
has no `struct file`, and `file_open` sees the same creation one step later
with `FMODE_CREATED`. One create path means one place to dedupe.

**`path_rename` was considered and rejected for v1.** It needs
`CONFIG_SECURITY_PATH`, which the fleet's distro kernels may not set (verify,
§11 Q10), and it gives nothing `inode_rename` lacks: `bpf_d_path` is not
allow-listed there either.

### 3.2 Gate order (cheapest first; `file_open` is a hot path)

`file_open` fires on every `open(2)` on the host, so the program returns in a
few instructions for almost every call:

1. `FMODE_WRITE` not set → return. This drops nearly all opens.
2. Calling uid not in `cfm_watched_uids`, or in the new per-policy
   `cfm_drop_excluded_uids` → return. The map and its three-layer build are
   the same as FS-005/EXEC-006 (`docs/cfm-lsm.md` "Watched-uid model"): web
   users, panel account uids, uid ≥ 1000.
3. The **name** has no PHP-executable extension class (§3.4) → return. This is
   a suffix compare on `d_name` (read `d_name.len`, then the last ≤ 8 bytes), so
   no path walk yet.
4. Writer class (§3.3) is `other` and the policy's `writers` knob is not `all`
   → return.
5. **Docroot ancestry walk** (§3.5) finds no docroot within the depth bound →
   return, except when the depth is exhausted (emit with `F_DEPTH_EXCEEDED`,
   §3.5).
6. In-kernel dedupe (§3.6) → return when it suppresses.
7. Reserve on the **dedicated** ringbuf, fill, submit. A reserve failure
   increments a per-CPU `lost` counter. The program always returns `ret`
   unchanged (monitor-only, §3.7).

Steps 1–3 are where the cost is decided. The plan's P0 measures it with
`kernel.bpf_stats_enabled=1` (`bpftool prog show` → `run_time_ns` /
`run_cnt`) on the busiest node before anything else ships.

### 3.3 "Is this the PHP tier?" — writer class

`comm` is spoofable (`prctl(PR_SET_NAME)`), and the spoof would help the
attacker: a shell renamed to look like `wp-cli` would escape a comm allowlist.
So the class comes from the **exe inode**, and comm is only carried as a
label.

* **`php_exe`**: `current->mm->exe_file->f_inode` (dev, ino) is in a new
  `cfm_php_exe_inodes` map. The daemon fills it from what
  `internal/phpinventory` already discovers (EA4 `ea-php*`, CloudLinux
  `alt-php*`, DirectAdmin CustomBuild, LiteSpeed `lsphp`, remi, system PHP),
  covering both `php-fpm` and `php-cgi`/`lsphp`/CLI binaries. It also adds the
  Apache `httpd` binary **only when mod_php is detected** (mod_php runs inside
  httpd).
* **`php_lineage`**: the task, or an ancestor, exec'd a `php_exe` binary. A
  task-storage bit is set in `bprm_check_security` and inherited through
  `task_alloc`, the same mechanism as FS-005's web-origin mark. It catches
  `system("curl -o x.php …")`, `exec("cp …")` and `proc_open` droppers whose
  own exe is not PHP. A php-fpm master exec'd as root marks every worker it
  forks, so pools inherit the bit regardless of their setuid. The exe class
  for the event is `php_exe` when both apply.
* **`other`**: everything else that writes as a watched uid, such as cPanel
  File Manager (`cpsrvd`/`uapi`, Perl), pure-ftpd after login, sshd/sftp,
  `git`, `rsync`, editors, and JetBackup restores that drop to the account.
  These are **not the threat this policy targets** (they imply stolen
  credentials, not a web exploit). They are dropped in BPF by default
  (`writers = php`). `writers = all` keeps them for an operator who wants
  credential-theft visibility too (§11 Q4).

The class (and, for userspace, the exe dev/ino and parent pid) rides on the
event. The daemon then splits `php_exe` into **`php_web`** (an FPM/lsphp/mod_php
worker) and **`php_cli`** (CLI binary; parent `crond`, a shell, `sshd`). That
split is the first noise discriminator: composer and wp-cli are `php_cli` with
no web lineage, while web exploits are `php_web` (§4).

### 3.4 Extension classes

The match is case-insensitive on the final name component. The canonical list
lives in **one** place, the BPF header plus its Go mirror with a parity test
(CLAUDE.md §5: no second copy that drifts):

| Class | Names | Why |
|---|---|---|
| `php` | `*.php`, `*.php3/4/5/7/8`, `*.phtml`, `*.pht`, `*.phar`, `*.phps` | handler-mapped by EA4 / CloudLinux / LiteSpeed / DA default configs |
| `php_double` | a name containing `.php.` (e.g. `x.php.jpg`) | `AddHandler`-style mappings execute these on some Apache configs. This is a **separate, lower-confidence class** and its own counter in P0. |
| `htaccess` | `.htaccess` | `AddHandler`/`SetHandler`/`php_value auto_prepend_file`: makes non-`.php` files executable, or prepends a shell to every request |
| `user_ini` | `.user.ini`, `php.ini` | `auto_prepend_file` persistence under php-fpm / CGI |

`htaccess` and `user_ini` are where most security and cache plugins write
constantly (§4). They get **their own sub-mode**, so an operator can run `php`
at P1 while these stay at P0 count-only.

### 3.5 "Under a docroot" — inode ancestry, not path strings

**Where the docroots come from.** CFM has no vhost→docroot reader today.
`internal/panelmap` parses `/etc/userdatadomains` but extracts only the owner,
and the docroot is a later `==` field of the same line
(`domain: owner==type==parent==sub==<docroot>==ip:port==…`). The plan adds a
`panelmap.Docroots()` reader **in that package**, so "which docroots exist,
which account and vhosts own them" stays one parse (the package exists
precisely to stop parallel copies):

* **cPanel**: the docroot field of `/etc/userdatadomains` (main, addon, sub
  and parked domains; an addon docroot outside `public_html` is just another
  entry).
* **DirectAdmin**: `/home/<user>/domains/<domain>/public_html` (and
  `private_html` when it is a real directory rather than the usual symlink),
  owners from `/etc/virtual/domainowners`, the file `internal/lsm/maps.go`
  already reads.
* **Plain hosts**: an operator list `docroot = /srv/www/*/htdocs` in the policy
  stanza (glob expanded in userspace at map-population time), as
  `persistence_path` works for FS-005 today.

**How the BPF side checks it.** The daemon `stat`s each docroot directory and
writes `(st_dev, st_ino)` → `docroot_id` into a new `cfm_docroot_inodes` hash.
This is the same key shape as FS-005's `cfm_watched_inodes`. The BPF walk goes
up `d_parent` from the target's parent for at most **`CFM_DROP_MAX_DEPTH = 24`**
levels and looks each ancestor up. On a hit, the event carries the
`docroot_id`, and the names collected on the way down **are** the path relative
to the docroot (§3.6). Why inodes and not strings:

* **CageFS, bind mounts and chroots don't matter.** A bind mount shares
  dentries, so the inode identity is the same inside the cage. A `d_path`
  string would be the cage's view.
* **No string compares in BPF**, no `bpf_d_path` (5.10+, and only some hooks
  are allow-listed for it), and it's the same verifier-proven loop shape as
  EXEC-006's `cfm_walk_to_top`.
* **Renames and moves of the docroot itself** are handled by a resync, not by
  stale strings.

**Depth bound.** Real WordPress/Joomla trees reach 12–16 levels below the
docroot (`wp-content/plugins/<p>/vendor/…`), and the docroot itself sits about
3 levels deep (`/home/u/public_html`). An extension-matched, watched-uid write
that runs out of depth without hitting a docroot or the filesystem root is
**emitted** with `F_DEPTH_EXCEEDED` (fail toward visibility) and resolved in
userspace. P0 counts how often that happens.

**Freshness.** The map is rebuilt when `/etc/userdatadomains` (or the DA file)
changes mtime, polled every 60 s, plus a full resync every 10 min. That second
pass catches an account restore, which recreates `public_html` with a new
inode. Map cap 65 536 entries; an overflow is logged and counted, never silent.

### 3.6 Event shape, dedicated ringbuf, in-kernel dedupe

**Own ringbuf.** `cfm_events` is one shared 256 KiB ringbuf ("exec is not a
hot path"). The Go drain (`loader.go::drain`) hands each event to an
unbuffered channel, so a slow consumer backs up into the kernel, and
`bpf_ringbuf_reserve` then fails. A cache-plugin storm on that shared buffer
would make the kernel drop **EXEC-003 reverse-shell and FS-005 events**. So
FS-009 gets its **own** `cfm_drop_events` ringbuf (1 MiB ≈ 2 800 events), its
own drain goroutine, and its own struct, which leaves the 124-byte
`cfm_lsm_event` wire layout untouched.

```c
struct cfm_drop_event {            /* ~380 bytes */
    __u64 ts_ns;
    __u32 policy_id;               /* CFM_LSM_POLICY_PHP_DROP = 20 */
    __u32 pid, tgid, ppid, uid, gid;
    __u8  op;                      /* CREATE | OVERWRITE | TRUNC | APPEND | RENAME_INTO | LINK_INTO */
    __u8  writer;                  /* PHP_EXE | PHP_LINEAGE | OTHER */
    __u8  ext_class;               /* PHP | PHP_DOUBLE | HTACCESS | USER_INI */
    __u8  flags;                   /* F_PATH_TRUNCATED | F_DEPTH_EXCEEDED | F_DIR_RENAME | F_SRC_OUTSIDE_DOCROOT */
    __u32 docroot_id;              /* value from cfm_docroot_inodes; 0 when F_DEPTH_EXCEEDED */
    __u64 file_dev, file_ino;      /* the target inode: the userspace re-open check (§6.2) */
    __u64 exe_dev, exe_ino;        /* writer's exe identity */
    __u64 cgroup_id;               /* bpf_get_current_cgroup_id(); LVE attribution is an open question */
    char  comm[16];
    __u16 relpath_len;
    char  relpath[256];            /* docroot-relative, built during the §3.5 walk */
} __attribute__((packed));
```

`op = RENAME_INTO` with `F_SRC_OUTSIDE_DOCROOT` (the old parent was not under
any docroot) is the classic upload-to-`/tmp`-then-move shape. `F_DIR_RENAME`
marks a **directory** renamed into a docroot. The name check can't see the
`.php` files inside it, so userspace walks the moved directory (bounded, §9).

**In-kernel dedupe.** An LRU hash keyed on the **file** `(dev, ino)` stores the
last emit time. A repeat `OVERWRITE`/`APPEND`/`TRUNC` of the same inode within
2 s is suppressed, with a per-key suppressed counter so userspace sees how
much. **`CREATE`, `RENAME_INTO` and `LINK_INTO` are never deduped**: a new
name or inode is a new fact. The dedupe **never keys on directory or
account**, so a shell can't hide among 500 cache writes in the same folder.
Hiding and burst detection are userspace's call, where they are visible and
tunable.

**Loss is a metric.** The per-CPU `lost` counter (ringbuf full) and the
dedupe-suppressed totals feed `cfm lsm status` and the `php_drops` MCP tool
(§5.6). A host that is losing events says so.

### 3.7 Enforce: not proposed

`isEnforceCapable` lists `CFML-FS-009` as **monitor-only**, so an enforce
setting is downgraded with the existing warning. Denying PHP writes into a
docroot breaks every CMS core/plugin update, every cache plugin and every site
builder on the node. This net acts *after* the write (scan, neutralise, ban;
§5), where a false positive costs a notification, not a broken site. If fleet
data ever shows a narrow, never-legitimate sub-shape (e.g. `RENAME_INTO` of a
`.php` from `upload_tmp_dir` by a `php_web` writer on a vhost with no upload
feature), that would be its own named proposal with its own burn-in.

## 4. Noise budget — legitimate writers

The policy's whole risk is here. Every row below is a **context** the daemon
assigns from fields it already has: writer class, docroot-relative path,
correlated request URI (§5.4), burst membership and the file's first bytes.
**A context never stops a file from being counted.** It decides whether the
file is scanned individually, scanned in a coalesced batch, or recorded
aggregated. The only thing that stops scanning outright is an explicit
operator allowlist (§6.4).

| Writer | Shape | Discriminator | Default handling |
|---|---|---|---|
| **WordPress core / plugin / theme updates** (`Core_Upgrader`, `Plugin_Upgrader`; `update-core.php`, `update.php`, `admin-ajax.php action=update-plugin`, auto-updates via `wp-cron.php`) | burst of 100–3 000 `php` creates in under a minute, unpacked under `wp-content/upgrade/…` then copied/moved into `wp-admin/`, `wp-includes/`, `wp-content/plugins/<p>/`; WP 6.3+ also writes `wp-content/upgrade-temp-backup/` | `php_web`, burst (§5.2), paths inside a known core/plugin tree, request URI is an upgrader endpoint or the node's own `wp-cron.php` loopback | **coalesced batch scan** at quiescence (one job for the touched set), one aggregated record, no per-file notify |
| **Joomla installer / updater**, **Akeeba** (backup / kickstart restore) | bursts; Joomla unpacks into the **site's own `tmp/`** (inside the docroot) then moves into `administrator/components/`, `plugins/`, … | same burst rule; `tmp/` + `com_installer` request URI | batch scan, aggregated record |
| **Cache plugins writing `.php`**: W3 Total Cache (object/db disk cache: `<?php exit; ?>`-prefixed files under `wp-content/cache/`, `w3tc-config/master.php`), WP Rocket (`wp-rocket-config/<host>.php`, `advanced-cache.php`), LiteSpeed Cache (`advanced-cache.php`, `object-cache.php`, constant `.htaccess` rewrites), WP Super Cache (`wp-cache-config.php`) | steady stream of overwrites and tmp+rename into a cache tree, plus a handful of drop-ins in `wp-content/` | known cache-tree prefixes; the `<?php exit;` header stub; overwrite of a known drop-in name. In-kernel same-inode dedupe absorbs most of it | cache trees: **counted, sampled scan** (first new name per tree per hour), aggregated record. Drop-ins: scanned on every change (a drop-in is a classic persistence spot) |
| **Compiled templates / framework caches**: Smarty `templates_c/`, Twig (Drupal `sites/*/files/php/twig/`), Laravel `storage/framework/views/`, `bootstrap/cache/`, Symfony/PrestaShop `var/cache/`, Magento `generated/` + `var/cache/`, Matomo `tmp/templates_c/` | **the highest-volume class**: one `.php` per template per cache clear | known cache-tree prefixes, recreated via tmp+rename | same as cache trees; P0 measures it per app before any default is set |
| **Security plugins**: Wordfence (`wp-content/wflogs/*.php` rewritten on many requests, `wordfence-waf.php`, and a **`.user.ini` / `.htaccess` with `auto_prepend_file`** for "extended protection"), Solid Security, AIOWPS (`.htaccess`) | very frequent `php` overwrites in `wflogs/`; occasional `user_ini`/`htaccess` writes | path prefix; for `user_ini`/`htaccess`, a content tell (§5.3) on the *value* of `auto_prepend_file` (Wordfence's points at `wordfence-waf.php`) | `wflogs/`: counted, sampled. `.user.ini`/`.htaccess`: **always recorded with the directives found**, since attackers use the same mechanism |
| **WPCode / Code Snippets** | snippets are stored in the DB and `eval`'d; no file write expected | — | **a gap, not noise** (§9). P0 confirms on the fleet that they write no files |
| **Theme / plugin editor** (`theme-editor.php`, `plugin-editor.php`, `admin-ajax.php action=edit-theme-plugin-file`) | single `OVERWRITE` of an existing theme/plugin file | correlated request URI | **scanned and recorded, never suppressed**: this is exactly what an attacker with stolen admin credentials does. Low severity unless infected |
| **cPanel File Manager** (cpsrvd / uapi, Perl), FTP, SSH/SFTP, git, rsync | writer exe is not PHP | writer class `other` | dropped in BPF unless `writers = all` |
| **composer**, **wp-cli**, **Softaculous** CLI installs, `php artisan` | bursts by a PHP CLI binary; parent is a shell/`sshd`/`crond`/panel | `php_cli`, no PHP-web lineage, no correlated request | batch scan, aggregated record, separate per-class counter |
| **Migration / backup tools**: All-in-One WP Migration import, Duplicator `installer.php`, Akeeba `kickstart.php`, UpdraftPlus restore | very large bursts (a whole site); the installer file itself is a lone `.php` create at the docroot | burst + request URI | batch scan. The lone `installer.php`/`kickstart.php` is scanned and recorded individually; these files are themselves abused |
| **Site builders** (Elementor, Divi, SitePad, cPanel Site Publisher) | mostly `.css`/`.json`/`.html`; occasional generated `.php` | out of extension scope for the common case | measured in P0 |
| **Imunify360 cleanup**, cagefsctl, JetBackup restore as root, cPanel account restore | run as **uid 0** | not in `cfm_watched_uids` | never emitted (§7) |
| **WP core self-repair / `wp-config.php` edits** at install | single creates/overwrites at the docroot root | correlated request URI (`setup-config.php`, `install.php`) | scanned, recorded; low severity |

**Rate limits (all per node, all configurable, all counted when they bite):**

* **Burst:** an account crossing **N = 50** `php` events in 60 s enters burst
  mode until 30 s of quiet. Per-file scans in the burst's tree are deferred
  into one coalesced job at quiescence (capped at 5 000 files; beyond that the
  record says `scanned=partial`). **Files outside the burst's tree keep the
  per-file path**: a shell dropped into `images/` during a plugin update is not
  absorbed by it.
* **Clean-file records:** the first 20 per account per hour are kept
  individually, the rest fold into one hourly aggregate row per account
  (count, top directories, top writers). This also answers the concern in
  `clam/scan_events.go`: high-volume clean rows must not prune the rare
  infected rows out of the bounded history store.
* **Scan budget:** at most `SCAN_PER_MIN` (default 300) drop-scans per node.
  Over budget, jobs stay pending (bounded, §6.1) and the overflow is counted.

**Before anything drives enforcement, count the fleet.** P0 (§8) records every
event as an aggregate per (node, account, writer class, op, ext class, context,
top-3 path prefixes) per day. It is read fleet-wide with the CFM MCP
(`node_call node="all" tool="php_drops"`) before P1 and again before every
later phase. The question each time is "how many events per node per day,
how many land in an unclassified context, and what does scanning them cost
clamd". Per CLAUDE.md §9 D3a, **zero events on a node is a deployment finding**
(policy not attached, docroot map empty, BPF-LSM unavailable), not evidence of
a quiet node.

## 5. Action — scan, record, attribute

### 5.1 Pipeline

```
 BPF cfm_drop_events ringbuf
   └─ drain goroutine (never blocks: parse → non-blocking send, cap 4096; full → drop++)
        └─ coalescer: pending map keyed (dev,ino), debounce + burst detection (cap 8192)
             └─ scan queue (bounded, cap 512) ── 1–2 workers ── clamd INSTREAM
                  └─ verdict → classify → record / notify / quarantine / attribute
                                                   └─ correlator (access ring → edgelog fallback)
```

All of it lives in a new package (working name `internal/phpdrop`). The LSM
package only gains the program, the maps, the struct parser and a typed
channel. Scanning, correlation and policy are not LSM concerns. That is the
FS-003 split (§2).

### 5.2 When to scan: debounce

`file_open` fires **before** any content is written, so an immediate scan
would read an empty file. The coalescer therefore:

1. holds each `(dev, ino)` for **2 s**; a new event for the same inode resets
   the timer (that is how bursts and repeated writes coalesce);
2. before scanning, `fstat`s twice, 500 ms apart, and requires a stable
   size+mtime;
3. after a clean verdict, re-stats once at +30 s and **re-scans if the mtime
   moved**. That catches a writer that keeps its fd open and writes late, as
   long as it does so within the window (residual in §9);
4. `RENAME_INTO`/`LINK_INTO` content is normally complete already, so these
   use a 500 ms debounce.

### 5.3 Scanning with the existing ClamAV client

**The client.** `internal/clam` holds the daemon-side client
(`clam.Client`: `SCAN`, `INSTREAM` via `ScanStream`/`ScanFileStream`,
`Ping`). It also has the `clam.Manager` worker pool behind the edge upload
scanner (`cfm_clamav.lua` → bridge → `Manager.Enqueue`) and the clamd health
circuit breaker (`health.go`). The design **reuses the client and the breaker,
not the Manager's job path**, for two reasons found in the code:

* **`Manager.process` deletes the scanned file when `Job.TempCopy` is set**
  (`_ = os.Remove(job.Path)`), and on an infected verdict copies it then
  removes it. That is correct for an edge spool copy and catastrophic for a
  customer's docroot file. The PHP-drop path must never construct a `clam.Job`
  for a docroot path. That rule is pinned by a test that runs the drop
  pipeline against a temp docroot and asserts the file is byte-identical and
  still in place after every verdict.
* **`SCAN <path>` makes clamd open the path itself**, as the clamd user. It
  can't read 0600/0640 account files, and it follows whatever the
  attacker-writable path points at by then. The drop scanner instead
  **opens the file itself** (§6.2) and streams the fd with `INSTREAM`
  (`ScanStream`). The daemon reads as root but only the inode the event named,
  with no symlinks.

The breaker is unexported today (`Manager.health`). Slice 3 (§12) exports a
small `clam.Breaker` interface so both pools trip and recover together and a
down clamd costs no dials. The drop pool's own size (1 worker by default,
`MaxWorkers` 2 max) keeps it from starving the **inline upload scan**, which
has a latency budget (`CLAM_INLINE_TIMEOUT`, 3 s). When the upload queue is
above half full, drop jobs pause.

Further limits:

* **Size cap:** files over 4 MiB are recorded `skipped=size` rather than
  streamed. Webshells are small, and a 4 MiB `.php` is itself unusual and is
  flagged.
* **Signature trust:** `CLAM_SIG_IGNORE` and the per-host sig-ignore store
  (`clam/sigignore.go`) apply unchanged. An ignored signature's hit is
  recorded `sig_ignored`, not notified, and never quarantined, as today.
* **Content tells (corpus-only first).** A cheap userspace read of the first
  64 KiB records a few markers next to the verdict, such as `php://input` +
  `file_put_contents`, `eval(`/`assert(` on a superglobal, a decoder chain
  (`base64_decode`/`gzinflate`/`str_rot13`), and for `.htaccess`/`.user.ini`
  the directives `auto_prepend_file`, `AddHandler`, `SetHandler`,
  `AddType application/x-httpd-php`. They are **scored by nothing** until the
  corpus says which ones hold. This is the same discipline as ChallengeV2's
  corpus-only readings (CLAUDE.md §6) and the FS-003 "decision logic belongs
  upstream" split.

### 5.4 Correlating with the edge

**The question:** which edge request made this write?

**What is known.** The event's wall time (`Event.Time(bootTime)`, as the other
policies do), the docroot (→ the exact vhost set that docroot serves, from
`panelmap.Docroots()`, more precise than "every domain of the account"), and
the writer pid. The PHP worker pid is not in the edge log: the edge proxies to
Apache/LiteSpeed on loopback, so the join is **time + vhost**, and the design
reports its ambiguity instead of hiding it.

**Where the requests come from.**

1. The webdetector **access ring** (`access_ring.go`, 4 096 parsed lines, in
   memory, no I/O). A line is appended when the request **ends**, so the
   correlator runs at scan time (≥ 2 s after the event) and once more at
   +`rt` for long requests.
2. When the ring has already rolled past the window, a bounded
   `edgelog.ScanHost` over the live file's tail (seek-from-EOF, timeout).
   Nothing is retained between calls.

**Matching.** A request R on a vhost served by that docroot matches when
`R.end − R.rt − 1 s ≤ event_ts ≤ R.end + 1 s`. Candidates are ranked by:
POST/PUT over GET; a URI whose script is the writer's file or a file in the
same tree; a **WAF hit of any tier on R or on R's IP within ±60 s** (rule
332/416 logonly hits count here, so the PR #1657 rules finally get a
consumer); and an IP seen in earlier drop events on this account.

**Confidence**, carried on every record:

| Value | Meaning | Allowed to |
|---|---|---|
| `unique` | exactly one candidate request in the window | name the IP; feed a ban (P3) |
| `ranked` | several; top one and up to 4 others listed | name the suspects; **notify only** |
| `none` | no request (cron, CLI, a non-HTTP writer, a ring gap) | record `writer`/`parent_exe` only |
| `self` | the request came from the node's own IP (`wp-cron.php` loopback, monitoring) | never ban; context only |

**The dropper-chain tell (CMS-independent, high value).** If the matched
request's script is a file this net saw the PHP tier **create in the last 24
h** on the same account, the record gets `chain=<that file>`, and severity is
raised **regardless of the ClamAV verdict**: a request ran a PHP file the PHP
tier itself wrote shortly before. In the incident, every `yavuzshell.php`
create (step 3) would have carried `chain=up.php`. The lookup is a bounded
per-account LRU of recent creates (path → ts, 512 per account). Legitimate
hits exist (Duplicator's `installer.php`, Akeeba `kickstart.php` run right
after upload), and P1 measures how often.

### 5.5 Outcomes

| Verdict | Notify | `detection_history` row | Quarantine |
|---|---|---|---|
| **infected** (not sig-ignored) | yes: `php_drop_infected`, severity `critical`, through `notify` (Slack/mail per the operator's routing) with file, account, vhost, signature, writer, correlated request(s) + confidence, chain tell | `php_drop_infected`, host-scoped | only if armed (below) |
| infected, **sig-ignored** | no | `php_drop_infected` with `sig_ignored`, `ignored_by` | never |
| **clean + chain tell**, or clean `.htaccess`/`.user.ini` carrying a directive tell | yes, severity `warning` (`php_drop_suspect`) | `php_drop_suspect` | never automatic |
| **clean** | no | `php_drop_new`, low severity, rate-limited per account (§4); the rest aggregated hourly | — |
| **skipped** (size, gone before scan, changed inode, breaker open, budget) | no (breaker state already alerts via `clam` health) | `php_drop_skipped` with the reason. "Gone before scan" on an Imunify node is itself informative (§7) | — |

Rows go through the webdetector `HistoryStore` like `clam_infected`
(`RecordClamScanEvent`), so they inherit `/api/v1/webdet/history/events`,
`scopeCheckHost`, the fleet `detection_history` read, and PULL into cfm-web.
New event types are added to `docs/endpoint_scope_inventory.md` in the same
change. **Scoped (cPanel) callers** see their own vhosts' rows. Writer
`cmdline` is stripped for them (it can carry another tenant's process
arguments under a shared web user), as `sig`/`src` are stripped elsewhere.

**Quarantine — operator's choice, off by default, never deletes.**
`QUARANTINE = off | copy | neutralize`:

* `copy`: an evidence copy via `safefs.CopyToNew` into
  `/var/lib/cfm/phpdrop/quarantine/` (0700, root), named by SHA-256, with a
  JSON sidecar (original path, owner, mode, mtime, verdict, correlation). The
  original is untouched.
* `neutralize`: `copy`, then the original is made **unservable without being
  changed**: `chown root:root` + `chmod 0000`. The account's PHP can no longer
  read, include or execute it, and its content and name stay as they were.
  The previous owner/mode are recorded in the sidecar; `cfm phpdrop restore
  <id>` puts them back. The file is never deleted, truncated or rewritten,
  and the never-delete rule has a test.
* Neutralize applies only to `infected` and never to `sig_ignored`, `suspect`
  or the burst batch (a mis-signature during a core update must not take a
  whole site down). On Imunify nodes the default is `off` (§7).

### 5.6 Surfaces

* `cfm.lsm.log` keeps the DETECT line (the existing per-policy rate cap via
  `admitDetect` still applies, so the log can't flood). Scan results go to
  `cfm.clam.log` with `src=php_drop`. No new log file is needed; if one is ever
  added, it gets a rotation entry in the same change (CLAUDE.md §5,
  `check_logrotate_coverage.sh`).
* `cfm lsm status`: attach state, ringbuf lost/suppressed, docroot-map size,
  php-exe-map size.
* `cfm phpdrop status | recent | restore`.
* MCP **`php_drops`**: the P0 aggregates, recent records, lost counters and
  scan budget, with `node="all"` fan-out. This is the fleet-count tool §4 and
  §8 depend on. `whats_wrong` gains one finding: "FS-009 attached but zero
  events in 24 h on a node with ≥ 50 docroots" (a deployment problem, D3a).

### 5.7 Banning

Bans are not wired directly: per CLAUDE.md §6, "the detector only emits
`core.Alert`". A new detectors.conf section **`[php_drop]`** receives an alert
for `infected` + `unique` (and, separately configurable, `chain` + `unique`).
Its section sink handles `BLOCK` (default `"6h"`, a soft TTL ban, persisted
via `ttlban` like the other TTL bans), leniency, `DRY_RUN`, API reporting and
email. It also calls `edgeban.Ban`, because it is a web-related ban and the
client may sit behind Cloudflare (an nft ban alone would hit the proxy). Never
banned: `self` / selfIPs, `IGNORE_IPS`, allow sets, trusted-proxy addresses.
Shipped as `DRY_RUN = 1` (§8 P3).

## 6. Safety

### 6.1 Bounded everywhere, nothing blocks the kernel

* **BPF:** non-sleepable LSM programs, a bounded loop (`CFM_DROP_MAX_DEPTH`),
  no helper that can sleep, always `return ret`. A full ringbuf costs an
  event (counted), never a syscall.
* **Drain → coalescer:** non-blocking hand-off (channel cap 4096). On a full
  channel the event is dropped and counted. The drain loop never waits on
  scanning, so the ringbuf keeps draining under a clamd stall. (The existing
  drain blocks on an unbuffered channel, which is fine for rare exec events
  and wrong for this volume.)
* **Coalescer:** a pending map capped at 8 192 inodes. Over the cap, new
  creates still get a record (`skipped=pending_cap`) and the account gets one
  summary alert per hour. A sudden flood of new PHP files on one account is a
  signal in its own right (mass defacement or a big install).
* **Scan workers:** one job at a time per worker, a per-scan deadline (the
  `Client` timeout), `recover()` per job (as `clam.Manager.worker` does), the
  shared breaker, exponential backoff 1 s → 60 s on consecutive transport
  errors. No subprocess is spawned on the hot path; clamd is a socket. If
  Imunify verdict lookups ever ship (§7, §11 Q1), they go through
  `exec.CommandContext` with a timeout and a `Wait` (reaped), one at a time,
  with the same backoff (CLAUDE.md "Concurrency / process lifecycle").
* **Health is never faked.** Stale-data markers are used, never an advancing
  heartbeat on failure: `last_event_ts`, `last_scan_ok_ts`,
  `docroot_map_built_at`, and `docroot_map_error` when the last rebuild failed
  (the old map stays loaded and is marked stale).
* **Shared state:** the docroot map rebuild builds a new userspace index and
  swaps it under a lock that covers **reads** (CLAUDE.md, the mmap'd-reader
  lesson). The BPF map is updated key by key (adds before deletes), so the
  kernel never sees an empty map mid-rebuild.

### 6.2 Opening an attacker-writable path safely

The docroot is writable by the very account that may be compromised, so
between event and scan the attacker can swap the path for a symlink (to
`/etc/shadow`, or a FIFO to hang the worker). The scanner:

1. resolves `docroot_path + relpath` with `openat2(RESOLVE_BENEATH |
   RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` from an fd on the docroot
   (5.6+), falling back to a per-component `O_NOFOLLOW` walk, with
   `O_NONBLOCK` as `safefs.OpenRegular` already does;
2. `fstat`s the fd: it must be a regular file **and its `(dev, ino)` must equal
   the event's**. On a mismatch the record is `skipped=inode_changed`
   (recorded, never scanned through a swapped path);
3. streams **that fd** to clamd (`INSTREAM`) and the quarantine copy reads the
   same fd. Neutralize uses `fchown`/`fchmod` **on the fd**, never on the path.

### 6.3 Kill switches

| Switch | Effect | Reload |
|---|---|---|
| `[policy "CFML-FS-009"] mode = disabled` (`/etc/cfm/lsm.conf`) | detaches the programs; nothing is emitted | `cfm lsm restart` |
| `cfm lsm disable` | every policy off (existing) | immediate |
| `[php_drop] ENABLED = 0` (`detectors.conf`) | events are counted only, no scan/record/notify/ban | polled, no restart |
| `[php_drop] SCAN = 0` | records and correlation, no clamd traffic | polled |
| `[php_drop] QUARANTINE = off` / `DRY_RUN = 1` | (defaults) | polled |

### 6.4 Allowlists

* **Per account, BPF-side:** `exclude_drop_user = <account>` adds the uid to
  `cfm_drop_excluded_uids`, so the account emits nothing. This is
  **per-policy**: the global `exclude_user` drops a uid from *every* watched-uid
  policy (FS-005, EXEC-004, EXEC-006 too), which is far too wide for a noisy
  CMS account.
* **Per path, userspace:** docroot-relative globs, global or per account
  (`allow_docroot_path = wp-content/cache/**`). Matches are counted, not
  scanned, not recorded. This is a **new key on purpose**: the existing
  `allow_path` (`internal/lsm/conf.go`, `parseAllowPath`) is an *absolute
  directory prefix matched against exec cmdline arguments* for
  CRED-002/EXEC-003/EXEC-005/EXEC-006. Giving the same key a second meaning
  would be the drift CLAUDE.md §5 warns about.
* **Per writer exe:** `allow_exe` (existing key, existing semantics: exe path,
  not comm).
* An allowlisted path still counts in the P0 aggregates, so "how much does
  this allowlist hide" stays answerable.

### 6.5 Tests never touch live paths (CLAUDE.md §5)

Every default path is a package var with a `Set…ForTest`, redirected from
`TestMain`:

* `phpdrop.QuarantineDir` (`/var/lib/cfm/phpdrop/quarantine`);
* the pending/state file, if one is persisted;
* the docroot sources, through the existing `panelmap.UserDataDomainsPath` /
  `UserDomainsPath` vars and a new DA var.

Further rules:

* Scanner tests use a **fake clamd** on a unix socket in `t.TempDir()`, never
  the real one.
* Quarantine/neutralize tests run only on files under `t.TempDir()`, and the
  chown path is skipped unless root **inside a user namespace**.
* BPF load tests are root-only integration tests (like
  `loader_integration_test.go`), skipped in CI. A live-netns-style recipe for a
  dev box goes into the doc's test section when slice 1 lands.
* `check_test_isolation.sh` covers `/var/lib/cfm`; the new package's
  `TestMain` is what keeps it green.

## 7. Coexistence — Imunify360, CageFS, the edge WAF

**Imunify360 (cPanel nodes where licensed).** Verify each point on a live node
before relying on it (§11 Q1). The keys named here are what an operator would
check in `imunify360-agent config show`, not facts asserted by this doc.

* **Malware Scanner, real-time mode** (`MALWARE_SCANNING.enable_scan_inotify`,
  plus the pure-ftpd upload hook). It already scans newly written files and
  applies `default_action` (notify / cleanup / quarantine). **That part
  overlaps with §5.3.** Duplicating it costs clamd I/O on every burst.
* **Proactive Defense** (Zend extension, `i360` in `php -m`; detected by
  `internal/phpinventory`). It blocks some writes before they happen, which
  means no file and no event. Complementary.
* **What Imunify does not do** is attribute a file to the **edge** request and
  client IP. Behind CFM's edge, Apache sees `127.0.0.1` unless
  `cfm realip` is set up (`docs/origin-real-ip.md`). Nor does it feed CFM's
  nft/edgeban bans or the dropper-chain tell. That is this design's unique
  part.

**Proposed default on Imunify nodes** (detected the way `internal/locate`
detects it, `imunify360` unit active): **`SCAN = auto`**, meaning the LSM event,
correlation, chain tell and records stay on, but the ClamAV scan **only runs
for `chain`, `.htaccess`/`.user.ini` and non-burst `php_web` creates**, and
`QUARANTINE` stays `off`. Imunify cleanup runs as root (no FS-009 event of its
own). When it modifies or quarantines the file before CFM's scan, CFM records
`skipped=gone_before_scan` or `inode_changed`, a useful cross-signal in itself.
CFM's `neutralize` and Imunify's cleanup must never fight over one file, which
is why quarantine defaults off there.

**CageFS / LVE.** CageFS confines the attacker to the cage, but the docroot is
inside the cage by design, so this policy is fully relevant on CloudLinux.
Inode keying (§3.5) makes the cage's bind mounts transparent. The per-user
`/tmp` inside CageFS is where `move_uploaded_file` sources come from
(`F_SRC_OUTSIDE_DOCROOT`).

**cfm-lsm siblings.** FS-005 (system paths) and EXEC-006 (exec from ephemeral
filesystems) are the later steps of the same attack. A record that shares
uid+pid lineage with an EXEC-003/005/006 event within minutes is linked in
the notify body (the uid swarm roster already collects the processes).

**Edge WAF.** Rules 332/416 and every other WAF tier become **evidence** for
attribution confidence (§5.4). A drop event never feeds `waf_security`'s
`WAFHitEvent` stream: it reaches bans only through its own `[php_drop]`
section.

## 8. Rollout — phases and promotion metrics

| Phase | What runs | Exit (promote) criteria — proposed, the operator sets the numbers |
|---|---|---|
| **P0 — count only** (≥ 2 weeks on 3 nodes of different stacks: cPanel+CloudLinux+Imunify, DirectAdmin, plain; then fleet ≥ 1 week) | BPF attached (monitor), daemon aggregates only: no scan, no per-event notify, no history rows beyond one daily aggregate per account | (1) BPF overhead: `file_open` `run_time_ns/run_cnt` < 100 ns on the busiest node, no measurable syscall p99 change. (2) `lost` = 0 at the p99 hour. (3) Events/node/day p50/p95 known **per writer class × context**, and **unclassified `php_web` creates** ≤ a few hundred/node/day (sized to scan). (4) `F_DEPTH_EXCEEDED` rare (< 0.1 %). (5) Every UP node with docroots shows non-zero events (D3a). |
| **P1 — scan + record** | debounce → clamd → history rows (§5.5); infected → notify; correlation recorded; chain tell recorded; quarantine off; `[php_drop] DRY_RUN = 1` (would-ban logged) | (1) clamd cost: drop scans add < 10 % to clamd CPU, never trip the breaker, never push the inline upload scan past its timeout. (2) ≥ 4 weeks fleet-wide. (3) Every `infected` reviewed: false-positive verdicts → sig-ignore entries; FP rate known. (4) Correlation: share of `infected`/`chain` rows with `unique` confidence ≥ 70 %. (5) Chain-tell FP sources listed (installer/kickstart patterns). |
| **P2 — suspect alerts + quarantine opt-in** | `php_drop_suspect` notifications (chain tell, `.user.ini`/`.htaccess` directive tells); `QUARANTINE = copy` offered; `neutralize` per node by the operator | (1) Suspect alerts ≤ ~1/node/week of noise after tuning. (2) At least one `neutralize` → `restore` drill done on a test account. |
| **P3 — autoblock** | `[php_drop] DRY_RUN = 0` on `infected + unique` (then, separately, `chain + unique`), `BLOCK = "6h"`, edgeban for proxied clients | (1) The P1 would-ban log over 4 weeks has **zero** bans that review calls wrong (an own-IP, a customer's office IP, a monitor). (2) Arming is per node first, then fleet: the same opt-in discipline as a newly block-promoted WAF family (CLAUDE.md §6). |
| *(not planned)* kernel deny | — | Would need its own proposal and burn-in (§3.7). |

Each phase's fleet read is one MCP call (`node_call node="all"
tool="php_drops"`), recorded with its date in the PR that promotes the phase.
That way the promotion decision is reviewable, not remembered.

## 9. Known gaps (honest limits)

* **Code that never becomes a PHP-executable file:** an `eval` of DB content
  (WPCode/Code Snippets-style persistence, a backdoor stored in
  `wp_options`), a shell saved as `x.jpg` and reached through an LFI
  `include()`, or a payload written to a non-docroot path the app includes.
  The edge WAF and Imunify PD remain the layers for those.
* **Writes through an fd held open past the +30 s re-check:** caught at the
  next open-for-write or by the operator's periodic scans, not by this net.
* **Directory renamed into a docroot** (`F_DIR_RENAME`): userspace walks the
  moved tree bounded (≤ 2 000 entries, ≤ depth 16). Beyond that the record is
  `skipped=dir_too_large` (still a notification-worthy oddity).
* **Paths deeper than 24 levels:** emitted with `F_DEPTH_EXCEEDED` and resolved
  in userspace, so it's a cost, not a miss. A deliberate 25-level nest is
  visible as such.
* **Writer-class evasion:** an attacker who gets a non-PHP-lineage process
  running as the account (stolen SSH/FTP/cPanel credentials, or a cron entry
  the account set up, whose `crond`-spawned children are not PHP-lineage
  unless they exec PHP) writes as `other`. That is dropped under the default
  `writers = php` (§11 Q4). A cron-launched PHP CLI is still `php_cli`.
* **Kernels without BPF LSM** (EL8 4.18; any node whose `lsm=` lacks `bpf` and
  that hasn't applied `KSEC-LSM-bpf-001`): preflight reports the policy
  `unavailable`, with no signal (§11 Q5).
* **Attribution is time+vhost, not pid:** on a busy vhost, `ranked` is the
  honest answer and bans need `unique`. An attacker who blends into heavy
  traffic gets notified about, not auto-banned.
* **ClamAV coverage:** a fresh shell with no signature is `clean`. The chain
  tell and the content tells exist so that "clean" is not the end of the
  story, and the clean record keeps the file findable for a later rescan
  (`cfm phpdrop rescan --since 7d` is a cheap follow-up once signatures update).

## 10. Alternatives considered

* **inotify / fanotify in userspace.** inotify needs one watch per directory
  (millions on a shared host) and gives no pid. fanotify
  `FAN_CLOSE_WRITE` + `FAN_MOVED_TO` with `FAN_REPORT_DFID_NAME` (5.9+) gives a
  pid and mount-wide marks. But it can't filter by uid or exe in the kernel,
  so every write on `/home` reaches userspace, and it has no PHP-lineage notion.
  It also doesn't help the 4.18 nodes BPF LSM can't reach either. It remains
  the only candidate fallback for kernels without BPF LSM (§11 Q5).
* **Periodic docroot scans (clamscan / find -newer).** These have no
  attribution and a detection delay of hours, and Imunify already does them
  where licensed. They are complementary, not a substitute.
* **Path-string matching in BPF** (`bpf_d_path` + prefix compare) is
  kernel-version-gated, breaks under CageFS views, and costs a string build on
  every candidate write. Rejected for inode ancestry (§3.5).
* **Reusing `clam.Manager.Enqueue`:** rejected. Its `TempCopy` semantics delete
  the scanned file, and `SCAN <path>` makes clamd follow attacker-controlled
  paths (§5.3).
* **Folding into FS-005:** FS-005 is a small-inode-set, enforce-capable policy
  on the shared ringbuf. Mixing a high-volume docroot stream into it would
  inherit its enforce semantics and starve its ringbuf.

## 11. Open questions for the operator

1. **Imunify nodes:** is `SCAN = auto` (§7) right, or do you want ClamAV on
   every drop there too (two engines, more I/O)? Or should CFM read Imunify's
   verdict for the path (`imunify360-agent malware malicious list --json`)
   instead of scanning?
2. **Quarantine:** is `neutralize` (root-owned, mode 0000, content untouched,
   restorable) acceptable for customer sites, or `copy` only? Who restores:
   only the node admin, or a scoped cPanel user from the plugin?
3. **Clean records:** is 20/account/hour individually, then hourly aggregates,
   right? Should scoped cPanel users see `php_drop_new` rows for their sites,
   or only `infected`/`suspect`?
4. **Writers:** keep `writers = php` (web-exploit net only), or also watch
   File Manager / FTP / SSH writes (`writers = all`, a stolen-credential net with
   much more noise)?
5. **EL8 / no-BPF-LSM nodes:** accept no coverage, plan a `fanotify` fallback,
   or push `KSEC-LSM-bpf-001` + reboot on those nodes first? Which nodes are
   affected today?
6. **Autoblock:** ban only on `infected + unique`, or also on `chain + unique`
   with no signature? Is the TTL 6 h like `waf_security`, or longer for a
   confirmed drop?
7. **Bursts:** are coalesced batch scans of whole core/plugin updates worth the
   clamd time, or sample-only (e.g. 10 % plus every file outside known trees)?
8. **`.htaccess` / `.user.ini`:** in scope from P0 (they're noisy with
   Wordfence/LiteSpeed/Solid), or a later sub-phase?
9. **Plain (non-panel) hosts:** which nodes need a hand-written `docroot =`
   list, and is that list OK to keep in `lsm.conf`?
10. **Kernel config:** confirm `CONFIG_BPF_LSM` and the `lsm=` list per node
    class (EL9 5.14, EL10 6.12, Debian/Ubuntu) and whether `CONFIG_SECURITY_PATH`
    is set (only matters if `path_rename`/`path_truncate` are ever wanted).
11. **Alert routing:** `php_drop_infected` as `critical` to Slack + mail, and
    `php_drop_suspect` Slack-only?
12. **Retention:** the history store is bounded. Should infected/suspect rows
    also be PULLed into cfm-web for durable retention, as the fingerprint
    ledger is?

## 12. Implementation slices (when approved)

Many small, single-concern PRs (CLAUDE.md §9), each with the adversarial
self-review:

1. **`panelmap.Docroots()`** (cPanel + DA + operator list) with fixtures, and
   the inverse docroot → vhost set. Pure Go, no LSM.
2. **BPF `CFML-FS-009`, P0:** programs, the four new maps, the dedicated
   ringbuf, the struct, the parser, policy ID 20, the `lsm.conf` stanza,
   monitor-only in `isEnforceCapable`, `TestPolicyByID_BPFConstantsMatchGoConstants`,
   the extension-class parity test, `cfm lsm status` counters, and the
   `php_drops` aggregate MCP tool. Also: the `cfm-lsm.md` catalogue entry and
   the pointer under FS-003.
3. **Scanner:** `internal/phpdrop` coalescer + workers, `clam.Breaker`
   export, `openat2` + inode check, the fake-clamd test harness, and the
   never-delete test.
4. **Records + notify:** history types, the endpoint scope inventory,
   scoped stripping, rate-limited clean rows.
5. **Correlator + chain tell.**
6. **Quarantine** (`copy`, `neutralize`, `restore`).
7. **`[php_drop]` detector section → autoblock sink** (`DRY_RUN = 1`).

Each runtime PR carries its `CHANGELOG.md` `[Unreleased]` entry. This design
doc itself is docs-only and needs none.
