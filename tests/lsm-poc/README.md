# cfm-lsm PoC harness

End-to-end proof-of-concept harness that exercises every detector
shipped under `internal/lsm/` against realistic post-exploit
threat scenarios. Each PoC is the smallest realistic workflow an
attacker would actually run; the harness then tails `/var/log/cfm/lsm.log`
and confirms the expected `CFML-XXX-NNN` line appears.

The PoCs are **deliberately destructive primitives**: dropped setuid
binaries, fileless memfd payloads, sensitive-file writes by web
users, BPF map creation from non-trusted comms. They are exactly what
the LSM is supposed to catch — running them on a test host gives
you a reproducible baseline of detection.

## Hard rules — read before running

1. **Test host only.** Never run on production. The harness creates a
   throwaway `cfmpoc` user, temporarily loosens permissions on a
   sentinel file under `/etc/cron.d/` (root would honour a cron entry
   written there for the duration of the test), drops setuid binaries
   under `/var/lib/cfmpoc/`, and other state changes that are routine
   for a scratch VM but unacceptable on a live server.

2. **cfm-lsm must be in `mode = monitor`.** The PoCs are designed to
   fire the rule; in enforce mode the kernel will refuse the
   underlying syscall and the test will report a different failure.
   The harness checks this and refuses to run if any policy is in
   enforce mode (override with `--allow-enforce` once you've read
   that section below).

3. **Cleanup is best-effort.** A `trap` runs on every exit path, but
   `kill -9` of the harness can leave the test user, sentinel files,
   `/var/lib/cfmpoc/.cfmpoc-*` staged binaries, and `/tmp/cfmpoc-*`
   artefacts behind. To clean up by hand:
   `userdel cfmpoc; rm -rf /var/lib/cfmpoc /tmp/cfmpoc /etc/cron.d/.cfmpoc-*`.

   On hardened hosts where `/tmp` is mounted `noexec,nosuid` (EL10 /
   CL10 default, increasingly common on cPanel), the harness puts
   stash binaries under `/var/lib/cfmpoc/` instead so the exec
   actually lands. EXEC-006 (the only scenario whose threat model
   *is* exec-from-/tmp) probes both `/tmp` and `/var/tmp`; if neither
   is exec-capable it logs a SKIP rather than a false FAIL.

4. **Some PoCs need a network socket.** EXEC-003 / EXEC-005 open a
   loopback TCP listener on a randomly chosen port (default 4444).
   Pass `--listener-port N` to override. If your test box has
   nothing listening on 0.0.0.0, this is harmless; if it does, pick
   a different port.

5. **CRED-003 has no clean userland PoC.** The rule fires on direct
   `commit_creds()` calls that bypass `task_fix_setuid` — that path
   is reachable only via a kernel exploit or a custom kernel module.
   The CRED-003 scenario reports the hook's attached state from
   `bpftool prog list` and links to an out-of-tree kernel-module
   variant for operators who want full coverage.

## Usage

```sh
# Build the C helpers (requires gcc + kernel headers for the bpf one)
make -C tests/lsm-poc/helpers

# Run every scenario; fail fast on first mismatch
sudo tests/lsm-poc/run-all.sh

# Run a single scenario
sudo tests/lsm-poc/scenarios/exec-001-memfd.sh

# Continue on failure to collect a full report
sudo tests/lsm-poc/run-all.sh --keep-going

# Verbose mode shows the trigger commands as they execute
sudo tests/lsm-poc/run-all.sh -v
```

## What each scenario proves

| Rule | Scenario | Threat model |
|---|---|---|
| CFML-EXEC-001 | `exec-001-memfd.sh` | Fileless ELF loader: payload lives only in a `memfd_create` fd, never touches disk. The textbook fileless-malware pattern. |
| CFML-EXEC-003 | `exec-003-revshell.sh` | Classic reverse shell: `bash -i` with stdin/stdout/stderr dup'd to a remote TCP socket in `ESTABLISHED` state. |
| CFML-EXEC-004 | `exec-004-deleted.sh` | Drop-unlink-exec by a web-class uid: webshell writes a binary to `/tmp`, opens it, unlinks the path, then `fexecve()`s the still-open fd to break forensics. |
| CFML-EXEC-005 | `exec-005-interp.sh` | Weak reverse-shell variant: interpreter (python/bash) with only one or two of stdin/stdout/stderr pointing at a remote TCP socket. Survives the strict-three-fd bypass. |
| CFML-EXEC-006 | `exec-006-tmp.sh` | Web-class uid exec from `/tmp`: payload staged in `/tmp/.<obfuscated>` and exec'd by the same PHP-FPM-like worker that wrote it. Execution-phase companion to Imunify Proactive Defense's write-phase guard. |
| CFML-FS-005 | `fs-005-sensitive.sh` | Post-privesc cash-in: web user (after gaining root via any other bug) writes to `/etc/sudoers.d/` to install a persistent backdoor. |
| CFML-FS-006 | `fs-006-fdleak.sh` | Setuid-helper fd-leak class: a privileged process opens `/etc/shadow`, drops to a non-root uid, then reads through the fd it still holds. Same kernel-side fingerprint as the `pidfd_getfd` race against ssh-keysign / chage / unix_chkpwd. |
| CFML-CRED-002 | `cred-002-suid-dropper.sh` | Post-exploit persistence: attacker dropped a setuid-root binary at `/tmp/.bd` during a transient root window. Subsequent runs by an unprivileged user re-acquire root without re-exploiting. The dropper is not on the disk-walked setuid path list, so CRED-002 fires. |
| CFML-CRED-003 | `cred-003-direct-cred.sh` | Kernel-exploit fingerprint: direct `commit_creds(prepare_kernel_cred(NULL))` from ROP without going through `task_fix_setuid`. No clean userland PoC; scenario reports attached-state from `bpftool` and points to the optional kernel-module harness. |
| CFML-BPF-001 | `bpf-001-mapcreate.sh` | BPF rootkit installer: untrusted comm calls `bpf(BPF_MAP_CREATE, ...)` and `bpf(BPF_PROG_LOAD, ...)` to set up a stealth tracing program. Real-world example: bvp47 / boopkit. |
| CFML-FS-007 | `fs-007-priv-install.sh` | Privilege-primitive install. Two legs: (1) watched-uid `chmod 4755` on a binary they own — the suid-bit dropper. (2) watched-uid `setcap cap_setuid+ep` via the security.capability xattr — the harder-to-spot file-capability variant. Companion to CRED-002 which catches the *use* of the dropped primitive; FS-007 catches the *install*. |
| CFML-EXEC-007 | `exec-007-kmod-load.sh` | Kernel rootkit installer: non-trusted comm calls `init_module(2)` / `finit_module(2)`. The tracepoint fires on syscall entry, so the PoC succeeds even with bogus module args (/dev/null on finit_module returns -ENOEXEC, but the event lands). Renames the helper to `.cfm-rootkit-loader` so the kernel-side trusted-loader allowlist (modprobe / insmod / kmod / systemd / systemd-modules / systemd-udevd) doesn't suppress. |
| CFML-FS-008 | `fs-008-corepattern-write.sh` | Kernel-exploit completion pivot: write to `/proc/sys/kernel/core_pattern` from a non-trusted comm (saves and restores the original value). Same threat class as the modprobe_path / sysrq-trigger / uevent_helper writes the rule covers — every public Linux kernel exploit from the last five years routes through one of these once it has the write primitive. |
| CFML-EXEC-008 | `exec-008-kexec-load.sh` | Rootkit persistence via post-boot kernel replacement: non-trusted comm calls `kexec_load(2)` / `kexec_file_load(2)` to stage a backdoored kernel image. The tracepoints fire on syscall entry, so the PoC succeeds even with bogus args (/dev/null on kexec_file_load returns -EPERM / -EINVAL, but the event lands). Renames the helper to `.cfm-kernel-stager` so the kernel-side trusted-loader allowlist (kexec / systemctl) doesn't suppress. Companion telemetry to kernsec's `kernel.kexec_load_disabled=1` (KSEC-SCT-kspp.kexec-001): on hosts that applied the sysctl, the syscall returns -EPERM but EXEC-008 still records the attempt — the forensic-trail co-design. |

## File layout

```
tests/lsm-poc/
├── README.md                      this file
├── run-all.sh                     top-level harness
├── lib.sh                         shared bash helpers
├── scenarios/                     one .sh per detector
└── helpers/                       small C programs the scenarios invoke
    ├── Makefile
    └── *.c
```

## What "PASS" actually means

A PASS for a scenario means: between the moment the harness marked
`lsm.log`'s position and the timeout, a line tagged with the
expected policy ID appeared with a pid matching the trigger process.

A FAIL means either:
- the policy is in `disabled` (rule not loaded, no events possible),
- the policy line never appeared within the timeout (detector miss),
- the policy line appeared with the wrong pid (some other event
  unrelated to this PoC — the harness flags this as a probable
  false-positive in the log rather than a genuine PASS).

The harness emits a final summary table with per-scenario PASS / FAIL
/ SKIP and exits non-zero if any scenario failed unless
`--keep-going` was passed.

## Diagnostics for partial-PASS runs

### "scenario SKIPped because test user is not in cfm_watched_uids"

EXEC-004, EXEC-006, and FS-005 are gated on the calling task's uid
being in the `cfm_watched_uids` BPF map. On a host with a
cPanel / DirectAdmin / Plesk manifest, the daemon populates that
map from the panel's account list and skips the uid-range fallback.
The harness's throwaway `cfmpoc` user (uid 1500) is then **not** in
the map and those three rules won't fire from it.

To make the harness exercise those rules on a panel host:

```sh
# 1. Ensure /etc/cfm/lsm.conf has the new shipped default:
#       watched_uid_fallback_min = 1000      # login.defs UID_MIN convention
#    (The default used to be -1 "auto", which silently skipped the
#    uid-range fallback on panel hosts. That created a coverage gap
#    for admin accounts; the new default closes it. -1 still parses
#    as a deprecated alias for 1000 with a one-time warning.)
# 2. Optionally opt-out your own admin accounts so YOUR sysadmin
#    sessions stay quiet:
#       exclude_user = your-admin-login
#       exclude_uid  = 1001
# 3. Apply:
sudo cfm lsm restart
# 4. Re-run the harness. EXEC-004 / EXEC-006 / FS-005 / FS-007
#    should now PASS from the cfmpoc test user (uid 1500).
```

1000 is the production-realistic threshold: it matches `/etc/login.defs`'s
`UID_MIN` on every modern distro, so the watched-uid set includes
every regular login account on the host — exactly what you want
post-test-window for catching webshell behavior on a real workload.
The throwaway `cfmpoc` user the harness creates lives at uid 1500
and falls inside that range.

Inspect the live map to confirm:

```sh
sudo bpftool map dump pinned /sys/fs/bpf/cfm/maps/cfm_watched_uids
```

### "no CFML-FS-006 line within Ns" after FS-006 PASSed previously

Background activity that rewrites `/etc/shadow` (`passwd` /
`chage` / `cron` shadow rotation) changes the file's inode. The
`cfm_watched_inodes` map still has the old inode from the last
`PopulateMaps` run; the live read goes to a different inode, the BPF
lookup misses, and FS-006 stays silent.

Compare live inode to the cached map:

```sh
stat -c 'live ino=%i' /etc/shadow
sudo bpftool map dump pinned /sys/fs/bpf/cfm/maps/cfm_watched_inodes \
  | grep -A1 key
```

Resolve by re-running `sudo cfm lsm restart` — it re-runs
`PopulateMaps` against the live filesystem.

### "no CFML-CRED-002 line" with a setuid-bit dropper

If you write your own CRED-002 PoC: the rule fires on
`task_fix_setuid` (the LSM hook for the setuid SYSCALL family) but
**not** on execve's setuid-bit elevation (which uses
`bprm_creds_for_exec`). A `chmod 4755` dropper that does `setuid(0)`
inside `main()` sees `old_euid == 0` already (set by execve), so
CRED-002 returns early on the "already root" check.

The right trigger is `cap_setuid+ep` file capabilities:

```sh
setcap cap_setuid+ep /tmp/.bd  # no setuid bit, just cap_setuid
```

The shipped scenario does exactly this — same threat model as a
suid-bit dropper, but with a privilege primitive that `task_fix_setuid`
actually observes.

## Maintenance

When a detector's trigger condition changes (e.g. a new dimension
added to CFML-CRED-002's setuid check), the corresponding scenario
script needs to be updated to keep firing the rule. Add the new
allowlist dimension to `internal/lsm/conf.go` AND a matching
"this would still fire" PoC variant under `scenarios/`. The point
of the harness is regression coverage — a quiet `run-all.sh` after
an allowlist tightening is the early warning that the tightening
went too far.
