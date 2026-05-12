/* SPDX-License-Identifier: GPL-2.0
 *
 * cfm-lsm BPF programs.
 *
 * One translation unit, two LSM programs, one shared ringbuf — the
 * simplest layout that lets the Go loader open a single Reader and
 * receive a merged-by-timestamp stream of events from both policies.
 *
 * Programs
 * --------
 *   cfm_memfd_exec  — CFML-EXEC-001 (memfd exec detector)
 *   cfm_revshell    — CFML-EXEC-003 (reverse-shell-pattern detector)
 *
 * Both hook bprm_check_security and default to monitor mode. Per
 * docs/cfm-lsm.md the enforce-mode flip happens via a bpf2go
 * constant rewrite once telemetry justifies it; audit emission is
 * best-effort, but enforce/allow verdicts must not depend on
 * ringbuf capacity or daemon availability.
 *
 * Verifier strategy
 * -----------------
 * - All kernel reads go through BPF_CORE_READ / bpf_probe_read_kernel
 *   so CO-RE resolves offsets at load time.
 * - The fd 0/1/2 walk in cfm_revshell is unrolled (three explicit
 *   calls, no loop) to stay well under older kernels' complexity
 *   budget.
 * - Every program returns 0 early as soon as a check fails; the
 *   "match" path is the rare path.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "common.bpf.h"

/* Magic from include/uapi/linux/magic.h. Stable since 2.6. */
#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

/* Shared ringbuf for both programs. Both policies emit struct
 * cfm_lsm_event; the leading policy_id field tells the Go reader
 * which one fired. 256 KiB is generous for the MVP — exec is not a
 * hot path. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} cfm_events SEC(".maps");

/* Per-policy enforcement mode. Rewritten by the Go loader at load
 * time via spec.RewriteConstants() — see internal/lsm/loader.go.
 *
 * Values:
 *   0  monitor mode  — emit event, allow (return 0)
 *   1  enforce mode  — emit event, block  (return -EPERM)
 *
 * Defaults are 0 (monitor) so an operator who forgets to rewrite —
 * or a partial / out-of-tree integration that loads the object
 * directly — gets the safe behaviour. Enforce mode is opt-in.
 *
 * `volatile const` is the canonical pattern: const so the verifier
 * accepts the load as a global, volatile so the compiler does not
 * fold the comparison at compile time (otherwise the unreachable
 * branch would be dead code stripped and the rewrite would have
 * nothing to flip). */
volatile const __u8 cfm_enforce_memfd_exec = 0;
volatile const __u8 cfm_enforce_revshell   = 0;

/* EPERM (1) — what bprm_check_security returns when an LSM denies
 * the exec. Keeps the negative-errno convention explicit. */
#define CFM_LSM_DENY (-1)

/* Audit emission is best-effort. Once a policy match is established,
 * the final LSM verdict depends only on the policy's enforce constant,
 * not on whether the shared ringbuf has room for an audit event. */
static __always_inline int cfm_exec_verdict(__u8 enforce)
{
    if (enforce)
        return CFM_LSM_DENY;
    return 0;
}

/* ------------------------------------------------------------------- *
 * CFML-EXEC-001 — Block exec from memfd.
 *
 * Hook: bprm_check_security (LSM)
 *
 * Mechanism: inspect bprm->file. If the backing inode is on a tmpfs
 * superblock AND the dentry name starts with "memfd:", this is a
 * memfd_create()'d payload being exec'd — the canonical fileless
 * post-exploit pattern.
 *
 * Mode: defaults to monitor (return 0). Enforce mode returns
 * -EPERM once telemetry confirms a near-zero FP rate.
 * ------------------------------------------------------------------- */

static __always_inline bool dentry_name_is_memfd(struct dentry *d)
{
    const unsigned char *name = NULL;
    char buf[8] = {};

    name = BPF_CORE_READ(d, d_name.name);
    if (!name)
        return false;

    /* Read 7 bytes (6 chars + NUL). Anything shorter than "memfd:"
     * cannot match. */
    long n = bpf_probe_read_kernel_str(buf, sizeof(buf), name);
    if (n < 6)
        return false;

    return buf[0] == 'm' && buf[1] == 'e' && buf[2] == 'm' &&
           buf[3] == 'f' && buf[4] == 'd' && buf[5] == ':';
}

SEC("lsm/bprm_check_security")
int BPF_PROG(cfm_memfd_exec, struct linux_binprm *bprm, int ret)
{
    struct file *file;
    struct inode *inode;
    struct super_block *sb;
    struct dentry *dentry;
    unsigned long magic;

    /* Honour earlier LSMs' deny verdicts — never undo a block. */
    if (ret != 0)
        return ret;

    file = BPF_CORE_READ(bprm, file);
    if (!file)
        return 0;

    inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    sb = BPF_CORE_READ(inode, i_sb);
    if (!sb)
        return 0;

    magic = BPF_CORE_READ(sb, s_magic);
    if (magic != TMPFS_MAGIC)
        return 0;

    dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return 0;

    if (!dentry_name_is_memfd(dentry))
        return 0;

    /* Match. Audit emission is best-effort; the enforce verdict still
     * applies if the shared ringbuf is full or unavailable. */
    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return cfm_exec_verdict(cfm_enforce_memfd_exec);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = CFM_LSM_POLICY_MEMFD_EXEC;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->op        = 0;
    e->flags     = 0;
    e->_pad1     = 0;
    e->_pad2     = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    if (name)
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), name);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);

    /* Enforce mode: block the exec. Monitor mode: allow. */
    return cfm_exec_verdict(cfm_enforce_memfd_exec);
}

/* ------------------------------------------------------------------- *
 * CFML-EXEC-003 — Reverse-shell pattern.
 *
 * Hook: bprm_check_security (LSM)
 *
 * Mechanism: at exec, look at the calling task's fd 0/1/2. A
 * reverse shell exists when ALL THREE point at AF_INET / AF_INET6
 * sockets in TCP_ESTABLISHED state. AF_UNIX is explicitly skipped —
 * unix-domain sockets dup'd to 0/1/2 are how systemd / journald /
 * supervisord wire up local workers and would be a FP carnival.
 * LISTEN / SYN_SENT states are skipped too: those are inetd-style
 * accepts and async-connect, not currently-talking-to-a-remote.
 *
 * We use `inode->i_mode & S_IFMT == S_IFSOCK` rather than comparing
 * f_op against &socket_file_ops because the former needs no kernel
 * symbol lookup and is exactly as specific.
 *
 * Mode: defaults to monitor (return 0). Per docs/cfm-lsm.md this
 * stays in monitor mode for 30 days before any enforce promotion —
 * fd-walk detectors traditionally surface unanticipated legitimate
 * patterns for the first month.
 * ------------------------------------------------------------------- */

static __always_inline int fd_is_remote_tcp(struct file **fdarr,
                                            unsigned int max_fds,
                                            unsigned int i)
{
    struct file *f;
    struct inode *ino;
    struct socket *sock;
    struct sock *sk;
    __u16 mode;
    __u16 family;
    __u8  state;

    if (i >= max_fds)
        return 0;

    /* fdarr is an array of struct file* in kernel memory. */
    if (bpf_probe_read_kernel(&f, sizeof(f), &fdarr[i]) != 0)
        return 0;
    if (!f)
        return 0;

    ino = BPF_CORE_READ(f, f_inode);
    if (!ino)
        return 0;

    mode = BPF_CORE_READ(ino, i_mode);
    if ((mode & S_IFMT) != S_IFSOCK)
        return 0;

    sock = (struct socket *)BPF_CORE_READ(f, private_data);
    if (!sock)
        return 0;

    sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;

    state = BPF_CORE_READ(sk, __sk_common.skc_state);
    if (state != TCP_ESTABLISHED)
        return 0;

    return 1;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(cfm_revshell, struct linux_binprm *bprm, int ret)
{
    struct task_struct *task;
    struct files_struct *files;
    struct fdtable *fdt;
    struct file **fdarr;
    unsigned int max_fds;

    if (ret != 0)
        return ret;

    task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    files = BPF_CORE_READ(task, files);
    if (!files)
        return 0;

    fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return 0;

    max_fds = BPF_CORE_READ(fdt, max_fds);
    fdarr   = BPF_CORE_READ(fdt, fd);
    if (!fdarr || max_fds < 3)
        return 0;

    /* All three of stdin/stdout/stderr must be connected remote TCP. */
    if (!fd_is_remote_tcp(fdarr, max_fds, 0))
        return 0;
    if (!fd_is_remote_tcp(fdarr, max_fds, 1))
        return 0;
    if (!fd_is_remote_tcp(fdarr, max_fds, 2))
        return 0;

    /* Match. Audit emission is best-effort; the enforce verdict still
     * applies if the shared ringbuf is full or unavailable. */
    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return cfm_exec_verdict(cfm_enforce_revshell);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = CFM_LSM_POLICY_REVERSE_SHELL;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->op        = 0;
    e->flags     = 0;
    e->_pad1     = 0;
    e->_pad2     = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Filename: the binary being exec'd (the would-be shell). */
    const char *fname = BPF_CORE_READ(bprm, filename);
    if (fname)
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), fname);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);

    /* Enforce mode: block the exec. Monitor mode: allow. */
    return cfm_exec_verdict(cfm_enforce_revshell);
}

/* ------------------------------------------------------------------- *
 * CFML-FS-005 — Sensitive-file modification by web user.
 *
 * Hooks: six write-class inode hooks (setattr / create / unlink /
 *        link / rename / setxattr).
 *
 * Mechanism: at every write-class inode op, look up the calling
 * uid in `cfm_watched_uids` (populated by the cfm daemon from
 * /etc/passwd / panel manifests at attach time). If matched, look
 * up the target filesystem+inode key in `cfm_watched_inodes`
 * (populated by the daemon stat()ing each sensitive path). If THAT also matches,
 * emit an event tagged with the op kind.
 *
 * The filesystem+inode match avoids BPF-side path walking entirely
 * while disambiguating identical inode numbers on different mounts.
 * For paths under sensitive directories (e.g. a new file in
 * /etc/sudoers.d/), the daemon also pins the parent directory's
 * inode and inode_create checks the dir's inode (which the hook
 * argument gives us directly).
 *
 * Enforcement: opt-in via volatile-const flip, same model as
 * EXEC-001 / EXEC-003. On enforce, return -EPERM so the write
 * fails outright.
 *
 * Verifier complexity: lower than EXEC-003 (no bounded loops, no
 * fd walking; just two map lookups + a few CO-RE reads).
 * ------------------------------------------------------------------- */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} cfm_watched_uids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct cfm_inode_key);
    __type(value, __u8);
} cfm_watched_inodes SEC(".maps");

volatile const __u8 cfm_enforce_sensitive_write = 0;

/* Emit one FS-005 event. Caller has already established that uid
 * + target inode are both in the watched sets. */
static __always_inline void cfm_fs005_emit(struct dentry *target,
                                           const char *fname_fallback,
                                           __u8 op)
{
    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = CFM_LSM_POLICY_SENSITIVE_WRITE;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->op        = op;
    e->flags     = 0;
    e->_pad1     = 0;
    e->_pad2     = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Filename: best-effort from the target dentry. For create/
     * rename the target dentry's d_name is the new name; for other
     * ops it is the existing name. */
    const unsigned char *name = NULL;
    if (target)
        name = BPF_CORE_READ(target, d_name.name);
    if (name) {
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), name);
    } else if (fname_fallback) {
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), fname_fallback);
    } else {
        e->filename[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
}

/* Convert kernel-internal dev_t (super_block->s_dev) to the same
 * encoding userspace sees in stat(2)'s st_dev. */
static __always_inline __u64 cfm_stat_dev_from_sdev(__u32 s_dev)
{
    __u32 major = s_dev >> 20;
    __u32 minor = s_dev & ((1U << 20) - 1);

    return (__u64)(minor & 0xff) | ((__u64)major << 8) |
           ((__u64)(minor & ~0xff) << 12);
}

/* Build the compound filesystem+inode key used by inode maps. */
static __always_inline bool cfm_inode_key_from_inode(struct inode *inode,
                                                     struct cfm_inode_key *key)
{
    if (!inode || !key)
        return false;

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (!sb)
        return false;

    __u32 s_dev = BPF_CORE_READ(sb, s_dev);
    key->dev = cfm_stat_dev_from_sdev(s_dev);
    key->ino = (__u64)BPF_CORE_READ(inode, i_ino);
    return true;
}

/* Look up one dentry's d_inode as a filesystem+inode key in
 * cfm_watched_inodes. Returns true on match. NULL dentry / NULL inode
 * are both treated as "no match" (the dentry passed at create-time has
 * no inode yet — the caller must pass d_parent in that case). */
static __always_inline bool cfm_fs005_inode_watched(struct dentry *d)
{
    if (!d)
        return false;
    struct inode *ino = BPF_CORE_READ(d, d_inode);

    struct cfm_inode_key key = {};
    if (!cfm_inode_key_from_inode(ino, &key))
        return false;
    return bpf_map_lookup_elem(&cfm_watched_inodes, &key) != NULL;
}

/* Shared check helper. Returns:
 *   0       — not a watched (uid, inode) pair — allow.
 *   0       — watched, monitor mode — emit event, allow.
 *  -EPERM   — watched, enforce mode — emit event, block.
 *
 * Looks up TWO filesystem+inode keys against cfm_watched_inodes:
 * `primary` and `secondary`. Either being in the set is a match. Callers pick the
 * pair that fits the LSM hook's semantics:
 *
 *   setattr / setxattr:   primary = file dentry,        secondary = NULL
 *   create:               primary = parent dir dentry,  secondary = NULL
 *                         (new dentry has no inode yet)
 *   unlink:               primary = file dentry,        secondary = parent
 *                         (catches rm /etc/passwd AND rm /etc/cron.d/foo)
 *   link / rename:        primary = new_dentry's parent, secondary = old_dentry's parent
 *                         (catches "into watched dir" AND "out of watched dir")
 *
 * Two map lookups is well under any verifier complexity budget; both
 * legs short-circuit via the uid pre-check (most calls return 0
 * without touching the inode set at all). */
static __always_inline int cfm_fs005_check2(struct dentry *primary,
                                            struct dentry *secondary,
                                            struct dentry *event_dentry,
                                            const char *fname_fallback,
                                            __u8 op, int ret)
{
    if (ret != 0)
        return ret;

    __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffffu);
    if (!bpf_map_lookup_elem(&cfm_watched_uids, &uid))
        return 0;

    if (!cfm_fs005_inode_watched(primary) && !cfm_fs005_inode_watched(secondary))
        return 0;

    struct dentry *ev = event_dentry;
    if (!ev)
        ev = primary ? primary : secondary;
    cfm_fs005_emit(ev, fname_fallback, op);

    if (cfm_enforce_sensitive_write)
        return CFM_LSM_DENY;
    return 0;
}

SEC("lsm/inode_setattr")
int BPF_PROG(cfm_fs005_setattr, struct mnt_idmap *idmap, struct dentry *dentry,
             struct iattr *attr, int ret)
{
    /* mnt_idmap was added to inode_setattr in kernel 6.3. Without it
     * in the signature, BPF_PROG silently shifts arg offsets and the
     * verifier rejects with "R2 pointer arithmetic with <<= operator
     * prohibited" when extracting `ret`. We don't read idmap fields. */
    return cfm_fs005_check2(dentry, NULL, dentry, NULL, CFM_FS_OP_SETATTR, ret);
}

SEC("lsm/inode_create")
int BPF_PROG(cfm_fs005_create, struct inode *dir, struct dentry *dentry,
             umode_t mode, int ret)
{
    /* For create, the dir's inode is what's already in our watched
     * set (e.g. /etc/sudoers.d/). The new dentry has no inode yet,
     * so we extract the parent via d_parent. */
    if (ret != 0)
        return ret;
    if (!dentry)
        return 0;
    struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
    return cfm_fs005_check2(parent, NULL, dentry, NULL, CFM_FS_OP_CREATE, 0);
}

SEC("lsm/inode_unlink")
int BPF_PROG(cfm_fs005_unlink, struct inode *dir, struct dentry *dentry, int ret)
{
    /* Two cases:
     *   - rm /etc/passwd            — dentry's own inode is watched.
     *   - rm /etc/cron.d/backdoor   — parent dir's inode is watched
     *                                  (post-exploit evidence-clearing).
     * Both fire the event. */
    struct dentry *parent = dentry ? BPF_CORE_READ(dentry, d_parent) : NULL;
    return cfm_fs005_check2(dentry, parent, dentry, NULL, CFM_FS_OP_UNLINK, ret);
}

SEC("lsm/inode_link")
int BPF_PROG(cfm_fs005_link, struct dentry *old_dentry, struct inode *dir,
             struct dentry *new_dentry, int ret)
{
    /* `dir` is the parent inode of `new_dentry`. We walk d_parent on
     * both dentries so the helper can rely on dentry->d_inode for
     * uniformity. Catches `ln /tmp/payload /etc/sudoers.d/x` (target
     * parent watched) and `ln /etc/cron.d/x /tmp/y` (source parent
     * watched — moving a watched file). */
    struct dentry *new_parent = new_dentry ? BPF_CORE_READ(new_dentry, d_parent) : NULL;
    struct dentry *old_parent = old_dentry ? BPF_CORE_READ(old_dentry, d_parent) : NULL;
    return cfm_fs005_check2(new_parent, old_parent, new_dentry, NULL, CFM_FS_OP_LINK, ret);
}

SEC("lsm/inode_rename")
int BPF_PROG(cfm_fs005_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry, int ret)
{
    /* Catches `mv /tmp/payload /etc/sudoers.d/x` (drop-via-rename:
     * a common way to evade inode_create-only hooks) AND moves
     * out of a watched dir. */
    struct dentry *new_parent = new_dentry ? BPF_CORE_READ(new_dentry, d_parent) : NULL;
    struct dentry *old_parent = old_dentry ? BPF_CORE_READ(old_dentry, d_parent) : NULL;
    return cfm_fs005_check2(new_parent, old_parent, new_dentry, NULL, CFM_FS_OP_RENAME, ret);
}

SEC("lsm/inode_setxattr")
int BPF_PROG(cfm_fs005_setxattr, struct mnt_idmap *idmap, struct dentry *dentry,
             const char *name, const void *value, size_t size, int flags, int ret)
{
    /* mnt_idmap was added to inode_setxattr in kernel 6.3 — same
     * fix as inode_setattr above. */
    return cfm_fs005_check2(dentry, NULL, dentry, NULL, CFM_FS_OP_SETXATTR, ret);
}

/* ------------------------------------------------------------------- *
 * CFML-CRED-002 — Privilege escalation without setuid path.
 *
 * Hook: task_fix_setuid (LSM)
 *
 * We hook task_fix_setuid rather than cred_prepare because
 * cred_prepare runs inside prepare_creds() *before* the caller has
 * mutated new->euid — at that point new is a byte-for-byte copy of
 * old, so a "new_euid==0 && old_euid!=0" gate is mathematically
 * unsatisfiable. task_fix_setuid fires from __sys_setresuid /
 * __sys_setuid / __sys_setreuid / __sys_setfsuid *after* the new
 * cred's uid fields have been written, so the comparison is
 * meaningful.
 *
 * Mechanism: on every setuid-family syscall, compare:
 *   - new cred's euid is 0
 *   - old cred's euid is not 0
 *   - current task's mm->exe_file's filesystem+inode key is NOT in
 *     `cfm_setuid_inodes` (populated by the daemon walking the host
 *     for files with S_ISUID set).
 *
 * If all three hold, the task is gaining root via a setuid()-family
 * call from a binary that is not on disk with the suid bit set.
 * That covers ordinary post-exploit pivots where a webshell calls
 * setresuid(0,0,0) after a kernel exploit installed root creds.
 *
 * Scope note: task_fix_setuid does NOT fire when a kernel exploit
 * installs creds directly via commit_creds() / prepare_kernel_cred()
 * without going through a userspace setuid syscall. That class is
 * tracked as a known gap in docs/cfm-lsm.md — a kprobe on
 * commit_creds is the canonical fix and is a separate follow-up.
 *
 * Mode: monitor ONLY. Returning -EPERM from this hook can deadlock
 * systemd helpers and pkexec mid-transition. CRED-002's value is
 * in the alert, not the block. No enforce constant for this policy.
 * ------------------------------------------------------------------- */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct cfm_inode_key);
    __type(value, __u8);
} cfm_setuid_inodes SEC(".maps");

SEC("lsm/task_fix_setuid")
int BPF_PROG(cfm_cred002, struct cred *new, const struct cred *old,
             int flags, int ret)
{
    if (ret != 0)
        return ret;
    if (!new || !old)
        return 0;

    __u32 new_euid = BPF_CORE_READ(new, euid.val);
    __u32 old_euid = BPF_CORE_READ(old, euid.val);

    /* Only suspicious: non-root → root. */
    if (new_euid != 0 || old_euid == 0)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return 0;
    struct file *exe = BPF_CORE_READ(mm, exe_file);
    if (!exe)
        return 0;
    struct inode *exe_ino = BPF_CORE_READ(exe, f_inode);
    if (!exe_ino)
        return 0;
    struct cfm_inode_key key = {};
    if (!cfm_inode_key_from_inode(exe_ino, &key))
        return 0;

    /* Whitelist hit — legitimate setuid binary path. */
    if (bpf_map_lookup_elem(&cfm_setuid_inodes, &key))
        return 0;

    /* Match. Emit event. Never block (monitor-only by design). */
    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = CFM_LSM_POLICY_CRED_ESCAL;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->op        = 0;
    e->flags     = 0;  /* reserved for future: old_euid byte */
    e->_pad1     = 0;
    e->_pad2     = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Filename: the executable inode that took the cred. Operator
     * uses this to identify the offending binary in forensics. */
    struct dentry *exe_dentry = BPF_CORE_READ(exe, f_path.dentry);
    const unsigned char *name = NULL;
    if (exe_dentry)
        name = BPF_CORE_READ(exe_dentry, d_name.name);
    if (name)
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), name);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0; /* monitor-only by design */
}

char LICENSE[] SEC("license") = "GPL";
