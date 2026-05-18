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
 *   cfm_interp_net_stdio
 *                   — CFML-EXEC-005 (weak interpreter net-stdio telemetry)
 *   cfm_deleted_file_exec
 *                   — CFML-EXEC-004 (deleted/unlinked exec by web user)
 *   cfm_cred003     — CFML-CRED-003 (direct root cred install detector)
 *
 * Exec policies hook bprm_check_security and default to monitor mode. Per
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
volatile const __u8 cfm_enforce_memfd_exec         = 0;
volatile const __u8 cfm_enforce_revshell           = 0;
volatile const __u8 cfm_enforce_deleted_file_exec  = 0;
volatile const __u8 cfm_enforce_ephemeral_exec     = 0;
/* CFML-EXEC-005 is monitor-only by default/design; no enforce constant. */

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

    task = bpf_get_current_task_btf();
    if (!task)
        return 0;

    /* Honour the documented uid 0 exemption (see docs/cfm-lsm.md
     * §"CFML-EXEC-003 — Reverse shell pattern" → Exemptions).
     * Root reverse shells are an administrative choice — admin
     * SSH→`nc` debug sessions, inetd-style root services, and
     * incident-response rescue shells legitimately have stdio
     * dup'd onto remote TCP. Enforce mode without this skip
     * would break those workflows. Checking effective uid matches
     * the doc's intent: "running as root via any mechanism."
     * Real uid is left unchecked so attackers who somehow exec'd
     * a setuid-root binary still get the rule's protection in the
     * non-root caller case. */
    __u32 euid = BPF_CORE_READ(task, cred, euid.val);
    if (euid == 0)
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
    e->flags     = CFM_LSM_F_REVSHELL_STRICT;
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
 * CFML-EXEC-005 — Suspicious interpreter network stdio.
 *
 * Hook: bprm_check_security (LSM)
 *
 * Mechanism: reuse CFML-EXEC-003's fd inspection and look for a weaker
 * companion signal: one or two of fd 0/1/2 are established remote TCP
 * sockets AND the executable basename is a shell/interpreter/network
 * stdio helper commonly used in one-liners. Three remote stdio fds are
 * left to the strict CFML-EXEC-003 rule to avoid duplicate telemetry.
 *
 * Mode: monitor-only. This intentionally has no enforce constant; weak
 * telemetry catches context around inetd-style services, admin one-liners,
 * and debugging sessions, so enforcement belongs only in the strict rule.
 * ------------------------------------------------------------------- */

static __always_inline int cfm_str_eq(const char *s, const char *lit, int lit_len)
{
    int i;

#pragma unroll
    for (i = 0; i < 16; i++) {
        if (i > lit_len)
            break;
        char c = s[i];
        char want = lit[i];
        if (c != want)
            return 0;
        if (want == '\0')
            return 1;
    }

    return 0;
}

static __always_inline int cfm_suspicious_exec_basename(const char *base)
{
    if (cfm_str_eq(base, "sh", 2)) return 1;
    if (cfm_str_eq(base, "bash", 4)) return 1;
    if (cfm_str_eq(base, "dash", 4)) return 1;
    if (cfm_str_eq(base, "zsh", 3)) return 1;
    if (cfm_str_eq(base, "python", 6)) return 1;
    if (cfm_str_eq(base, "python3", 7)) return 1;
    if (cfm_str_eq(base, "perl", 4)) return 1;
    if (cfm_str_eq(base, "php", 3)) return 1;
    if (cfm_str_eq(base, "ruby", 4)) return 1;
    if (cfm_str_eq(base, "node", 4)) return 1;
    if (cfm_str_eq(base, "nc", 2)) return 1;
    if (cfm_str_eq(base, "ncat", 4)) return 1;
    if (cfm_str_eq(base, "socat", 5)) return 1;

    return 0;
}

static __always_inline int cfm_path_is_suspicious_basename(const char *path)
{
    char buf[CFM_FILENAME_LEN] = {};
    int base = 0;
    int i;

    if (!path)
        return 0;

    if (bpf_probe_read_kernel_str(buf, sizeof(buf), path) <= 0)
        return 0;

#pragma unroll
    for (i = 0; i < CFM_FILENAME_LEN; i++) {
        char c = buf[i];
        if (c == '/')
            base = i + 1;
        if (c == '\0')
            break;
    }

    /* cfm_str_eq() reads up to 16 bytes from the returned pointer; keep
     * the whole window inside buf so the verifier can prove the access
     * in-bounds for the variable-offset interior stack pointer. */
    if (base > CFM_FILENAME_LEN - 16)
        return 0;

    return cfm_suspicious_exec_basename(&buf[base]);
}

static __always_inline void cfm_emit_exec_stdio_event(struct linux_binprm *bprm,
                                                      __u32 policy_id,
                                                      __u8 flags)
{
    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = policy_id;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->op        = 0;
    e->flags     = flags;
    e->_pad1     = 0;
    e->_pad2     = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *fname = BPF_CORE_READ(bprm, filename);
    if (fname)
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), fname);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(cfm_interp_net_stdio, struct linux_binprm *bprm, int ret)
{
    struct task_struct *task;
    struct files_struct *files;
    struct fdtable *fdt;
    struct file **fdarr;
    unsigned int max_fds;
    int remote = 0;
    const char *fname;
    __u8 flags = CFM_LSM_F_INTERP_STDIO_WEAK;

    if (ret != 0)
        return ret;

    fname = BPF_CORE_READ(bprm, filename);
    if (!cfm_path_is_suspicious_basename(fname))
        return 0;

    task = bpf_get_current_task_btf();
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

    if (fd_is_remote_tcp(fdarr, max_fds, 0))
        remote++;
    if (fd_is_remote_tcp(fdarr, max_fds, 1))
        remote++;
    if (fd_is_remote_tcp(fdarr, max_fds, 2))
        remote++;

    if (remote == 1)
        flags |= CFM_LSM_F_STDIO_ONE_REMOTE;
    else if (remote == 2)
        flags |= CFM_LSM_F_STDIO_TWO_REMOTE;
    else
        return 0;

    cfm_emit_exec_stdio_event(bprm, CFM_LSM_POLICY_INTERP_NET_STDIO, flags);
    return 0;
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
 * (populated by the daemon stat()ing each sensitive or persistence path). The
 * map value distinguishes stable core paths that may enforce from broader
 * persistence paths that are always monitor-only. If THAT also matches, emit
 * an event tagged with the op kind.
 *
 * The filesystem+inode match avoids BPF-side path walking entirely
 * while disambiguating identical inode numbers on different mounts.
 * For paths under sensitive directories (e.g. a new file in
 * /etc/sudoers.d/), the daemon also pins the parent directory's
 * inode and inode_create checks the dir's inode (which the hook
 * argument gives us directly).
 *
 * Enforcement: opt-in via volatile-const flip, same model as
 * EXEC-001 / EXEC-003, but only for map entries marked enforceable by
 * userspace. Persistence-path entries report only, even when the policy mode
 * is enforce.
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

#define CFM_FS005_WATCH_ENFORCEABLE 1
#define CFM_FS005_WATCH_MONITOR_ONLY 2

/* Conservative feature gate for origin tracking. 0 preserves the
 * historical current-uid-only FS-005 behaviour; 1 tracks tasks that
 * started under web/panel uids and reports origin-only matches in
 * monitor mode, even if FS-005 itself is later set to enforce. */
volatile const __u8 cfm_fs005_web_origin_monitor = 0;

struct cfm_web_origin_state {
    __u8 web_origin;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __type(value, struct cfm_web_origin_state);
} cfm_web_origin_tasks SEC(".maps");

static __always_inline bool cfm_uid_watched(__u32 uid)
{
    return bpf_map_lookup_elem(&cfm_watched_uids, &uid) != NULL;
}

static __always_inline bool cfm_cred_has_watched_uid(const struct cred *cred)
{
    if (!cred)
        return false;

    __u32 uid = BPF_CORE_READ(cred, uid.val);
    if (cfm_uid_watched(uid))
        return true;
    uid = BPF_CORE_READ(cred, euid.val);
    if (cfm_uid_watched(uid))
        return true;
    uid = BPF_CORE_READ(cred, fsuid.val);
    return cfm_uid_watched(uid);
}

static __always_inline bool cfm_current_cred_has_watched_uid(void)
{
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task)
        return false;

    return cfm_cred_has_watched_uid(BPF_CORE_READ(task, cred));
}

static __always_inline bool cfm_task_is_web_origin(struct task_struct *task)
{
    if (!cfm_fs005_web_origin_monitor || !task)
        return false;

    struct cfm_web_origin_state *state =
        bpf_task_storage_get(&cfm_web_origin_tasks, task, 0, 0);
    return state && state->web_origin != 0;
}

static __always_inline void cfm_mark_current_web_origin(void)
{
    if (!cfm_fs005_web_origin_monitor)
        return;

    struct task_struct *task = bpf_get_current_task_btf();
    if (!task)
        return;

    struct cfm_web_origin_state *state =
        bpf_task_storage_get(&cfm_web_origin_tasks, task, 0,
                             BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (state)
        state->web_origin = 1;
}

static __always_inline void cfm_mark_current_web_origin_if_needed(void)
{
    if (!cfm_current_cred_has_watched_uid())
        return;
    cfm_mark_current_web_origin();
}

/* ------------------------------------------------------------------- *
 * CFML-EXEC-004 — Deleted-file exec by web user.
 *
 * Hook: bprm_check_security (LSM)
 *
 * Mechanism: inspect bprm->file->f_path.dentry and the backing inode.
 * A regular executable that was opened and then unlinked typically has
 * inode->__i_nlink == 0, and its dentry is commonly unhashed
 * (d_hash.pprev == NULL). Either state is suspicious when the calling
 * task is a web-class uid. If web-origin task storage is enabled, tasks
 * that originated under a watched uid also emit telemetry after uid
 * transitions, but those origin-only matches remain monitor-only.
 *
 * Mode: monitor by default. Enforcement is deliberately opt-in via
 * cfm_enforce_deleted_file_exec only after production telemetry proves
 * the signal is clean.
 * ------------------------------------------------------------------- */

static __always_inline bool cfm_dentry_unhashed(struct dentry *d)
{
    if (!d)
        return false;

    return BPF_CORE_READ(d, d_hash.pprev) == NULL;
}

static __always_inline int cfm_deleted_file_exec_flags(struct dentry *dentry,
                                                       struct inode *inode,
                                                       __u8 *flags)
{
    if (!dentry || !inode || !flags)
        return 0;

    /* EXEC-001 owns anonymous memfd telemetry. Do not double-report it
     * as a deleted-file exec just because memfd inodes also have no
     * durable link from a normal filesystem namespace. */
    if (dentry_name_is_memfd(dentry))
        return 0;

    __u8 f = 0;
    unsigned int nlink = BPF_CORE_READ(inode, __i_nlink);
    if (nlink == 0)
        f |= CFM_LSM_F_UNLINKED_INODE;
    if (cfm_dentry_unhashed(dentry))
        f |= CFM_LSM_F_UNHASHED_DENTRY;

    *flags = f;
    return f != 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(cfm_deleted_file_exec, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret;

    cfm_mark_current_web_origin_if_needed();

    __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffffu);
    bool current_uid_watched = cfm_uid_watched(uid);
    bool origin_watched = cfm_task_is_web_origin(bpf_get_current_task_btf());
    if (!current_uid_watched && !origin_watched)
        return 0;

    struct file *file = BPF_CORE_READ(bprm, file);
    if (!file)
        return 0;
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return 0;

    __u8 flags = 0;
    if (!cfm_deleted_file_exec_flags(dentry, inode, &flags))
        return 0;
    if (origin_watched && !current_uid_watched)
        flags |= CFM_LSM_F_WEB_ORIGIN;

    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e) {
        if (current_uid_watched && cfm_enforce_deleted_file_exec)
            return CFM_LSM_DENY;
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = CFM_LSM_POLICY_DELETED_FILE_EXEC;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->op        = 0;
    e->flags     = flags;
    e->_pad1     = 0;
    e->_pad2     = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    if (name)
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), name);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);

    /* Origin-only matches stay monitor-only while the origin signal is
     * still being proven out. Current web-class uid enforcement is opt-in. */
    if (current_uid_watched && cfm_enforce_deleted_file_exec)
        return CFM_LSM_DENY;
    return 0;
}

/* ------------------------------------------------------------------- *
 * CFML-EXEC-006 — Web-user exec from ephemeral / writeable-by-web-user
 *                 filesystem (/tmp, /var/tmp, /dev/shm, /run/user/<uid>).
 *
 * Hook: bprm_check_security (LSM)
 *
 * Mechanism: at exec, if the calling task's uid is in cfm_watched_uids,
 * inspect the file being exec'd:
 *
 *   1. If the backing superblock's magic is TMPFS_MAGIC, treat the
 *      file as ephemeral. This covers /dev/shm (always tmpfs),
 *      /run/user/<uid>/ (per-user systemd runtime dir, tmpfs), and
 *      /tmp on distros that mount it as tmpfs (most modern Linux
 *      distros do).
 *
 *   2. Otherwise, walk the file's dentry up to the filesystem root
 *      via d_parent and compare the top-level directory name. EL9
 *      and CloudLinux 9 default to /tmp on the root filesystem
 *      rather than tmpfs, so the magic check alone is not enough.
 *      Prefixes matched: /tmp/, /var/tmp/.
 *
 * The walk is bounded (#pragma unroll on a small loop) so the verifier
 * is happy on every supported kernel; the magic-check fast path covers
 * the common case in O(1) reads.
 *
 * Threat model: webshells stage payloads under /tmp/.<obfuscated> and
 * exec them via the same PHP-FPM worker that wrote the file. Imunify
 * Proactive Defense catches the WRITE at the PHP VM layer; this
 * detector catches the EXEC at the kernel layer when the PHP-layer
 * guard is absent or bypassed.
 *
 * Mode: monitor by default. Enforce returns -EPERM from
 * bprm_check_security, failing the execve. Enforce should be enabled
 * only after monitor-mode telemetry confirms the host has no
 * legitimate exec-from-/tmp workflows (package extractions, custom
 * build pipelines) that would FP.
 * ------------------------------------------------------------------- */

/* Walk the file's dentry up to (but not past) the filesystem root.
 * Returns the immediate child of root via *top_out, and the level just
 * below it (if any) via *second_out. Both may be NULL on a degenerate
 * chain (e.g. the file IS root, which cannot be exec'd anyway).
 *
 * The walk is unrolled to 16 levels — long enough for any realistic
 * exec path, short enough that the verifier accepts it without
 * complexity-budget churn. */
static __always_inline void cfm_walk_to_top(struct dentry *d,
                                            struct dentry **top_out,
                                            struct dentry **second_out)
{
    struct dentry *prev = NULL;
    struct dentry *prev_prev = NULL;
    struct dentry *cur = d;

    *top_out = NULL;
    *second_out = NULL;
    if (!cur)
        return;

#pragma unroll
    for (int i = 0; i < 16; i++) {
        struct dentry *parent = BPF_CORE_READ(cur, d_parent);
        if (!parent || parent == cur)
            break;
        prev_prev = prev;
        prev = cur;
        cur = parent;
    }

    /* After the loop, `cur` is either the filesystem root (parent ==
     * cur) or the topmost dentry we could reach within the unroll
     * budget. `prev` is the immediate child of `cur` — i.e. the
     * top-level directory in the path. `prev_prev` is the level below
     * that. */
    *top_out = prev;
    *second_out = prev_prev;
}

/* Compare the dentry's d_name to a literal of up to 7 chars. Reads
 * the name into a small stack buffer so the verifier can prove the
 * byte-by-byte compares are in-bounds. */
static __always_inline bool cfm_dentry_name_eq(struct dentry *d,
                                               const char *lit, int lit_len)
{
    if (!d)
        return false;

    const unsigned char *name = BPF_CORE_READ(d, d_name.name);
    if (!name)
        return false;

    char buf[8] = {};
    long n = bpf_probe_read_kernel_str(buf, sizeof(buf), name);
    if (n <= 0)
        return false;
    /* bpf_probe_read_kernel_str returns the number of bytes written
     * including the trailing NUL; need length+1 for a clean match. */
    if (n != lit_len + 1)
        return false;

#pragma unroll
    for (int i = 0; i < 8; i++) {
        if (i >= lit_len) {
            return buf[i] == '\0';
        }
        if (buf[i] != lit[i])
            return false;
    }
    return true;
}

/* Path-prefix match. Returns true when the dentry sits under one of:
 *   /tmp/...        (top_name == "tmp")
 *   /var/tmp/...    (top_name == "var", second == "tmp")
 *
 * /dev/shm and /run/user/<uid>/ are caught by the tmpfs-magic fast
 * path in the caller; we don't bother matching their non-tmpfs
 * variants. */
static __always_inline bool cfm_dentry_under_ephemeral_root(struct dentry *d)
{
    struct dentry *top = NULL;
    struct dentry *second = NULL;
    cfm_walk_to_top(d, &top, &second);
    if (!top)
        return false;

    if (cfm_dentry_name_eq(top, "tmp", 3))
        return true;
    if (cfm_dentry_name_eq(top, "var", 3) &&
        cfm_dentry_name_eq(second, "tmp", 3))
        return true;
    return false;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(cfm_ephemeral_exec, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret;

    /* Web-class uid gate — same set FS-005 / EXEC-004 consult. */
    __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffffu);
    if (!cfm_uid_watched(uid))
        return 0;

    struct file *file = BPF_CORE_READ(bprm, file);
    if (!file)
        return 0;
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;
    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (!sb)
        return 0;

    __u8 flags = 0;
    unsigned long magic = BPF_CORE_READ(sb, s_magic);
    if (magic == TMPFS_MAGIC)
        flags |= CFM_LSM_F_TMPFS_BACKED;

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (flags == 0) {
        /* Non-tmpfs path: check /tmp/ and /var/tmp/ via dentry walk.
         * EL9 / CloudLinux 9 ship /tmp on the root filesystem. */
        if (cfm_dentry_under_ephemeral_root(dentry))
            flags |= CFM_LSM_F_EPHEMERAL_DIR;
    }

    if (flags == 0)
        return 0;

    /* EXEC-001 owns memfd telemetry. Avoid double-emitting for memfd
     * payloads whose superblock magic also happens to be TMPFS. */
    if (dentry && dentry_name_is_memfd(dentry))
        return 0;

    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return cfm_exec_verdict(cfm_enforce_ephemeral_exec);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = CFM_LSM_POLICY_EPHEMERAL_EXEC;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->op        = 0;
    e->flags     = flags;
    e->_pad1     = 0;
    e->_pad2     = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Prefer the bprm filename (the path the kernel actually
     * exec()'d) over the dentry d_name, which is just the basename.
     * Operators want the full path for incident triage. */
    const char *fname = BPF_CORE_READ(bprm, filename);
    if (fname)
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), fname);
    else if (dentry) {
        const unsigned char *base = BPF_CORE_READ(dentry, d_name.name);
        if (base)
            bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), base);
        else
            e->filename[0] = '\0';
    } else {
        e->filename[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);

    return cfm_exec_verdict(cfm_enforce_ephemeral_exec);
}

/* Emit one FS-005 event. Caller has already established that uid/origin
 * + target inode are both in the watched sets. */
static __always_inline void cfm_fs005_emit(struct dentry *target,
                                           const char *fname_fallback,
                                           __u8 op, __u8 flags)
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
    e->flags     = flags;
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
 * cfm_watched_inodes. Returns the userspace-supplied watch value on match.
 * NULL dentry / NULL inode are both treated as "no match" (the dentry
 * passed at create-time has no inode yet — the caller must pass d_parent in
 * that case). */
static __always_inline __u8 cfm_fs005_inode_watch_mode(struct dentry *d)
{
    if (!d)
        return 0;
    struct inode *ino = BPF_CORE_READ(d, d_inode);

    struct cfm_inode_key key = {};
    if (!cfm_inode_key_from_inode(ino, &key))
        return 0;
    __u8 *mode = bpf_map_lookup_elem(&cfm_watched_inodes, &key);
    if (!mode)
        return 0;
    return *mode;
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

    cfm_mark_current_web_origin_if_needed();

    __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffffu);
    bool current_uid_watched = cfm_uid_watched(uid);
    bool origin_watched = cfm_task_is_web_origin(bpf_get_current_task_btf());
    if (!current_uid_watched && !origin_watched)
        return 0;

    __u8 primary_watch = cfm_fs005_inode_watch_mode(primary);
    __u8 secondary_watch = cfm_fs005_inode_watch_mode(secondary);
    __u8 watch_mode = primary_watch ? primary_watch : secondary_watch;
    if (!watch_mode)
        return 0;

    struct dentry *ev = event_dentry;
    if (!ev)
        ev = primary ? primary : secondary;

    __u8 flags = 0;
    if (origin_watched && !current_uid_watched)
        flags |= CFM_LSM_F_WEB_ORIGIN;
    cfm_fs005_emit(ev, fname_fallback, op, flags);

    /* Origin-only matches are intentionally monitor-only while we gather
     * production telemetry. Current-uid matches preserve the historical
     * FS-005 enforcement semantics.
     *
     * Setuid-root context skip: cfm_uid_watched(uid) above keyed on
     * the REAL uid (low 32 of bpf_get_current_uid_gid()). When a
     * watched user runs a setuid-root helper — passwd / chage /
     * pkexec / sudo writing /etc/shadow / /etc/sudoers / /etc/passwd
     * legitimately — real_uid stays watched but euid is 0 because
     * the kernel granted root privs through a trusted setuid binary.
     * Denying that write would break password changes and other
     * password-database workflows for every regular user.
     *
     * The event still fires above (forensic record of who touched
     * the sensitive file); we just don't override the kernel's own
     * cred decision in enforce mode. Attackers can't reach this
     * skip without already passing through a setuid-root binary
     * the kernel itself approved — which is FS-007 + CRED-002's
     * territory, not FS-005's. */
    struct task_struct *task = bpf_get_current_task_btf();
    if (task) {
        __u32 euid = BPF_CORE_READ(task, cred, euid.val);
        if (euid == 0)
            return 0;
    }
    if (current_uid_watched && cfm_enforce_sensitive_write &&
        watch_mode == CFM_FS005_WATCH_ENFORCEABLE)
        return CFM_LSM_DENY;
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(cfm_fs005_mark_exec, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret;
    cfm_mark_current_web_origin_if_needed();
    return 0;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(cfm_fs005_mark_setuid, struct cred *new, const struct cred *old,
             int flags, int ret)
{
    if (ret != 0)
        return ret;
    if (!cfm_fs005_web_origin_monitor)
        return 0;

    if (cfm_cred_has_watched_uid(old) || cfm_cred_has_watched_uid(new))
        cfm_mark_current_web_origin();
    return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(cfm_fs005_mark_task_alloc, struct task_struct *task,
             unsigned long clone_flags, int ret)
{
    if (ret != 0)
        return ret;
    if (!cfm_fs005_web_origin_monitor || !task)
        return 0;

    cfm_mark_current_web_origin_if_needed();
    if (!cfm_task_is_web_origin(bpf_get_current_task_btf()))
        return 0;

    struct cfm_web_origin_state *state =
        bpf_task_storage_get(&cfm_web_origin_tasks, task, 0,
                             BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (state)
        state->web_origin = 1;
    return 0;
}

/* The `inode_setattr` LSM hook drifted across kernels:
 *   - Pre-5.12 upstream / EL9 5.14 backport: (dentry, iattr)
 *   - 5.12-6.2 upstream:                     (mnt_userns, dentry, iattr)
 *   - 6.3+ upstream / EL10 6.12:             (mnt_idmap, dentry, iattr)
 *
 * BPF_PROG's argument count must exactly match the kernel's BPF
 * trampoline arity (hook args + ret) or the verifier rejects the
 * program with "doesn't have N-th argument". We ship both variants
 * and the Go loader BTF-probes `bpf_lsm_inode_setattr` at load time,
 * neutralising the wrong-arity variant to a no-op before LoadAndAssign.
 * See internal/lsm/btfprobe.go.
 *
 * The 5.12-6.2 and 6.3+ shapes are both 3-hook-arg; we treat them
 * with one variant whose first arg is `void *` so the type identity
 * (mnt_userns vs mnt_idmap) doesn't matter — we never read it. */

/* noidmap: EL9 / pre-5.12 upstream — 2 hook args, no idmap/userns. */
SEC("lsm/inode_setattr")
int BPF_PROG(cfm_fs005_setattr_noidmap,
             struct dentry *dentry, struct iattr *attr, int ret)
{
    return cfm_fs005_check2(dentry, NULL, dentry, NULL, CFM_FS_OP_SETATTR, ret);
}

/* idmap: upstream 5.12+ / EL10 — 3 hook args, first is mnt_userns
 * (5.12-6.2) or mnt_idmap (6.3+). We never read it; `void *` is fine. */
SEC("lsm/inode_setattr")
int BPF_PROG(cfm_fs005_setattr_idmap, void *idmap_or_ns,
             struct dentry *dentry, struct iattr *attr, int ret)
{
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

/* inode_setxattr drifted with the same shape as inode_setattr — see
 * the long comment above for kernel version map. Two BPF_PROG variants,
 * the Go loader picks one via BTF probe of `bpf_lsm_inode_setxattr`. */

/* noidmap: EL9 / pre-5.12 upstream — 6 hook args (no idmap/userns). */
SEC("lsm/inode_setxattr")
int BPF_PROG(cfm_fs005_setxattr_noidmap, struct dentry *dentry,
             const char *name, const void *value, size_t size, int flags, int ret)
{
    return cfm_fs005_check2(dentry, NULL, dentry, NULL, CFM_FS_OP_SETXATTR, ret);
}

/* idmap: upstream 5.12+ / EL10 — 7 hook args, first is mnt_userns/mnt_idmap. */
SEC("lsm/inode_setxattr")
int BPF_PROG(cfm_fs005_setxattr_idmap, void *idmap_or_ns, struct dentry *dentry,
             const char *name, const void *value, size_t size, int flags, int ret)
{
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
 * without going through a userspace setuid syscall. CFML-CRED-003
 * complements this hook with monitor-only commit_creds telemetry.
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

struct cfm_cred_transition_state {
    __u64 task_fix_setuid_cred;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __type(value, struct cfm_cred_transition_state);
} cfm_cred_transition_tasks SEC(".maps");

static __always_inline void cfm_mark_task_fix_setuid_cred(struct task_struct *task,
                                                          const struct cred *new)
{
    if (!task || !new)
        return;

    struct cfm_cred_transition_state *state =
        bpf_task_storage_get(&cfm_cred_transition_tasks, task, 0,
                             BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (state)
        state->task_fix_setuid_cred = (__u64)new;
}

static __always_inline bool cfm_task_fix_setuid_expected(struct task_struct *task,
                                                         const struct cred *new)
{
    if (!task || !new)
        return false;

    struct cfm_cred_transition_state *state =
        bpf_task_storage_get(&cfm_cred_transition_tasks, task, 0, 0);
    if (!state)
        return false;

    bool match = state->task_fix_setuid_cred == (__u64)new;
    if (match)
        state->task_fix_setuid_cred = 0;
    return match;
}

static __always_inline void cfm_cred_emit(__u32 policy_id, __u8 flags, struct file *exe)
{
    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = policy_id;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->op        = 0;
    e->flags     = flags;
    e->_pad1     = 0;
    e->_pad2     = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct dentry *exe_dentry = exe ? BPF_CORE_READ(exe, f_path.dentry) : NULL;
    const unsigned char *name = NULL;
    if (exe_dentry)
        name = BPF_CORE_READ(exe_dentry, d_name.name);
    if (name)
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), name);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
}

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

    struct task_struct *task = bpf_get_current_task_btf();
    if (!task)
        return 0;

    /* Let CFML-CRED-003 distinguish syscall-mediated setuid-family
     * transitions from direct commit_creds() installs. */
    cfm_mark_task_fix_setuid_cred(task, new);

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
    cfm_cred_emit(CFM_LSM_POLICY_CRED_ESCAL, 0, exe);
    return 0; /* monitor-only by design */
}

/* ------------------------------------------------------------------- *
 * CFML-CRED-003 — Direct root credential install.
 *
 * Hook: fentry/commit_creds
 *
 * Mechanism: compare the current task's active credentials (old) with
 * the cred pointer being passed to commit_creds() (new). Alert only on
 * non-root → root transitions where uid/euid become 0 and the new cred
 * pointer was not just observed by task_fix_setuid. That makes this
 * complementary to CFML-CRED-002: CRED-002 covers setuid-family syscall
 * paths, while CRED-003 covers direct commit_creds() completion paths
 * used by kernel exploits.
 *
 * Mode: monitor ONLY. fentry tracing is telemetry, not an LSM decision
 * hook, so this program never attempts enforcement.
 * ------------------------------------------------------------------- */

SEC("fentry/commit_creds")
int BPF_PROG(cfm_cred003, struct cred *new)
{
    if (!new)
        return 0;

    struct task_struct *task = bpf_get_current_task_btf();
    if (!task)
        return 0;

    const struct cred *old = BPF_CORE_READ(task, cred);
    if (!old)
        return 0;

    __u32 old_uid = BPF_CORE_READ(old, uid.val);
    __u32 old_euid = BPF_CORE_READ(old, euid.val);
    __u32 new_uid = BPF_CORE_READ(new, uid.val);
    __u32 new_euid = BPF_CORE_READ(new, euid.val);

    /* Only suspicious: non-root current task installing root creds. */
    if (new_uid != 0 || new_euid != 0)
        return 0;
    if (old_uid == 0 || old_euid == 0)
        return 0;

    /* task_fix_setuid already saw this exact cred pointer, so leave it
     * to CFML-CRED-002 and avoid duplicate telemetry. */
    if (cfm_task_fix_setuid_expected(task, new))
        return 0;

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    struct file *exe = mm ? BPF_CORE_READ(mm, exe_file) : NULL;

    cfm_cred_emit(CFM_LSM_POLICY_DIRECT_CRED, CFM_LSM_F_DIRECT_CRED_INSTALL, exe);
    return 0;
}


/* ------------------------------------------------------------------- *
 * CFML-BPF-001 — Unexpected BPF use.
 *
 * Hook: tracepoint/syscalls/sys_enter_bpf
 *
 * Mechanism: observe bpf() syscall entry for BPF_MAP_CREATE and
 * BPF_PROG_LOAD commands. Trusted CFM/distro agent comm names are
 * suppressed unless the current uid is one of the daemon-populated
 * web/panel uids; web/panel attempts are always reported.
 *
 * Mode: monitor ONLY. This tracepoint is telemetry, not an LSM decision
 * hook, and broad unprivileged BPF reduction remains a kernsec/sysctl
 * responsibility (kernel.unprivileged_bpf_disabled, bpf_jit_harden, ...).
 * ------------------------------------------------------------------- */

#ifndef BPF_MAP_CREATE
#define BPF_MAP_CREATE 0
#endif
#ifndef BPF_PROG_LOAD
#define BPF_PROG_LOAD 5
#endif

struct trace_event_raw_sys_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    unsigned long args[6];
} ___NCO;

static __always_inline bool cfm_comm_is_trusted_bpf_agent(const char *comm)
{
    if (!comm)
        return false;

    /* CFM's own CLI/daemon identity. */
    if (comm[0] == 'c' && comm[1] == 'f' && comm[2] == 'm' && comm[3] == '\0')
        return true;

    /* Known distro/platform agents that legitimately manage BPF state. */
    if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 't' &&
        comm[4] == 'e' && comm[5] == 'm' && comm[6] == 'd' && comm[7] == '\0')
        return true;
    if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 't' &&
        comm[4] == 'e' && comm[5] == 'm' && comm[6] == 'd' && comm[7] == '-' &&
        comm[8] == 'u' && comm[9] == 'd' && comm[10] == 'e' && comm[11] == 'v' &&
        comm[12] == 'd' && comm[13] == '\0')
        return true;
    if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 't' &&
        comm[4] == 'e' && comm[5] == 'm' && comm[6] == 'd' && comm[7] == '-' &&
        comm[8] == 'n' && comm[9] == 'e' && comm[10] == 't' && comm[11] == 'w' &&
        comm[12] == 'o' && comm[13] == 'r' && comm[14] == 'k')
        return true;
    if (comm[0] == 'N' && comm[1] == 'e' && comm[2] == 't' && comm[3] == 'w' &&
        comm[4] == 'o' && comm[5] == 'r' && comm[6] == 'k' && comm[7] == 'M' &&
        comm[8] == 'a' && comm[9] == 'n' && comm[10] == 'a' && comm[11] == 'g' &&
        comm[12] == 'e' && comm[13] == 'r' && comm[14] == '\0')
        return true;
    if (comm[0] == 'b' && comm[1] == 'p' && comm[2] == 'f' && comm[3] == 't' &&
        comm[4] == 'o' && comm[5] == 'o' && comm[6] == 'l' && comm[7] == '\0')
        return true;
    if (comm[0] == 'a' && comm[1] == 'u' && comm[2] == 'd' && comm[3] == 'i' &&
        comm[4] == 't' && comm[5] == 'd' && comm[6] == '\0')
        return true;

    return false;
}

static __always_inline void cfm_bpf001_emit(__u8 op, __u8 flags, const char *comm)
{
    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = CFM_LSM_POLICY_UNEXPECTED_BPF;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->op        = op;
    e->flags     = flags;
    e->_pad1     = 0;
    e->_pad2     = 0;

    __builtin_memcpy(e->comm, comm, CFM_TASK_COMM_LEN);
    if (op == CFM_BPF_OP_MAP_CREATE)
        __builtin_memcpy(e->filename, "BPF_MAP_CREATE", 15);
    else if (op == CFM_BPF_OP_PROG_LOAD)
        __builtin_memcpy(e->filename, "BPF_PROG_LOAD", 14);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int cfm_bpf001(struct trace_event_raw_sys_enter *ctx)
{
    __u32 cmd = (__u32)ctx->args[0];
    __u8 op = CFM_OP_NONE;

    if (cmd == BPF_MAP_CREATE) {
        op = CFM_BPF_OP_MAP_CREATE;
    } else if (cmd == BPF_PROG_LOAD) {
        op = CFM_BPF_OP_PROG_LOAD;
    } else {
        return 0;
    }

    __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffffu);
    bool web_uid = cfm_uid_watched(uid);

    char comm[CFM_TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    if (!web_uid && cfm_comm_is_trusted_bpf_agent(comm))
        return 0;

    __u8 flags = 0;
    if (web_uid)
        flags |= CFM_LSM_F_WEB_ORIGIN;

    cfm_bpf001_emit(op, flags, comm);
    return 0;
}

/* ------------------------------------------------------------------- *
 * CFML-FS-006 — Sensitive read via root-owned fd from unprivileged task.
 *
 * Hook: file_permission (LSM)
 *
 * Threat: a setuid-root helper (ssh-keysign, chage, unix_chkpwd,
 * passwd, ...) opens a sensitive file as root; an unprivileged task
 * obtains a reference to that already-opened struct file before the
 * helper closes it (pidfd_getfd exit-window race — Qualys ssh-keysign
 * chain, Linus commit 31e62c2ebbfd; CLONE_FILES + setuid-exec;
 * /proc/<pid>/fd/<n>). The unprivileged task then reads/writes the
 * file via the leaked fd: its own current_cred() stays at the original
 * uid, but file->f_cred->euid is 0 and the fd grants whatever access
 * root had at open time.
 *
 * Mechanism: emit one event when current task's effective uid is
 * non-zero, file->f_cred->euid is zero, and the dentry's (fs_id, ino)
 * is in cfm_watched_inodes (the same map FS-005 maintains).
 *
 * Mask: file_permission fires on every read/write/access through any
 * fd. We do NOT filter on mask — both reads (the canonical exfil
 * primitive) and writes (an exploited fd that points at a sensitive
 * file with write intent is a stronger compromise indicator) are
 * interesting. The cred-check filters keep the lookup cost bounded.
 *
 * Mode: monitor-only by design and for the foreseeable future. Several
 * legitimate authentication chains (passwd, pkexec, sudo, unix_chkpwd,
 * dovecot-auth, postfix smtpd_pickup) open the watched files as root
 * and read(2) after dropping privs; returning -EPERM here would
 * deadlock the auth session, not just block one read. Telemetry first;
 * enforce — if it ever lands — needs a curated (comm, exe_inode)
 * allow-list scrubbed against production data, not guessed. No
 * cfm_enforce_fd_cred_mismatch knob exists in this BPF program.
 *
 * Relationship to kernsec: kernsec ships kernel.yama.ptrace_scope=2
 * (KSEC-SCT-kspp.kernel-006) which closes the modern pidfd_getfd()
 * primitive at the kernel layer. FS-006 covers hosts that
 * `state = skip` that rule for same-uid debuggability + future
 * fd-leak variants that don't go through ptrace.
 * ------------------------------------------------------------------- */

static __always_inline void cfm_fs006_emit(struct file *file)
{
    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = CFM_LSM_POLICY_FD_CRED_MISMATCH;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->op        = CFM_OP_NONE;
    e->flags     = 0;
    e->_pad1     = 0;
    e->_pad2     = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Filename: best-effort from the file's dentry. The full path is
     * not reconstructed (bpf_d_path is restricted to a few hooks and
     * file_permission is not on its allow-list across kernel versions);
     * userspace correlates via (uid, comm, inode) when needed. */
    struct dentry *d = BPF_CORE_READ(file, f_path.dentry);
    const unsigned char *name = NULL;
    if (d)
        name = BPF_CORE_READ(d, d_name.name);
    if (name) {
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), name);
    } else {
        e->filename[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
}

SEC("lsm/file_permission")
int BPF_PROG(cfm_fs006, struct file *file, int mask, int ret)
{
    /* `mask` is intentionally unused — see header comment. */
    (void)mask;

    if (!file)
        return ret;

    /* Hot-path optimisation: file_permission fires on every read /
     * write / access through any fd system-wide, so the cost of the
     * common-case early-return matters. Cheap check first —
     * bpf_get_current_uid_gid() is a single helper call (no
     * bpf_probe_read_kernel chase). The low 32 bits are the real uid;
     * on real-root callers (kworkers, kthreads, every root daemon
     * doing fs activity) this is zero and we return immediately,
     * skipping the two-deref task_struct chase below. */
    if ((__u32)(bpf_get_current_uid_gid() & 0xffffffffu) == 0)
        return ret;

    /* Sudo / setuid-elevated edge case: real uid != 0 but euid == 0
     * (the task is acting as root via a setuid binary or sudo-style
     * cred elevation). Neither is the fd-leak pattern; skip. Reads
     * euid directly off task->cred via BPF_CORE_READ. */
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task)
        return ret;
    __u32 cur_euid = BPF_CORE_READ(task, cred, euid.val);
    if (cur_euid == 0)
        return ret;

    /* Only fire when the file was opened by a privileged context.
     * f_cred is captured at open time and never updated, which is
     * exactly the property the fd-leak attack exploits. */
    __u32 fcred_euid = BPF_CORE_READ(file, f_cred, euid.val);
    if (fcred_euid != 0)
        return ret;

    /* Only fire on inodes in the FS-005 watched-inode set
     * (shadow, sudoers, .ssh keys, host keys, plus
     * operator-configured persistence paths). */
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    struct cfm_inode_key key = {};
    if (!cfm_inode_key_from_inode(inode, &key))
        return ret;
    if (!bpf_map_lookup_elem(&cfm_watched_inodes, &key))
        return ret;

    cfm_fs006_emit(file);
    return ret;  /* monitor-only — never deny */
}

/* ------------------------------------------------------------------- *
 * CFML-FS-007 — setuid bit / file capability install by watched uid.
 *
 * Hooks: lsm/inode_setattr  (catches chmod adding S_ISUID or S_ISGID)
 *        lsm/inode_setxattr (catches `setcap` writing security.capability)
 *
 * Threat scenario: classic Linux persistence. After any privesc bug,
 * the attacker drops a binary and grants it a root-acquiring primitive
 * so a later unprivileged shell can re-enter root without re-exploiting:
 *
 *   - `chmod 4755 /tmp/.bd`            (the suid bit pattern)
 *   - `setcap cap_setuid+ep /tmp/.bd`  (the file-cap pattern — harder
 *                                       to spot in `ls -l`, only `getcap`
 *                                       reveals the privilege)
 *
 * CFML-CRED-002 catches the *use* of the dropped binary. FS-007 catches
 * the *install* step — the moment the dropper creates the persistence
 * primitive, before any second exec happens.
 *
 * Watched-uid gate: the rule only fires when the calling task's uid is
 * in cfm_watched_uids (web-class user / panel-managed account). A web
 * worker creating a setuid binary is structurally illegitimate; an
 * admin running `chmod 4755 /usr/local/bin/my-helper` is not watched
 * and won't trip the rule.
 *
 * No watched-inode gate (unlike FS-005): the target file can be
 * anywhere on disk — the privilege primitive itself is the signal,
 * not the path.
 *
 * Mode: monitor by default. Enforce returns -EPERM from the LSM hook;
 * the kernel propagates that out of chmod(2) / setxattr(2) so the
 * dropper sees the failure and the persistence primitive never lands.
 * Enforce promotion is safe — there is no legitimate workflow for a
 * web-class uid to set the suid bit or cap_setuid on a file. The
 * companion EXEC-006 (web-user exec from /tmp) sees the same lack of
 * legitimate workflows from the same uid set.
 * ------------------------------------------------------------------- */

volatile const __u8 cfm_enforce_priv_install = 0;

/* Emit one FS-007 event. Caller has already established that the uid
 * is watched and the operation actually adds a privilege primitive. */
static __always_inline void cfm_fs007_emit(struct dentry *target,
                                           __u8 op, __u8 flags)
{
    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = CFM_LSM_POLICY_PRIV_INSTALL;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->op        = op;
    e->flags     = flags;
    e->_pad1     = 0;
    e->_pad2     = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const unsigned char *name = NULL;
    if (target)
        name = BPF_CORE_READ(target, d_name.name);
    if (name)
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), name);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
}

/* setattr leg. Fires when the watched uid is chmoding a file to add
 * S_ISUID or S_ISGID. Removing the bits is benign (security hardening)
 * and not flagged. */
static __always_inline int cfm_fs007_check_setattr(struct dentry *dentry,
                                                    struct iattr *attr, int ret)
{
    if (ret != 0)
        return ret;
    if (!attr || !dentry)
        return 0;

    /* ATTR_MODE = 1 << 0 — the only ia_valid bit we care about. */
    unsigned int ia_valid = BPF_CORE_READ(attr, ia_valid);
    if (!(ia_valid & 1))
        return 0;

    /* ia_mode carries the new mode bits. S_ISUID = 04000, S_ISGID = 02000. */
    __u16 ia_mode = BPF_CORE_READ(attr, ia_mode);
    __u8 flags = 0;
    if (ia_mode & 04000)
        flags |= CFM_LSM_F_PRIV_SUID;
    if (ia_mode & 02000)
        flags |= CFM_LSM_F_PRIV_SGID;
    if (!flags)
        return 0;

    __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffffu);
    if (!cfm_uid_watched(uid))
        return 0;

    cfm_fs007_emit(dentry, CFM_FS_OP_SETATTR, flags);
    return cfm_enforce_priv_install ? CFM_LSM_DENY : 0;
}

/* inode_setattr drifted with the same shape as FS-005's variants —
 * see the long comment in the FS-005 section. Two BPF_PROG variants;
 * btfprobe.go picks one based on the live kernel's hook arity. */

SEC("lsm/inode_setattr")
int BPF_PROG(cfm_fs007_setattr_noidmap, struct dentry *dentry,
             struct iattr *attr, int ret)
{
    return cfm_fs007_check_setattr(dentry, attr, ret);
}

SEC("lsm/inode_setattr")
int BPF_PROG(cfm_fs007_setattr_idmap, void *idmap_or_ns,
             struct dentry *dentry, struct iattr *attr, int ret)
{
    return cfm_fs007_check_setattr(dentry, attr, ret);
}

/* setxattr leg. Fires when the watched uid is writing the
 * security.capability xattr — the mechanism behind `setcap`. We don't
 * parse the cap value (vfs_cap_data) because any non-zero cap install
 * by a watched uid is illegitimate; cap_setuid is the high-risk case
 * but cap_dac_override / cap_dac_read_search / cap_sys_admin are
 * equally weaponisable. */
static __always_inline int cfm_fs007_check_setxattr(struct dentry *dentry,
                                                     const char *name, int ret)
{
    if (ret != 0)
        return ret;
    if (!name || !dentry)
        return 0;

    /* Match name == "security.capability" exactly. The string is 19
     * chars + NUL = 20 bytes. We open-code the byte compare because
     * the cfm_str_eq helper's #pragma unroll is bounded to 16
     * iterations — fine for the short interpreter basenames it was
     * built for, but it cannot reach the NUL at index 19 here and
     * would always return 0, making this whole leg dead code. The
     * explicit char compare also matches the comm-allowlist pattern
     * used in cfm_comm_is_trusted_bpf_agent / _modprobe / _sysctl. */
    char buf[20] = {};
    long n = bpf_probe_read_kernel_str(buf, sizeof(buf), name);
    if (n != 20)
        return 0;
    if (!(buf[0]  == 's' && buf[1]  == 'e' && buf[2]  == 'c' && buf[3]  == 'u' &&
          buf[4]  == 'r' && buf[5]  == 'i' && buf[6]  == 't' && buf[7]  == 'y' &&
          buf[8]  == '.' && buf[9]  == 'c' && buf[10] == 'a' && buf[11] == 'p' &&
          buf[12] == 'a' && buf[13] == 'b' && buf[14] == 'i' && buf[15] == 'l' &&
          buf[16] == 'i' && buf[17] == 't' && buf[18] == 'y' && buf[19] == '\0'))
        return 0;

    __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffffu);
    if (!cfm_uid_watched(uid))
        return 0;

    cfm_fs007_emit(dentry, CFM_FS_OP_SETXATTR, CFM_LSM_F_PRIV_FILECAP);
    return cfm_enforce_priv_install ? CFM_LSM_DENY : 0;
}

SEC("lsm/inode_setxattr")
int BPF_PROG(cfm_fs007_setxattr_noidmap, struct dentry *dentry,
             const char *name, const void *value, size_t size,
             int flags, int ret)
{
    return cfm_fs007_check_setxattr(dentry, name, ret);
}

SEC("lsm/inode_setxattr")
int BPF_PROG(cfm_fs007_setxattr_idmap, void *idmap_or_ns, struct dentry *dentry,
             const char *name, const void *value, size_t size,
             int flags, int ret)
{
    return cfm_fs007_check_setxattr(dentry, name, ret);
}

/* ------------------------------------------------------------------- *
 * CFML-EXEC-007 — kernel module load by a non-trusted comm.
 *
 * Hooks: tracepoint/syscalls/sys_enter_init_module
 *        tracepoint/syscalls/sys_enter_finit_module
 *
 * Threat: a kernel module is being loaded by something other than the
 * tiny set of distro tooling that legitimately loads modules. The
 * canonical post-exploit primitive for installing a kernel-level
 * rootkit (bvp47-style, hidden processes, syscall-table hooks, ...).
 * On a panel host, no user-visible workload should ever load kernel
 * modules — modprobe is invoked only from boot scripts, udev rules,
 * and a handful of NetworkManager / systemd actions, all of which
 * run under well-known comm names.
 *
 * The detector is comm-allowlist driven (same shape as CFML-BPF-001).
 * Any uid is in scope — the kernel checks CAP_SYS_MODULE later, but
 * a non-root task even *attempting* the syscall is interesting
 * telemetry on a panel host. Web-class uid attempts are tagged with
 * WEB_ORIGIN.
 *
 * Mode: monitor ONLY (tracepoint, not an LSM decision hook — the
 * kernel ignores any return value we set, so enforce is impossible
 * here). Companion kernsec sysctl kernel.modules_disabled=1 (KSEC-
 * MOD-kspp.kernel-007) is the actual block at the kernel layer for
 * hosts that don't load any modules post-boot; FS-007 is the
 * always-on telemetry for everyone else.
 * ------------------------------------------------------------------- */

/* Comm names that legitimately load kernel modules. Truncated to
 * CFM_TASK_COMM_LEN-1 = 15 chars by the kernel. */
static __always_inline bool cfm_comm_is_trusted_modprobe(const char *comm)
{
    if (!comm)
        return false;

    /* modprobe (the userspace loader) */
    if (comm[0] == 'm' && comm[1] == 'o' && comm[2] == 'd' && comm[3] == 'p' &&
        comm[4] == 'r' && comm[5] == 'o' && comm[6] == 'b' && comm[7] == 'e' &&
        comm[8] == '\0')
        return true;

    /* insmod (rarely used directly post-systemd era, but still ships) */
    if (comm[0] == 'i' && comm[1] == 'n' && comm[2] == 's' && comm[3] == 'm' &&
        comm[4] == 'o' && comm[5] == 'd' && comm[6] == '\0')
        return true;

    /* kmod (the busybox-style multi-call binary; modprobe / insmod are
     * symlinks to it on some distros) */
    if (comm[0] == 'k' && comm[1] == 'm' && comm[2] == 'o' && comm[3] == 'd' &&
        comm[4] == '\0')
        return true;

    /* systemd-modules-load.service. Real comm is
     * "systemd-modules-load" but TASK_COMM_LEN truncates to 15 chars:
     * "systemd-modules". */
    if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 't' &&
        comm[4] == 'e' && comm[5] == 'm' && comm[6] == 'd' && comm[7] == '-' &&
        comm[8] == 'm' && comm[9] == 'o' && comm[10] == 'd' && comm[11] == 'u' &&
        comm[12] == 'l' && comm[13] == 'e' && comm[14] == 's')
        return true;

    /* systemd (PID 1) loads built-ins on boot via the same syscall path */
    if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 't' &&
        comm[4] == 'e' && comm[5] == 'm' && comm[6] == 'd' && comm[7] == '\0')
        return true;

    /* systemd-udevd loads kernel modules in response to uevents */
    if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 't' &&
        comm[4] == 'e' && comm[5] == 'm' && comm[6] == 'd' && comm[7] == '-' &&
        comm[8] == 'u' && comm[9] == 'd' && comm[10] == 'e' && comm[11] == 'v' &&
        comm[12] == 'd' && comm[13] == '\0')
        return true;

    return false;
}

static __always_inline void cfm_exec007_emit(__u8 op, __u8 flags, const char *comm)
{
    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = CFM_LSM_POLICY_KMOD_LOAD;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->op        = op;
    e->flags     = flags;
    e->_pad1     = 0;
    e->_pad2     = 0;

    __builtin_memcpy(e->comm, comm, CFM_TASK_COMM_LEN);
    if (op == CFM_KMOD_OP_INIT)
        __builtin_memcpy(e->filename, "init_module", 12);
    else if (op == CFM_KMOD_OP_FINIT)
        __builtin_memcpy(e->filename, "finit_module", 13);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
}

static __always_inline int cfm_exec007_check(__u8 op)
{
    __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffffu);
    bool web_uid = cfm_uid_watched(uid);

    char comm[CFM_TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    /* Trusted modprobe-class caller AND not a web-class uid impersonating
     * one — suppress. A watched-uid task running with comm "modprobe"
     * is exactly the suspicious case (an attacker spoofing comm via
     * prctl). */
    if (!web_uid && cfm_comm_is_trusted_modprobe(comm))
        return 0;

    __u8 flags = 0;
    if (web_uid)
        flags |= CFM_LSM_F_WEB_ORIGIN;

    cfm_exec007_emit(op, flags, comm);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int cfm_exec007_init(struct trace_event_raw_sys_enter *ctx)
{
    (void)ctx;
    return cfm_exec007_check(CFM_KMOD_OP_INIT);
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int cfm_exec007_finit(struct trace_event_raw_sys_enter *ctx)
{
    (void)ctx;
    return cfm_exec007_check(CFM_KMOD_OP_FINIT);
}

/* ------------------------------------------------------------------- *
 * CFML-EXEC-008 — kexec_load / kexec_file_load from non-trusted comm.
 *
 * Hook: tracepoint/syscalls/sys_enter_kexec_load +
 *       tracepoint/syscalls/sys_enter_kexec_file_load
 *
 * Threat: rootkit persistence. kexec_load(2) and kexec_file_load(2)
 * stage a replacement kernel image into a reserved memory region;
 * the next kexec_reboot transitions to that image without going
 * through firmware. An attacker with root + CAP_SYS_BOOT can use
 * this to install a backdoored kernel that survives "reboot",
 * defeating every audit that compares the running kernel hash to
 * its package on disk.
 *
 * Trusted-comm allowlist matches the documented userspace tools that
 * legitimately call these syscalls:
 *   - kexec       — kexec-tools userspace (`/sbin/kexec` / `/usr/sbin/kexec`).
 *                   Also the binary kdump.service launches at boot to
 *                   preload the crash kernel.
 *   - systemctl   — `systemctl kexec` triggers a kexec reboot via
 *                   systemd; systemd invokes kexec under the hood.
 *
 * Any other comm calling these syscalls — or any of the trusted comms
 * running from a watched (web-class) uid (comm spoofing via prctl by
 * a web user) — fires the rule. The watched-uid case is structurally
 * impossible to succeed (the syscall requires CAP_SYS_BOOT which
 * watched uids never have), but the tracepoint fires on syscall ENTRY
 * before the cap check, so the attempt itself is the signal.
 *
 * Companion to kernsec's KSEC-SCT-kspp.kexec-001 sysctl
 * (kernel.kexec_load_disabled=1) which blocks the syscall at the
 * kernel layer on hosts that don't run kdump. When the sysctl is on,
 * the syscall returns -EPERM but the EXEC-008 tracepoint still fires
 * — giving the operator forensic visibility of attackers probing the
 * lockout. When the sysctl is off (kdump host), the rule surfaces
 * every legitimate kexec call from kexec-tools plus any unexpected
 * caller.
 *
 * Mode: monitor ONLY by design. Tracepoint hooks are observation-only
 * — the kernel ignores any return value the BPF program sets, so
 * enforce is structurally impossible here. The kernsec sysctl is the
 * "actually block" layer.
 * ------------------------------------------------------------------- */

/* Allowlist of comm names that legitimately invoke kexec_load /
 * kexec_file_load. The list is intentionally small: only the kexec
 * userspace utility and systemctl. Matched as a NUL-terminated
 * literal compare on the 16-byte TASK_COMM_LEN buffer. */
static __always_inline bool cfm_comm_is_trusted_kexec(const char *comm)
{
    /* "kexec\0" */
    if (comm[0] == 'k' && comm[1] == 'e' && comm[2] == 'x' && comm[3] == 'e' &&
        comm[4] == 'c' && comm[5] == '\0')
        return true;

    /* "systemctl\0" — `systemctl kexec` calls kexec_file_load under
     * the hood. Long enough that the first-9-byte compare is unique. */
    if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 't' &&
        comm[4] == 'e' && comm[5] == 'm' && comm[6] == 'c' && comm[7] == 't' &&
        comm[8] == 'l' && comm[9] == '\0')
        return true;

    return false;
}

static __always_inline void cfm_exec008_emit(__u8 op, __u8 flags, const char *comm)
{
    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = CFM_LSM_POLICY_KEXEC_LOAD;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->op        = op;
    e->flags     = flags;
    e->_pad1     = 0;
    e->_pad2     = 0;

    __builtin_memcpy(e->comm, comm, CFM_TASK_COMM_LEN);
    if (op == CFM_KEXEC_OP_LOAD)
        __builtin_memcpy(e->filename, "kexec_load", 11);
    else if (op == CFM_KEXEC_OP_FILE_LOAD)
        __builtin_memcpy(e->filename, "kexec_file_load", 16);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
}

static __always_inline int cfm_exec008_check(__u8 op)
{
    __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffffu);
    bool web_uid = cfm_uid_watched(uid);

    char comm[CFM_TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    /* Trusted kexec-class caller AND not a web-class uid impersonating
     * one — suppress. A watched-uid task running with comm "kexec" is
     * exactly the suspicious case (an attacker spoofing comm via
     * prctl). */
    if (!web_uid && cfm_comm_is_trusted_kexec(comm))
        return 0;

    __u8 flags = 0;
    if (web_uid)
        flags |= CFM_LSM_F_WEB_ORIGIN;

    cfm_exec008_emit(op, flags, comm);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kexec_load")
int cfm_exec008_kexec(struct trace_event_raw_sys_enter *ctx)
{
    (void)ctx;
    return cfm_exec008_check(CFM_KEXEC_OP_LOAD);
}

SEC("tracepoint/syscalls/sys_enter_kexec_file_load")
int cfm_exec008_kexec_file(struct trace_event_raw_sys_enter *ctx)
{
    (void)ctx;
    return cfm_exec008_check(CFM_KEXEC_OP_FILE_LOAD);
}

/* ------------------------------------------------------------------- *
 * CFML-FS-008 — write to a sensitive kernel knob.
 *
 * Hook: lsm/file_permission (every read/write through any fd)
 *
 * Threat: kernel-exploit completion + post-exploit persistence. The
 * watched paths are the small set of /proc/sys and /sys nodes that
 * every public Linux kernel exploit from the last five years pivots
 * through once it has the write primitive:
 *
 *   /proc/sys/kernel/core_pattern      — pipe-to-program on coredump
 *                                        (CVE-2022-0185, dirtypipe followup)
 *   /proc/sys/kernel/modprobe_path     — substitute modprobe binary
 *                                        (BPF verifier bug chains)
 *   /proc/sys/kernel/hotplug           — uevent helper, legacy variant
 *   /proc/sysrq-trigger                — magic sysrq for arbitrary
 *                                        kernel actions
 *   /sys/kernel/uevent_helper          — modern uevent helper
 *   /proc/sys/fs/binfmt_misc/register  — register a binfmt handler
 *                                        that runs on every matching exec
 *
 * Each of these gives the writer a path to run code as root on the
 * next triggering event (a coredump / a binary that no userspace knows
 * how to handle / a uevent firing / etc).
 *
 * Userspace populates cfm_kernel_knob_inodes from these paths at
 * adoption time (paths absent on this kernel are skipped silently).
 * The BPF program checks file inode against the map on every write-
 * class access, comparing comm against a small trusted-writer set
 * (cfm / sysctl / systemd / systemd-sysctl) before emitting.
 *
 * Mode: monitor by default. Enforce-capable but DEFAULT to monitor —
 * an unanticipated legitimate writer of any of these knobs (operator
 * tuning script, RPM postinstall) would otherwise silently fail.
 * Promote to enforce after a 30-day monitor window confirms no in-
 * the-wild legitimate writer.
 * ------------------------------------------------------------------- */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct cfm_inode_key);
    __type(value, __u8);
} cfm_kernel_knob_inodes SEC(".maps");

volatile const __u8 cfm_enforce_kernel_knob_write = 0;

/* Trusted writer comm allowlist. The legitimate sysctl pipeline is
 * narrow: `sysctl(8)` and systemd-sysctl on boot / reload, cfm itself
 * for the few knobs the kernsec subsystem manages. */
static __always_inline bool cfm_comm_is_trusted_sysctl(const char *comm)
{
    if (!comm)
        return false;

    /* cfm — own daemon (kernsec subsystem applies sysctl tweaks) */
    if (comm[0] == 'c' && comm[1] == 'f' && comm[2] == 'm' && comm[3] == '\0')
        return true;

    /* sysctl */
    if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 'c' &&
        comm[4] == 't' && comm[5] == 'l' && comm[6] == '\0')
        return true;

    /* systemd-sysctl. Real comm "systemd-sysctl" — fits in 15 chars. */
    if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 't' &&
        comm[4] == 'e' && comm[5] == 'm' && comm[6] == 'd' && comm[7] == '-' &&
        comm[8] == 's' && comm[9] == 'y' && comm[10] == 's' && comm[11] == 'c' &&
        comm[12] == 't' && comm[13] == 'l' && comm[14] == '\0')
        return true;

    /* systemd (PID 1 writes some knobs during early boot) */
    if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 't' &&
        comm[4] == 'e' && comm[5] == 'm' && comm[6] == 'd' && comm[7] == '\0')
        return true;

    return false;
}

static __always_inline void cfm_fs008_emit(struct file *file, const char *comm)
{
    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = CFM_LSM_POLICY_KERNEL_KNOB_WRITE;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->op        = CFM_OP_NONE;
    e->flags     = 0;
    e->_pad1     = 0;
    e->_pad2     = 0;

    __builtin_memcpy(e->comm, comm, CFM_TASK_COMM_LEN);

    /* Best-effort filename via the file's dentry. For procfs these
     * are short tokens like "core_pattern" / "sysrq-trigger". */
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    const unsigned char *name = NULL;
    if (dentry)
        name = BPF_CORE_READ(dentry, d_name.name);
    if (name)
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), name);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
}

/* MAY_WRITE from include/linux/fs.h. The mask is a bitfield;
 * MAY_EXEC=1, MAY_WRITE=2, MAY_READ=4, MAY_APPEND=8. We fire on
 * any write-class access (write or append). */
#define CFM_MAY_WRITE  2
#define CFM_MAY_APPEND 8

SEC("lsm/file_permission")
int BPF_PROG(cfm_fs008, struct file *file, int mask, int ret)
{
    if (!file)
        return ret;

    /* Fast path: read-only access on most file_permission calls.
     * Bail before any deref. */
    if (!(mask & (CFM_MAY_WRITE | CFM_MAY_APPEND)))
        return ret;

    /* Inode in the watched-knob set? */
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    struct cfm_inode_key key = {};
    if (!cfm_inode_key_from_inode(inode, &key))
        return ret;
    if (!bpf_map_lookup_elem(&cfm_kernel_knob_inodes, &key))
        return ret;

    /* Trusted writer? Suppress. We compare task->comm rather than the
     * exe identity because /sbin/sysctl and /usr/sbin/sysctl can be
     * different inodes across distros — comm is the stable signal. */
    char comm[CFM_TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (cfm_comm_is_trusted_sysctl(comm))
        return ret;

    cfm_fs008_emit(file, comm);

    if (cfm_enforce_kernel_knob_write)
        return CFM_LSM_DENY;
    return ret;
}

/* ------------------------------------------------------------------- *
 * CFML-OBS-004 — ptrace from a watched (web-class) uid.
 *
 * Hook: lsm/ptrace_access_check
 *
 * Threat: process introspection / code injection. A compromised
 * vhost user PTRACE_ATTACHes to another process they own (sibling
 * PHP-FPM worker, long-running cron job) and uses PTRACE_POKETEXT to
 * inject shellcode, or PTRACE_GETREGS / PEEKTEXT to steal in-memory
 * secrets. Even with kernel.yama.ptrace_scope=1 (the default), the
 * kernel allows same-uid ptrace — so any of the user's own running
 * processes is a credential-theft target. With yama=0 (legacy hosts),
 * cross-uid ptrace is open within the kernel's normal cred checks.
 *
 * Companion to kernsec's kernel.yama.ptrace_scope=2 sysctl: yama=2
 * blocks all ptrace except through PR_SET_PTRACER negotiation. On
 * yama≤1 hosts (the distro default across EL/Debian/Ubuntu), OBS-004
 * has full coverage: every PTRACE_ATTACH / PTRACE_READ by a watched
 * uid surfaces in the audit trail. On yama=2 hosts the picture is
 * coarser — the kernel iterates LSM hooks via call_int_hook which
 * short-circuits on the first non-zero return. On cfm-managed
 * hosts BPF LSM is the LAST hook in the chain because kernsec's
 * MergeLSMBPF (internal/kernsec/lsm_merge.go) appends `bpf` to the
 * end of any operator-set `lsm=` token. So yama's -EPERM pre-empts
 * the BPF hook entirely. OBS-004 still
 * records every attempt yama would have ALLOWED on yama=2 (rare —
 * only PR_SET_PTRACER-negotiated traces) but does NOT see the
 * denied-by-yama attempts that constitute most attacker probes.
 * The host's kernel block IS the protection in that case; OBS-004
 * is the always-on visibility on the much larger yama≤1 population.
 *
 * Watched-uid gate first — root callers (gdb / strace by the admin,
 * systemd's signal-on-fork uses, every container runtime) generate
 * huge ptrace_access_check traffic and we don't want to flag any of
 * it. The rule only fires when a watched-uid task is the caller.
 *
 * Mode flags: bit 4 = PTRACE_MODE_READ requested, bit 5 =
 * PTRACE_MODE_ATTACH requested (kernel ptrace mode is a bitmask;
 * a single call can request both). Bit 6 = caller and target share
 * effective uid (the same-uid sibling-worker credential-theft case;
 * absence of the bit means a cross-uid introspection attempt).
 *
 * Mode: monitor ONLY by design. The kernsec yama sysctl is the
 * actual block layer; making OBS-004 enforce-capable would break
 * legitimate developer workflows (operator su'ing to a vhost user
 * to debug a crashed worker via gdb, etc.) without adding security
 * the yama sysctl doesn't already provide. Enforce is downgraded to
 * monitor at enable time.
 * ------------------------------------------------------------------- */

/* PTRACE_MODE_* from include/linux/ptrace.h. The mode arg is a
 * bitmask; we care about the READ and ATTACH bits. NOAUDIT /
 * FSCREDS / REALCREDS bits exist but don't change the security
 * decision and we don't surface them. */
#define CFM_PTRACE_MODE_READ    0x01
#define CFM_PTRACE_MODE_ATTACH  0x02

static __always_inline void cfm_obs004_emit(struct task_struct *child,
                                            __u8 flags)
{
    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = CFM_LSM_POLICY_PTRACE_ACCESS;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->op        = CFM_OP_NONE;
    e->flags     = flags;
    e->_pad1     = 0;
    e->_pad2     = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Target task identity. The most useful context for an operator
     * triaging an OBS-004 event is "what was the target?" — comm is
     * the cheapest stable identifier and fits in filename's 64 bytes
     * with room to spare. `comm` is an inline TASK_COMM_LEN-byte
     * char buffer; BPF_CORE_READ_STR_INTO performs a CO-RE-relocated
     * read of the inline array into our event buffer. */
    if (child) {
        BPF_CORE_READ_STR_INTO(&e->filename, child, comm);
    } else {
        e->filename[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(cfm_obs004, struct task_struct *child, unsigned int mode, int ret)
{
    /* Fast path: watched-uid gate. Root / system daemons / container
     * runtimes generate the bulk of ptrace_access_check traffic; we
     * want none of it. cfm_uid_watched is a hash lookup over the
     * cfm_watched_uids map populated at adoption time. */
    __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffffu);
    if (!cfm_uid_watched(uid))
        return ret;

    if (!child)
        return ret;

    /* Self-ptrace skip. A task can ptrace itself via PR_SET_PTRACER
     * arrangements that funnel back through ptrace_access_check with
     * child == current. That isn't credential theft — skip. */
    struct task_struct *self = bpf_get_current_task_btf();
    if (self == child)
        return ret;

    __u8 flags = CFM_LSM_F_WEB_ORIGIN;
    if (mode & CFM_PTRACE_MODE_READ)
        flags |= CFM_LSM_F_PTRACE_READ;
    if (mode & CFM_PTRACE_MODE_ATTACH)
        flags |= CFM_LSM_F_PTRACE_ATTACH;

    /* Same-uid hint: the kernel allows same-uid ptrace at yama=1
     * (default) so the same-uid sibling-worker case is the most
     * frequent in-the-wild post-exploit pattern. Tagged so the
     * operator can filter cross-uid (attacker reaching across
     * tenants) from same-uid (attacker walking their own process
     * tree). Read EFFECTIVE uid on both sides — that's what the
     * kernel's own ptrace_may_access cred check compares (see
     * security/yama/yama_pl.c and kernel/ptrace.c::__ptrace_may_access).
     * Reading caller's real uid (cheap via bpf_get_current_uid_gid)
     * vs target's euid would flip the flag in the setuid-wrapper
     * edge case where caller's real != euid. */
    __u32 self_euid  = BPF_CORE_READ(self, cred, euid.val);
    __u32 child_euid = BPF_CORE_READ(child, cred, euid.val);
    if (child_euid == self_euid)
        flags |= CFM_LSM_F_PTRACE_SAMEUID;

    cfm_obs004_emit(child, flags);
    return ret;  /* monitor-only — never deny */
}

/* ------------------------------------------------------------------- *
 * CFML-NET-002 — raw / packet socket from a watched (web-class) uid.
 *
 * Hook: lsm/socket_create
 *
 * Threat: post-exploit scanner / sniffer / spoofing toolkit. Legitimate
 * vhost-user workloads (PHP / Python / MySQL clients) have zero use
 * for raw sockets; root daemons that genuinely need them (named for
 * DNS, dhclient, NetworkManager) all run as uid 0 and are filtered
 * out by the watched-uid gate at the top of the program.
 *
 * Coverage:
 *   - AF_PACKET sockets             — full L2 frame sniff / inject.
 *                                     Wireshark / tcpdump / arpspoof /
 *                                     ettercap / custom rootkit sniffers.
 *   - AF_INET  + SOCK_RAW           — arbitrary L3 IPv4 send / recv.
 *                                     hping / ICMP spoofing / TCP-RST
 *                                     injection / scan toolkits.
 *   - AF_INET6 + SOCK_RAW           — same for IPv6.
 *
 * `ping` behaviour by host configuration:
 *   - Modern Linux's "ping group" mechanism uses SOCK_DGRAM +
 *     IPPROTO_ICMP (NOT SOCK_RAW), so unprivileged `ping` on hosts
 *     with open net.ipv4.ping_group_range does NOT trip the rule
 *     regardless of who calls it.
 *   - On hosts where ping_group_range is closed (the default on
 *     most distros) iputils falls back to SOCK_RAW. The legacy
 *     setuid /bin/ping path runs at euid=0 and is suppressed by
 *     the program's euid==0 fast-path skip below. The modern
 *     cap_net_raw+ep /bin/ping (Ubuntu / Debian / EL9+) runs at
 *     euid=watched even though it holds CAP_NET_RAW, so a watched
 *     uid invoking it WILL fire the rule. Operators on hosts where
 *     vhost users routinely run `ping` should add
 *     `allow_exe = /usr/bin/ping` (or `/bin/ping`) under [allow] in
 *     lsm.conf to suppress, OR keep the rule in monitor mode and
 *     ignore the events.
 *
 * No kernsec sysctl pairing — there's no equivalent kernel-side knob
 * (CAP_NET_RAW is per-process and per-binary, not a global toggle).
 * NET-002 is the standalone telemetry layer.
 *
 * Mode: monitor by default. Enforce-capable — there is no legitimate
 * workflow for a web-class uid to open a raw / packet socket, so
 * returning -EPERM out of socket(2) is safe (the dropper sees the
 * syscall fail and the primitive never lands). Promoted to enforce
 * via the cfm_enforce_raw_socket variable wired through the loader.
 * ------------------------------------------------------------------- */

/* Stable Linux ABI constants. Values are fixed by the syscall
 * interface and uniform across architectures, so literals are safe
 * (matching the AF_ / SOCK_ / PF_ definitions in
 * include/linux/socket.h and include/linux/net.h). */
#define CFM_AF_INET    2
#define CFM_AF_INET6   10
#define CFM_AF_PACKET  17
#define CFM_SOCK_RAW   3

volatile const __u8 cfm_enforce_raw_socket = 0;

static __always_inline void cfm_net002_emit(__u8 op, int protocol)
{
    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = CFM_LSM_POLICY_RAW_SOCKET;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->op        = op;
    e->flags     = CFM_LSM_F_WEB_ORIGIN;
    e->_pad1     = 0;
    e->_pad2     = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Protocol arg as a short token in filename. Most callers pass
     * either 0 (default) or a small int — we write a tiny ASCII
     * representation so the audit row is human-readable without an
     * extra lookup table in userspace. The 64-byte filename buffer
     * is overkill for a single integer; userspace renders it as-is. */
    e->filename[0] = 'p';
    e->filename[1] = 'r';
    e->filename[2] = 'o';
    e->filename[3] = 't';
    e->filename[4] = 'o';
    e->filename[5] = '=';
    /* Stringify protocol (0..255) as up to 3 decimal digits + NUL.
     * Open-coded because BPF lacks a stable strprintf and we want
     * deterministic verifier behaviour. */
    __u32 p = (__u32)protocol;
    if (p > 999)
        p = 999;
    if (p >= 100) {
        e->filename[6] = '0' + (p / 100);
        e->filename[7] = '0' + ((p / 10) % 10);
        e->filename[8] = '0' + (p % 10);
        e->filename[9] = '\0';
    } else if (p >= 10) {
        e->filename[6] = '0' + (p / 10);
        e->filename[7] = '0' + (p % 10);
        e->filename[8] = '\0';
    } else {
        e->filename[6] = '0' + p;
        e->filename[7] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
}

SEC("lsm/socket_create")
int BPF_PROG(cfm_net002, int family, int type, int protocol, int kern, int ret)
{
    /* Kernel-internal socket (sock_create_kern) — not user-initiated,
     * not in our threat model. */
    if (kern)
        return ret;

    /* Family / type filter first. socket_create is called for every
     * socket(2) on the host (apache → AF_UNIX, mysql → AF_UNIX,
     * nginx → AF_INET/SOCK_STREAM, …) — the bulk of traffic is
     * AF_UNIX which we don't care about. Two int compares are
     * cheaper than the hash lookup. */
    __u8 op;
    if (family == CFM_AF_PACKET) {
        op = CFM_NET_OP_PACKET;
    } else if (family == CFM_AF_INET && type == CFM_SOCK_RAW) {
        op = CFM_NET_OP_RAW_INET;
    } else if (family == CFM_AF_INET6 && type == CFM_SOCK_RAW) {
        op = CFM_NET_OP_RAW_INET6;
    } else {
        return ret;
    }

    /* Watched-uid gate. bpf_get_current_uid_gid() returns the REAL
     * uid (current_cred()->uid), not the effective one — so root
     * daemons running as uid 0 (named, dhclient, NetworkManager)
     * are filtered out here. */
    __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffffu);
    if (!cfm_uid_watched(uid))
        return ret;

    /* Effective-uid 0 fast-path skip. A watched-uid task that exec'd
     * a setuid-root binary (/bin/ping on older distros, /usr/sbin/
     * traceroute, /usr/bin/mtr) has real_uid=watched but euid=0;
     * those are legitimate raw-socket callers that walked through a
     * trusted privilege-escalation channel and should not fire the
     * rule. Note: this does NOT cover file-capability-granted
     * raw-socket binaries (modern /bin/ping with cap_net_raw+ep
     * runs at euid=watched even though it holds CAP_NET_RAW); those
     * still fire and the operator-side mitigation is to add
     * allow_exe=/bin/ping (or similar) under [allow] in lsm.conf if
     * vhost users routinely run ping on this host. */
    struct task_struct *task = bpf_get_current_task_btf();
    if (task) {
        __u32 euid = BPF_CORE_READ(task, cred, euid.val);
        if (euid == 0)
            return ret;
    }

    cfm_net002_emit(op, protocol);

    if (cfm_enforce_raw_socket)
        return CFM_LSM_DENY;
    return ret;
}

/* ------------------------------------------------------------------- *
 * CFML-CRED-004 — capability-set raise by a watched (web-class) uid.
 *
 * Hook: fentry/commit_creds
 *
 * Threat: post-exploit capability hoarding. A watched-uid task that
 * already holds CAP_X in its inheritable set (rare but happens when
 * a hosting customer is granted CAP_NET_BIND_SERVICE / CAP_NET_RAW
 * / similar via file capabilities) calls
 * prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_X, 0, 0) to move
 * the cap into the ambient set. Ambient capabilities survive
 * execve(), so the attacker can drop into a shell or call another
 * binary and keep the elevated privilege — the canonical
 * cred-survives-process-boundary pattern.
 *
 * CFML-CRED-002 catches uid→0 transitions (the easy privilege
 * escalation). CFML-CRED-003 catches direct commit_creds installs
 * (kernel-exploit fingerprint). CRED-004 catches the third class:
 * the watched uid never changes, but the capability set DOES, and
 * the new bits will outlive every subsequent exec.
 *
 * What we compare: cap_ambient and cap_inheritable. NOT cap_effective —
 * legitimate setuid binaries change effective routinely (every su,
 * sudo, passwd call), and we'd be drowning in noise. Ambient raises
 * are rare and almost always intentional credential persistence.
 * Inheritable raises set up a future ambient raise, so they're
 * caught here as the earlier signal.
 *
 * Hook ordering vs CRED-002: commit_creds fires AFTER task_fix_setuid
 * for setuid-family syscalls. CRED-002 already handles uid→0 (which
 * also bumps cap_permitted/effective). To avoid duplicate telemetry
 * on those paths, we exclude uid→0 transitions here — they belong
 * to CRED-002.
 *
 * No kernsec sysctl pairing — there is no global "disable
 * prctl(PR_CAP_AMBIENT_RAISE)" knob. kernel.cap_last_cap is fixed
 * and unprivileged-userns toggles don't affect ambient. CRED-004
 * stands alone.
 *
 * Mode: monitor ONLY. commit_creds is a fentry trace probe, not an
 * LSM decision point — the kernel ignores any return value, so
 * enforce is structurally impossible (same reason as CRED-003).
 * Pair with the operator's choice of capability-management hygiene
 * (audit `getcap -r /` for unexpected file caps on watched-uid
 * homedirs) for actual blocking.
 * ------------------------------------------------------------------- */

static __always_inline void cfm_cred004_emit(__u8 flags, __u8 cap_bit, struct task_struct *task)
{
    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = CFM_LSM_POLICY_CAP_RAISE;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->op        = CFM_OP_NONE;
    e->flags     = flags;
    e->_pad1     = 0;
    e->_pad2     = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Filename payload: "cap=NN" where NN is the bit index of the
     * lowest newly-raised capability. Userspace can map the bit
     * back to a CAP_* name (CAP_NET_RAW=13, CAP_SETUID=7, ...).
     * Multiple raised bits in one event → only the lowest is
     * surfaced here; the operator-facing alert is "task X raised
     * at least cap N" which is enough to triage. */
    e->filename[0] = 'c';
    e->filename[1] = 'a';
    e->filename[2] = 'p';
    e->filename[3] = '=';
    if (cap_bit >= 10) {
        e->filename[4] = '0' + (cap_bit / 10);
        e->filename[5] = '0' + (cap_bit % 10);
        e->filename[6] = '\0';
    } else {
        e->filename[4] = '0' + cap_bit;
        e->filename[5] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
}

SEC("fentry/commit_creds")
int BPF_PROG(cfm_cred004, struct cred *new)
{
    if (!new)
        return 0;

    struct task_struct *task = bpf_get_current_task_btf();
    if (!task)
        return 0;

    const struct cred *old = BPF_CORE_READ(task, cred);
    if (!old)
        return 0;

    /* Watched-uid gate. bpf_get_current_uid_gid() returns real uid;
     * that's what we want — cap-raise on a watched uid is the
     * signal regardless of euid context. */
    __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffffu);
    if (!cfm_uid_watched(uid))
        return 0;

    /* Skip uid→0 transitions. Those are the CRED-002 / CRED-003
     * domain (setuid root install). They also incidentally bump
     * cap_effective; comparing here would generate noisy duplicate
     * telemetry on every setuid binary execution. */
    __u32 new_uid = BPF_CORE_READ(new, uid.val);
    __u32 new_euid = BPF_CORE_READ(new, euid.val);
    if (new_uid == 0 || new_euid == 0)
        return 0;

    /* The core check: ambient or inheritable gained any bit. */
    __u64 old_ambient = BPF_CORE_READ(old, cap_ambient);
    __u64 new_ambient = BPF_CORE_READ(new, cap_ambient);
    __u64 old_inherit = BPF_CORE_READ(old, cap_inheritable);
    __u64 new_inherit = BPF_CORE_READ(new, cap_inheritable);

    __u64 raised_ambient = new_ambient & ~old_ambient;
    __u64 raised_inherit = new_inherit & ~old_inherit;
    __u64 raised         = raised_ambient | raised_inherit;
    if (!raised)
        return 0;

    __u8 flags = CFM_LSM_F_WEB_ORIGIN;
    if (raised_ambient)
        flags |= CFM_LSM_F_CAP_RAISE_AMBIENT;
    if (raised_inherit)
        flags |= CFM_LSM_F_CAP_RAISE_INHERITABLE;

    /* Lowest set bit index. The BPF v1 LLVM target doesn't implement
     * __builtin_ctz / __builtin_ctzll (LLVM opcode 191), so we
     * compute log2 of (raised & -raised) via the classic branchless
     * 5-step reduction:
     *   v = isolated lowest bit (a power of two)
     *   r = sum of bit positions where v lands in the half-masks
     * Five conditional-OR ops cover bits 0..31; we split the 64-bit
     * value into low/high halves and pick whichever half has a bit.
     * Low half covers the realistic targets (CAP_NET_RAW=13,
     * CAP_SETUID=7, CAP_SYS_ADMIN=21, CAP_SETFCAP=31); high half
     * covers CAP_BPF=39 / CAP_PERFMON=38 / CAP_CHECKPOINT_RESTORE=40.
     * Verifier-clean: no loops, no helper calls. */
    __u32 v;
    __u8 base;
    __u32 raised_lo = (__u32)(raised & 0xffffffffu);
    if (raised_lo) {
        /* Isolate lowest set bit via `x & -x`. Phrased as
         * (0u - raised_lo) — well-defined unsigned negation for
         * every u32 value including 0x80000000 (where the more
         * compact `-(__s32)raised_lo` would be signed-integer
         * overflow / UB even though LLVM happens to wrap). */
        v = raised_lo & (0u - raised_lo);
        base = 0;
    } else {
        __u32 raised_hi = (__u32)(raised >> 32);
        v = raised_hi & (0u - raised_hi);
        base = 32;
    }
    __u8 r = 0;
    if (v & 0xFFFF0000u) r |= 16;
    if (v & 0xFF00FF00u) r |= 8;
    if (v & 0xF0F0F0F0u) r |= 4;
    if (v & 0xCCCCCCCCu) r |= 2;
    if (v & 0xAAAAAAAAu) r |= 1;
    __u8 cap_bit = base + r;

    cfm_cred004_emit(flags, cap_bit, task);
    return 0;  /* monitor-only — commit_creds is not an LSM decision point */
}

char LICENSE[] SEC("license") = "GPL";
