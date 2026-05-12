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
 * Both hook bprm_check_security and currently run in monitor mode
 * (always return 0). Per docs/cfm-lsm.md the enforce-mode flip
 * happens via a bpf2go constant rewrite once telemetry justifies
 * it; the structure of each program is identical between the two
 * modes apart from that return value.
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
 * Mode: monitor only (return 0). Enforce (return -EPERM) is the
 * follow-up flip once telemetry confirms a near-zero FP rate.
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

    /* Match. Emit event; do not block (monitor mode). */
    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = CFM_LSM_POLICY_MEMFD_EXEC;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->_pad      = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    if (name)
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), name);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);

    return 0;
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
 * Mode: monitor only (return 0). Per docs/cfm-lsm.md this stays in
 * monitor mode for 30 days before any enforce promotion — fd-walk
 * detectors traditionally surface unanticipated legitimate patterns
 * for the first month.
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

    /* Match. Emit event; do not block (monitor mode). */
    struct cfm_lsm_event *e = bpf_ringbuf_reserve(&cfm_events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->policy_id = CFM_LSM_POLICY_REVERSE_SHELL;
    e->pid       = (__u32)(pid_tgid & 0xffffffffu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)(uid_gid & 0xffffffffu);
    e->gid       = (__u32)(uid_gid >> 32);
    e->_pad      = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Filename: the binary being exec'd (the would-be shell). */
    const char *fname = BPF_CORE_READ(bprm, filename);
    if (fname)
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), fname);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
