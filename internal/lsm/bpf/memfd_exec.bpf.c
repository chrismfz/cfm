/* SPDX-License-Identifier: GPL-2.0
 *
 * CFML-EXEC-001 — Block exec from memfd.
 *
 * Hook: bprm_check_security (LSM)
 *
 * Mechanism
 * ---------
 * On every exec the kernel calls bprm_check_security with the
 * candidate `struct linux_binprm`. We inspect bprm->file:
 *
 *   1. f_inode->i_sb->s_magic == TMPFS_MAGIC. Memfd is always
 *      backed by an anonymous shmem inode whose superblock is
 *      tmpfs. This single check already filters out ~all normal
 *      exec paths (binaries on disk).
 *
 *   2. dentry name starts with "memfd:". This is the kernel's
 *      convention for memfd_create() — see fs/anon_inodes.c and
 *      memfd_create(2). The check disambiguates a real tmpfs file
 *      (legitimate /tmp/foo on a host where /tmp is tmpfs) from
 *      a true memfd payload.
 *
 * Mode
 * ----
 * Monitor only in this MVP slice: we emit a ringbuf event and
 * return 0 (allow). Enforce mode (return -EPERM) is a compile-time
 * constant set via bpf2go's constant rewriting once telemetry
 * proves FP rate is acceptable.
 *
 * Verifier notes
 * --------------
 * - All field reads go through BPF_CORE_READ so the kernel verifier
 *   can hand us the right offsets via CO-RE relocation.
 * - The dentry name comparison is unrolled to keep the program
 *   linear and within the older-kernel complexity budget.
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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} cfm_events SEC(".maps");

/* dentry_name_is_memfd checks the first 6 chars of d->d_name.name
 * against the literal "memfd:". Done with bpf_probe_read_kernel_str
 * so the verifier accepts the bounded read. */
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

    /* Best-effort filename copy from the dentry. dentry->d_name.name
     * points at "memfd:<label>" — useful for forensics. */
    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    if (name)
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), name);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
