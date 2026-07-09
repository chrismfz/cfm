/* SPDX-License-Identifier: GPL-2.0
 *
 * Minimal CO-RE vmlinux.h for cfm-lsm — only the kernel types the
 * MVP BPF programs touch, hand-written rather than generated via
 *
 *     bpftool btf dump file /sys/kernel/btf/vmlinux format c
 *
 * because the produced header is multi-megabyte and most of it is
 * dead weight for our two-policy scope. The smaller surface also
 * makes it easier to audit and keeps it stable across kernel
 * versions — every field accessed by the programs is part of the
 * long-standing kernel ABI, and the actual offsets are resolved at
 * load time via CO-RE relocation rather than from the layout here.
 *
 * When EXEC-003 (reverse shell) lands, extend this file with the
 * additional types it needs (task_struct fdtable / file_struct,
 * socket / sock for fd-walk) and regenerate the BPF objects.
 */

#ifndef __CFM_VMLINUX_H__
#define __CFM_VMLINUX_H__

typedef signed char         __s8;
typedef unsigned char       __u8;
typedef short               __s16;
typedef unsigned short      __u16;
typedef int                 __s32;
typedef unsigned int        __u32;
typedef long long           __s64;
typedef unsigned long long  __u64;

typedef __u8   u8;
typedef __u16  u16;
typedef __u32  u32;
typedef __u64  u64;
typedef __s32  s32;
typedef __s64  s64;

/* Endian-tagged aliases. libbpf's bpf_helper_defs.h references
 * __be16/__be32 / __wsum from network helpers we do not use; the
 * typedefs still have to exist for that header to compile. */
typedef __u16  __be16;
typedef __u16  __le16;
typedef __u32  __be32;
typedef __u32  __le32;
typedef __u64  __be64;
typedef __u64  __le64;
typedef __u16  __sum16;
typedef __u32  __wsum;

typedef _Bool  bool;
enum { false = 0, true = 1 };

/* Kernel typedefs used by LSM hook signatures. umode_t is the mode
 * field type used by inode_create; size_t by inode_setxattr. We use
 * the kernel ABI definitions, not stddef ones, to avoid pulling
 * platform headers into the BPF compile. */
typedef __u16  umode_t;
typedef __u32  gfp_t;
#ifndef __SIZE_TYPE__
typedef unsigned long  size_t;
#else
typedef __SIZE_TYPE__  size_t;
#endif

/* BPF map type enum subset. Mirrors include/uapi/linux/bpf.h for
 * the map kinds cfm-lsm uses. */
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC                = 0,
    BPF_MAP_TYPE_HASH                  = 1,
    BPF_MAP_TYPE_ARRAY                 = 2,
    BPF_MAP_TYPE_RINGBUF               = 27,
    BPF_MAP_TYPE_INODE_STORAGE         = 28,
    BPF_MAP_TYPE_TASK_STORAGE          = 29,
};

#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 0)
#endif
#ifndef BPF_LOCAL_STORAGE_GET_F_CREATE
#define BPF_LOCAL_STORAGE_GET_F_CREATE (1U << 0)
#endif

/* CO-RE-relocated structs. Only the fields cfm-lsm reads are listed;
 * absent kernel fields are not a problem for BPF_CORE_READ as long
 * as the named field exists in the running kernel's BTF. */

#define ___NCO __attribute__((preserve_access_index))

struct qstr {
    union {
        struct {
            __u32 hash;
            __u32 len;
        };
        __u64 hash_len;
    };
    const unsigned char *name;
} ___NCO;

struct hlist_bl_node {
    struct hlist_bl_node  *next;
    struct hlist_bl_node **pprev;
} ___NCO;

struct dentry {
    struct hlist_bl_node   d_hash;
    struct qstr            d_name;
    struct dentry         *d_parent;
    struct inode          *d_inode;
} ___NCO;

struct path {
    struct dentry         *dentry;
} ___NCO;

struct super_block {
    unsigned long          s_magic;
    __u32                  s_dev;
} ___NCO;

struct inode {
    __u16                  i_mode;
    unsigned int           __i_nlink;
    unsigned long          i_ino;
    struct super_block    *i_sb;
} ___NCO;

struct file {
    struct path            f_path;
    struct inode          *f_inode;
    void                  *private_data;
    /* f_cred is captured at open(2) time and never updated; CFML-FS-006
     * compares its euid against current's euid to detect fd leaks from
     * setuid helpers. The struct cred forward decl lives further down,
     * just above struct task_struct. */
    const struct cred     *f_cred;
} ___NCO;

struct linux_binprm {
    struct file           *file;
    const char            *filename;
    const char            *interp;
} ___NCO;

/* Types used by CFML-EXEC-003 (reverse-shell fd-walk).
 *
 * The fd table layout is:
 *
 *   current()->files (struct files_struct *)
 *     ->fdt (struct fdtable *)
 *       ->fd (struct file **)
 *
 * From the file we read f_inode->i_mode & S_IFMT to confirm it is a
 * socket (cheaper than comparing f_op against &socket_file_ops, and
 * does not require any kernel-symbol lookup). For sockets the
 * private_data points at the struct socket, which carries the sock.
 * From the sock we read sk_family (skip AF_UNIX) and sk_state
 * (require TCP_ESTABLISHED). */

#ifndef S_IFMT
#define S_IFMT  0170000
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif

#ifndef AF_INET
#define AF_INET  2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* TCP states from include/net/tcp_states.h. Only ESTABLISHED is
 * meaningful for a reverse shell; LISTEN/SYN_SENT etc. are filtered
 * out so this does not fire on accept loops or half-open handshakes. */
#ifndef TCP_ESTABLISHED
#define TCP_ESTABLISHED 1
#endif

struct fdtable {
    unsigned int           max_fds;
    struct file          **fd;
} ___NCO;

struct files_struct {
    struct fdtable        *fdt;
} ___NCO;

/* Types used by CFML-CRED-002 (priv-esc-without-setuid).
 *
 * kuid_t is a single-field wrapper around __u32. cred_prepare hands
 * the program both `new` and `old` cred pointers; we only read .euid.val.
 *
 * mm_struct.exe_file is the file currently mmaped as the process's
 * primary executable. We resolve its inode and compare against the
 * setuid-binary inode map. */
struct kuid_t {
    __u32 val;
} ___NCO;

struct kgid_t {
    __u32 val;
} ___NCO;

struct cred {
    struct kuid_t          uid;
    struct kgid_t          gid;
    struct kuid_t          suid;
    struct kgid_t          sgid;
    struct kuid_t          euid;
    struct kgid_t          egid;
    struct kuid_t          fsuid;
    struct kgid_t          fsgid;
    /* Capability sets. The kernel field type is kernel_cap_t, which
     * changed layout in 6.3 (commit f7d7a8e2cf02):
     *   pre-6.3: struct kernel_cap_struct { __u32 cap[2]; }
     *   6.3+:    typedef struct { __u64 val; } kernel_cap_t
     * Both forms are 8 bytes total; both retain the same field
     * offset within `struct cred`. We expose BOTH possible member
     * names via a union so the BPF source can probe the live kernel
     * BTF at load time (via bpf_core_field_exists) and pick the
     * correct accessor. Only ONE of the union's leaves resolves on
     * any given kernel; the other one's bpf_core_field_exists
     * check returns 0 and that branch becomes dead code at the
     * verifier's eyes via libbpf's CO-RE relocation rewrite. Used
     * by CFML-CRED-004 to detect cap_ambient / cap_inheritable
     * raises by watched uids.
     *
     * No explicit ___NCO on the inner unions: clang propagates the
     * outer struct's __attribute__((preserve_access_index)) into
     * nested anonymous unions automatically. Same precedent as
     * `struct qstr` further down in this file, whose anonymous
     * union is read via CO-RE without each leaf carrying its own
     * attribute. */
    union {
        __u64 val;        /* 6.3+ accessor */
        __u32 cap[2];     /* pre-6.3 accessor */
    } cap_inheritable;
    union {
        __u64 val;
        __u32 cap[2];
    } cap_ambient;
} ___NCO;

struct mm_struct {
    struct file           *exe_file;
} ___NCO;

struct task_struct {
    struct mm_struct      *mm;
    struct files_struct   *files;
    const struct cred     *cred;
    /* tgid is the thread-group id (== the process id userspace sees);
     * real_parent points at the parent task, so real_parent->tgid is the
     * ppid. Both are CO-RE-resolved from kernel BTF at load, so the
     * in-source position here is only a shape hint. ppid is read for
     * every event (cfm_event_fill_kin); tgid is read from the ptrace
     * TARGET task by CFML-OBS-004. */
    int                    tgid;
    struct task_struct    *real_parent;
    /* comm is an inline TASK_COMM_LEN-byte char buffer holding the
     * task's command name. CO-RE resolves the offset from kernel BTF
     * at load time, so the in-source size is just a shape hint;
     * the live kernel may carry the same field at a different offset
     * and the verifier handles the relocation. Used by CFML-OBS-004
     * to read the ptrace-target task's identity (current task's comm
     * is available cheaply via bpf_get_current_comm). */
    char comm[16];
} ___NCO;

/* Used by CFML-FS-005 (opaque — only the type matters for BPF_PROG
 * signature compatibility) and by CFML-FS-007 (reads ia_valid + ia_mode
 * to detect suid/sgid bits being set). The ___NCO / preserve_access_index
 * attribute makes CO-RE resolve field offsets against the live kernel
 * BTF at load time, so this in-source layout is just a shape hint —
 * the compiler doesn't need every kernel iattr field to be enumerated. */
struct iattr {
    unsigned int ia_valid;
    umode_t      ia_mode;
} ___NCO;

/* The first argument of inode_setattr / inode_setxattr drifted across
 * kernels (commit `9452e93e` and friends, "fs: port to mnt_idmap"):
 *   - Pre-5.12 / EL9 5.14 backport: no first arg
 *   - 5.12-6.2:                     struct user_namespace *mnt_userns
 *   - 6.3+ / EL10 6.12:             struct mnt_idmap *idmap
 * BPF_PROG argument count must exactly match the kernel's trampoline
 * arity or the verifier rejects with "doesn't have N-th argument".
 * We carry two C variants per drifting hook (`_noidmap` and `_idmap`)
 * and the Go loader BTF-probes the kernel at load time to neutralise
 * the wrong one. See cfmlsm.bpf.c near `cfm_fs005_setattr_noidmap`
 * and internal/lsm/btfprobe.go.
 *
 * The empty struct is enough because the `_idmap` variant takes its
 * first arg as `void *` — we never read fields. Keeping the struct
 * declared makes earlier-version vmlinux.h headers from contributors
 * cross-compile without diff churn. */
struct mnt_idmap {} ___NCO;

/* sock_common holds the cheap-to-read state and family fields that
 * union into both struct sock and struct inet_sock. Reading them via
 * struct sock's __sk_common embedded member is the canonical CO-RE
 * idiom and is portable across kernel versions. */
struct sock_common {
    unsigned short         skc_family;
    unsigned char          skc_state;
} ___NCO;

struct sock {
    struct sock_common     __sk_common;
} ___NCO;

struct socket {
    struct sock           *sk;
} ___NCO;

#endif /* __CFM_VMLINUX_H__ */
