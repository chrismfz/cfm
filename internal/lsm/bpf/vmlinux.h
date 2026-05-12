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

/* BPF map type enum subset. Mirrors include/uapi/linux/bpf.h. Only
 * the value cfm-lsm uses today (ringbuf) needs to be correct. */
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC                = 0,
    BPF_MAP_TYPE_HASH                  = 1,
    BPF_MAP_TYPE_ARRAY                 = 2,
    BPF_MAP_TYPE_RINGBUF               = 27,
};

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

struct dentry {
    struct qstr            d_name;
    struct dentry         *d_parent;
} ___NCO;

struct path {
    struct dentry         *dentry;
} ___NCO;

struct super_block {
    unsigned long          s_magic;
} ___NCO;

struct inode {
    struct super_block    *i_sb;
} ___NCO;

struct file {
    struct path            f_path;
    struct inode          *f_inode;
} ___NCO;

struct linux_binprm {
    struct file           *file;
    const char            *filename;
    const char            *interp;
} ___NCO;

#endif /* __CFM_VMLINUX_H__ */
