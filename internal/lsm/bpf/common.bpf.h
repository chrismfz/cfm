/* SPDX-License-Identifier: GPL-2.0
 *
 * Shared BPF-side types and helpers for the cfm-lsm programs.
 *
 * Event records emitted by every cfm-lsm BPF program share the same
 * fixed-size struct so the Go-side ringbuf reader can decode them
 * uniformly regardless of which policy fired. The leading `policy_id`
 * field tells the reader which policy this event belongs to.
 */

#ifndef __CFM_LSM_COMMON_H__
#define __CFM_LSM_COMMON_H__

#include "vmlinux.h"

/* On-wire event policy IDs. Stable across releases — Go-side parsing
 * keys off these values, not strings. */
enum cfm_lsm_policy_id {
    CFM_LSM_POLICY_MEMFD_EXEC        = 1,  /* CFML-EXEC-001 */
    CFM_LSM_POLICY_REVERSE_SHELL     = 3,  /* CFML-EXEC-003 */
    CFM_LSM_POLICY_DELETED_FILE_EXEC = 4,  /* CFML-EXEC-004 */
    CFM_LSM_POLICY_INTERP_NET_STDIO  = 6,  /* CFML-EXEC-005 */
    CFM_LSM_POLICY_SENSITIVE_WRITE   = 5,  /* CFML-FS-005   */
    CFM_LSM_POLICY_CRED_ESCAL        = 7,  /* CFML-CRED-002 */
    CFM_LSM_POLICY_DIRECT_CRED       = 9,  /* CFML-CRED-003 */
    CFM_LSM_POLICY_UNEXPECTED_BPF    = 10, /* CFML-BPF-001  */
    CFM_LSM_POLICY_FD_CRED_MISMATCH  = 11, /* CFML-FS-006   */
};

/* File-system operation kind for CFML-FS-005 events. Carried in the
 * `op` byte of cfm_lsm_event (formerly _pad). 0 means "other / not
 * an FS event" and is the default for non-FS policy emissions. */
enum cfm_event_op {
    CFM_OP_NONE           = 0,
    CFM_FS_OP_SETATTR     = 1,
    CFM_FS_OP_CREATE      = 2,
    CFM_FS_OP_UNLINK      = 3,
    CFM_FS_OP_LINK        = 4,
    CFM_FS_OP_RENAME      = 5,
    CFM_FS_OP_SETXATTR    = 6,
    CFM_BPF_OP_MAP_CREATE = 20,
    CFM_BPF_OP_PROG_LOAD  = 21,
};

#define CFM_TASK_COMM_LEN 16
#define CFM_FILENAME_LEN  64

/* Event flags. */
#define CFM_LSM_F_WEB_ORIGIN          (1U << 0)
#define CFM_LSM_F_DIRECT_CRED_INSTALL (1U << 1)
#define CFM_LSM_F_UNLINKED_INODE      (1U << 2)
#define CFM_LSM_F_UNHASHED_DENTRY     (1U << 3)
#define CFM_LSM_F_REVSHELL_STRICT     (1U << 4)
#define CFM_LSM_F_INTERP_STDIO_WEAK   (1U << 5)
#define CFM_LSM_F_STDIO_ONE_REMOTE    (1U << 6)
#define CFM_LSM_F_STDIO_TWO_REMOTE    (1U << 7)

/* Compound inode map key shared by the watched-inode and setuid-inode
 * maps. `dev` is the target inode's stat-compatible filesystem
 * identity (super_block->s_dev encoded like stat(2) st_dev), and
 * `ino` is inode->i_ino. Pairing both
 * fields avoids collisions between different filesystems that reuse
 * the same inode number. */
struct cfm_inode_key {
    __u64 dev;
    __u64 ino;
};

/* Event record. Size deliberately fixed and small (well under the
 * 256 KiB ringbuf budget) so a busy host can buffer many events
 * before the Go reader drains them.
 *
 * Wire layout (112 bytes, stable since EXEC-001):
 *   offset  size  field
 *        0     8  ts_ns
 *        8     4  policy_id
 *       12     4  pid
 *       16     4  tgid
 *       20     4  uid
 *       24     4  gid
 *       28     1  op         (enum cfm_event_op; 0 for policies without an op)
 *       29     1  flags      (per-policy event flags; see CFM_LSM_F_*)
 *       30     2  _pad
 *       32    16  comm
 *       48    64  filename
 *
 * Total size unchanged from the EXEC-001 release — `_pad` was 4
 * bytes; FS-005 splits it into op + flags + 2 trailing pad bytes so
 * the Go parser does not need a wire-version bump. */
struct cfm_lsm_event {
    __u64 ts_ns;
    __u32 policy_id;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u8  op;
    __u8  flags;
    __u8  _pad1;
    __u8  _pad2;
    char  comm[CFM_TASK_COMM_LEN];
    char  filename[CFM_FILENAME_LEN];
} __attribute__((packed));

#endif /* __CFM_LSM_COMMON_H__ */
