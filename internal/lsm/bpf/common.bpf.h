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
    CFM_LSM_POLICY_MEMFD_EXEC   = 1,  /* CFML-EXEC-001 */
    CFM_LSM_POLICY_REVERSE_SHELL = 3, /* CFML-EXEC-003 (placeholder, not yet implemented) */
};

#define CFM_TASK_COMM_LEN 16
#define CFM_FILENAME_LEN  64

/* Event record. Size deliberately fixed and small (well under the
 * 256 KiB ringbuf budget) so a busy host can buffer many events
 * before the Go reader drains them. */
struct cfm_lsm_event {
    __u64 ts_ns;
    __u32 policy_id;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 _pad;
    char  comm[CFM_TASK_COMM_LEN];
    char  filename[CFM_FILENAME_LEN];
} __attribute__((packed));

#endif /* __CFM_LSM_COMMON_H__ */
