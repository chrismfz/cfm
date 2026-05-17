/*
 * bpf-mapcreate — create a BPF map from an untrusted comm.
 *
 * Threat scenario: an attacker installing a BPF-based rootkit (the
 * 2022-onwards Linux-malware trend — bvp47, boopkit, symbiote, etc).
 * Step one for any of them is to call bpf(BPF_MAP_CREATE, ...) to
 * stash hidden state or hook-tracking data, then bpf(BPF_PROG_LOAD,
 * ...) for the actual hooks. CFM-LSM's BPF-001 catches the syscall
 * on entry; the kernel side allowlist is the comm name, so a binary
 * named anything outside the trusted set (cfm / systemd / bpftool /
 * NetworkManager / auditd / containerd / etc) fires the rule.
 *
 * This helper executes the minimal bpf(BPF_MAP_CREATE) for an array
 * map and exits. No libbpf dependency — we declare the union ourselves
 * and use the raw syscall, which is intentionally what real-world
 * BPF malware does too (no externally-resolvable symbol fingerprints).
 *
 * The comm seen by the kernel is the binary's basename, which is
 * "bpf-mapcreate" when invoked directly. The scenario script renames
 * this binary into /tmp/.cfm-bd-installer so the kernel comm is the
 * suspicious name we want in the lsm.log event.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef BPF_MAP_CREATE
#define BPF_MAP_CREATE 0
#endif
#ifndef BPF_MAP_TYPE_ARRAY
#define BPF_MAP_TYPE_ARRAY 2
#endif

/* Minimal bpf_attr for BPF_MAP_CREATE. We only fill the fields the
 * kernel reads for this command — the union is large but the kernel
 * checks attr_size separately and accepts a shorter struct as long
 * as the trailing bytes are zero. */
union bpf_attr_map_create {
    struct {
        __u32 map_type;
        __u32 key_size;
        __u32 value_size;
        __u32 max_entries;
        __u32 map_flags;
        __u32 inner_map_fd;
        __u32 numa_node;
        char  map_name[16];
        __u32 map_ifindex;
        __u32 btf_fd;
        __u32 btf_key_type_id;
        __u32 btf_value_type_id;
    };
};

int main(void)
{
    union bpf_attr_map_create attr = {};
    attr.map_type    = BPF_MAP_TYPE_ARRAY;
    attr.key_size    = 4;
    attr.value_size  = 4;
    attr.max_entries = 1;
    strncpy(attr.map_name, "cfm_poc_evil", sizeof(attr.map_name) - 1);

    int fd = (int)syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd < 0) {
        /* EPERM is expected on kernels with
         * kernel.unprivileged_bpf_disabled=1 when invoked as non-root.
         * That's fine — BPF-001 fires on syscall entry before the
         * permission check, so the LSM event is recorded either way. */
        fprintf(stderr, "bpf(BPF_MAP_CREATE) returned errno=%d (%s)\n",
                errno, strerror(errno));
        return errno == EPERM ? 0 : 1;
    }

    fprintf(stderr, "bpf(BPF_MAP_CREATE) succeeded; fd=%d\n", fd);
    close(fd);
    return 0;
}
