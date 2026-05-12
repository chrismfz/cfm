// Package lsm is the scaffolding for cfm-lsm — a BPF LSM-based
// userspace-behaviour enforcement subsystem of the CFM daemon.
//
// This package currently provides:
//
//   - The /etc/cfm/lsm.conf parser and writer.
//   - A kernel preflight that determines whether the running host can
//     load CO-RE BPF LSM programs at all.
//   - The `cfm lsm` CLI surface (status, preview, init).
//
// No BPF programs are loaded yet. Every policy reports "not implemented"
// until the EXEC-001 and EXEC-003 BPF programs land in a subsequent
// change. The package exists at this stage so operators can audit
// fleet readiness ahead of the rollout and so the config / CLI shape
// is settled before any BPF C is committed.
//
// See docs/cfm-lsm.md for the design.
package lsm
