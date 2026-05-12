// Package lsm — BPF-object generation directive.
//
// This file exists only to host the //go:generate line that invokes
// bpf2go. Running `go generate ./internal/lsm/...` calls clang on the
// BPF C sources under internal/lsm/bpf/ and produces:
//
//   - cfmlsm_x86_bpfel.{go,o}    — x86_64 little-endian
//   - cfmlsm_arm64_bpfel.{go,o}  — aarch64 little-endian
//
// Both pairs are committed to the repository. End users and
// downstream packagers therefore do not need clang or libbpf-dev to
// build CFM — `go build` (CGO_ENABLED=0) embeds the prebuilt .o via
// go:embed.
//
// Build deps for regenerating the BPF objects (contributors only):
//
//   - clang ≥ 11
//   - libbpf-dev (provides <bpf/bpf_helpers.h> and friends)
//   - kernel headers ≥ 5.7 are NOT required here; the BPF sources
//     are self-contained via internal/lsm/bpf/vmlinux.h.
//
// See docs/cfm-lsm.md (Architecture → Build model) for the rationale.
package lsm

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64,arm64 -cflags "-O2 -Wall -Werror -I./bpf" cfmlsm bpf/memfd_exec.bpf.c
