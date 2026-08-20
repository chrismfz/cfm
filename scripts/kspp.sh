#!/usr/bin/env bash
# ============================================================
# KSPP Server-Safe Hardening Script
# ------------------------------------------------------------
# STANDALONE hardening script — usable on its own on hosts that
# don't run cfm. Also serves as the reference implementation for
# the cfm kernsec component (see docs/kernsec.md): bootloader
# detection, boot-arg management, sysctl apply/verify, status
# checks. cfm kernsec is the canonical implementation; this
# script stays for non-cfm hosts and historical reference.
#
# When extending: prefer cfm kernsec for new functionality. Keep
# this script focused on the KSPP server-safe profile and bug
# fixes. A future direction is to have this script delegate to
# `cfm kernsec` when present, falling back to the bash flow
# otherwise — not implemented yet.
# ------------------------------------------------------------
# Cross-distro boot support:
#   - Proxmox systemd-boot / proxmox-boot-tool
#   - RHEL/Alma/Rocky BLS / grubby
#   - Debian/Ubuntu/RHEL legacy GRUB
#
# Simple modes:
#   enable   Apply server-safe hardening
#   disable  Remove managed boot args and sysctl file
#   status   Show status + verification
#
# Notes:
#   - Boot args require reboot before becoming active.
#   - This script only manages boot args listed in MANAGED_ARG_KEYS.
#   - Copy Fail / CVE-2026-31431 workaround is included:
#       initcall_blacklist=algif_aead_init
#     Remove it later once all relevant kernels are patched.
# ============================================================

set -Eeuo pipefail

MODE="${1:-status}"

SYSCTL_FILE="/etc/sysctl.d/99-kspp.conf"

GRUB_FILE="/etc/default/grub"
GRUB_BACKUP="/etc/default/grub.kspp.bak"

PVE_CMDLINE_FILE="/etc/kernel/cmdline"
PVE_CMDLINE_BACKUP="/etc/kernel/cmdline.kspp.bak"

# ------------------------------------------------------------
# Server-safe sysctl profile
# ------------------------------------------------------------

KSPP_SYSCTL=(
  "kernel.kptr_restrict=2"
  "kernel.dmesg_restrict=1"
  "kernel.unprivileged_bpf_disabled=2"
  "kernel.randomize_va_space=2"

  "fs.protected_hardlinks=1"
  "fs.protected_symlinks=1"
  "fs.protected_fifos=2"
  # fs.protected_regular is 1, NOT the stricter KSPP 2: value 2 also
  # covers group-writable sticky dirs, which breaks cPanel's DNS Zone
  # Editor. 1 still guards world-writable sticky dirs (/tmp, /var/tmp).
  # Kept in sync with kernsec (internal/kernsec/profile.go) so this
  # legacy script never re-introduces the =2 that kernsec reconciles.
  "fs.protected_regular=1"

  "net.core.bpf_jit_harden=2"

  # Stronger perf restriction, usually safe on servers.
  "kernel.perf_event_paranoid=3"

  # Mode 2: ptrace attach requires CAP_SYS_PTRACE in init_user_ns.
  # Beyond mode 1's child-only restriction, mode 2 also closes the
  # same-uid pidfd_getfd() exit-window race against setuid helpers
  # (the ssh-keysign host-key theft chain — Linus commit 31e62c2ebbfd).
  # Cost: gdb --attach / strace -p / py-spy etc. need sudo.
  "kernel.yama.ptrace_scope=2"
)

# ------------------------------------------------------------
# Server-safe boot args
# ------------------------------------------------------------

KSPP_ARGS=(
  "slab_nomerge"
  "init_on_alloc=1"
  "page_alloc.shuffle=1"
  "randomize_kstack_offset=on"

  # Temporary mitigation for CVE-2026-31431 / Copy Fail.
  # Prevents algif_aead_init() from running during boot.
  # Requires reboot.
  # Remove later once all relevant kernels are patched.
  "initcall_blacklist=algif_aead_init"
)

# This script owns these boot arg keys.
# disable removes them. enable removes stale values first, then adds KSPP_ARGS.
MANAGED_ARG_KEYS=(
  "slab_nomerge"
  "init_on_alloc"
  "page_alloc.shuffle"
  "randomize_kstack_offset"
  "initcall_blacklist"
)

RUNTIME_SYSCTL_KEYS=(
  "kernel.kptr_restrict"
  "kernel.dmesg_restrict"
  "kernel.unprivileged_bpf_disabled"
  "kernel.randomize_va_space"
  "kernel.perf_event_paranoid"
  "kernel.yama.ptrace_scope"

  "fs.protected_hardlinks"
  "fs.protected_symlinks"
  "fs.protected_fifos"
  "fs.protected_regular"

  "net.core.bpf_jit_harden"
)

log() {
  echo "[*] $*"
}

ok() {
  echo "[+] $*"
}

warn() {
  echo "[!] $*" >&2
}

die() {
  echo "[ERROR] $*" >&2
  exit 1
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Run as root."
  fi
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

join_by_space() {
  local IFS=' '
  echo "$*"
}

sysctl_proc_path() {
  local key="$1"
  echo "/proc/sys/${key//./\/}"
}

sysctl_exists() {
  local key="$1"
  [[ -e "$(sysctl_proc_path "$key")" ]]
}

# ------------------------------------------------------------
# Boot backend detection
# ------------------------------------------------------------

is_proxmox_boot_tool() {
  has_cmd proxmox-boot-tool || return 1
  [[ -f "$PVE_CMDLINE_FILE" ]] || return 1

  # Strong indication: currently booted with Proxmox EFI/systemd-boot entries.
  if grep -qE '(^| )initrd=\\EFI\\proxmox\\' /proc/cmdline 2>/dev/null; then
    return 0
  fi

  # Also accept proxmox-boot-tool systems with configured ESPs.
  if proxmox-boot-tool status 2>/dev/null | grep -qiE 'configured|esp|proxmox|systemd-boot'; then
    return 0
  fi

  return 1
}

is_bls() {
  [[ -d /boot/loader/entries ]] || return 1
  has_cmd grubby || return 1

  # If explicitly disabled, do not use BLS even if entries exist.
  if [[ -f /etc/default/grub ]] && grep -qE '^GRUB_ENABLE_BLSCFG="?false"?' /etc/default/grub; then
    return 1
  fi

  # Strong evidence active GRUB config loads BLS.
  if grep -Rqs 'blscfg' /boot/grub2/grub.cfg /boot/grub/grub.cfg /boot/efi/EFI/*/grub.cfg 2>/dev/null; then
    return 0
  fi

  # Fallback only if explicitly enabled.
  if [[ -f /etc/default/grub ]] && grep -qE '^GRUB_ENABLE_BLSCFG="?true"?' /etc/default/grub; then
    return 0
  fi

  return 1
}

boot_backend() {
  if is_proxmox_boot_tool; then
    echo "proxmox"
  elif is_bls; then
    echo "bls"
  else
    echo "grub"
  fi
}

boot_backend_label() {
  case "$(boot_backend)" in
    proxmox) echo "Proxmox boot tool / systemd-boot" ;;
    bls)     echo "BLS / grubby" ;;
    grub)    echo "Legacy GRUB" ;;
  esac
}

# ------------------------------------------------------------
# General helpers
# ------------------------------------------------------------

get_kernel_log() {
  journalctl -k -b -o cat 2>/dev/null || dmesg 2>/dev/null || true
}

get_kernel_config_path() {
  local cfg="/boot/config-$(uname -r)"

  if [[ -r "$cfg" ]]; then
    echo "$cfg"
    return
  fi

  echo ""
}

read_kernel_config() {
  local cfg
  cfg="$(get_kernel_config_path)"

  if [[ -n "$cfg" ]]; then
    cat "$cfg"
  elif [[ -r /proc/config.gz ]] && has_cmd zcat; then
    zcat /proc/config.gz
  else
    return 1
  fi
}

apply_sysctl_file() {
  [[ -f "$SYSCTL_FILE" ]] || return 0

  log "Applying sysctl from $SYSCTL_FILE"
  sysctl --load="$SYSCTL_FILE" >/dev/null
}

write_sysctl_file() {
  log "Writing $SYSCTL_FILE"

  {
    echo "# Managed by kspp.sh"
    echo "# Do not edit manually unless you know what you are doing."

    local line key proc
    for line in "${KSPP_SYSCTL[@]}"; do
      key="${line%%=*}"
      proc="$(sysctl_proc_path "$key")"

      if [[ -e "$proc" ]]; then
        echo "$line"
      else
        echo "# skipped missing sysctl: $line"
        warn "Skipping missing sysctl: $key"
      fi
    done
  } > "$SYSCTL_FILE"

  apply_sysctl_file
}

remove_managed_args_from_line() {
  local line="$1"
  local out=()
  local word key remove managed

  for word in $line; do
    key="${word%%=*}"
    remove=0

    for managed in "${MANAGED_ARG_KEYS[@]}"; do
      if [[ "$key" == "$managed" ]]; then
        remove=1
        break
      fi
    done

    [[ "$remove" -eq 0 ]] && out+=("$word")
  done

  echo "${out[*]:-}"
}

# ------------------------------------------------------------
# GRUB helpers
# ------------------------------------------------------------

backup_grub() {
  if [[ -f "$GRUB_FILE" && ! -f "$GRUB_BACKUP" ]]; then
    cp -a "$GRUB_FILE" "$GRUB_BACKUP"
    ok "Created backup: $GRUB_BACKUP"
  fi
}

get_grub_cmdline() {
  if [[ ! -f "$GRUB_FILE" ]]; then
    echo ""
    return
  fi

  if grep -qE '^GRUB_CMDLINE_LINUX=' "$GRUB_FILE"; then
    grep -E '^GRUB_CMDLINE_LINUX=' "$GRUB_FILE" \
      | sed -E 's/^GRUB_CMDLINE_LINUX="(.*)"/\1/'
  else
    echo ""
  fi
}

set_grub_cmdline() {
  local new_cmdline="$1"

  if grep -qE '^GRUB_CMDLINE_LINUX=' "$GRUB_FILE"; then
    sed -i -E "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"${new_cmdline}\"|" "$GRUB_FILE"
  else
    echo "GRUB_CMDLINE_LINUX=\"${new_cmdline}\"" >> "$GRUB_FILE"
  fi
}

update_grub_cfg() {
  # Debian/Ubuntu wrapper.
  if has_cmd update-grub; then
    log "Regenerating GRUB config using update-grub"
    update-grub >/dev/null
    return
  fi

  local mkconfig=""

  if has_cmd grub2-mkconfig; then
    mkconfig="grub2-mkconfig"
  elif has_cmd grub-mkconfig; then
    mkconfig="grub-mkconfig"
  else
    die "Could not find update-grub, grub2-mkconfig, or grub-mkconfig"
  fi

  local cfg=""

  if [[ -f /boot/grub2/grub.cfg || -d /boot/grub2 ]]; then
    cfg="/boot/grub2/grub.cfg"
  elif [[ -f /boot/grub/grub.cfg || -d /boot/grub ]]; then
    cfg="/boot/grub/grub.cfg"
  elif [[ -d /sys/firmware/efi ]]; then
    cfg="$(find /boot/efi/EFI -name grub.cfg 2>/dev/null | head -n1 || true)"
    [[ -n "$cfg" ]] || die "Could not find EFI grub.cfg"
  else
    die "Could not determine GRUB config output path"
  fi

  log "Regenerating GRUB config using $mkconfig: $cfg"
  "$mkconfig" -o "$cfg" >/dev/null
}

# ------------------------------------------------------------
# Boot arg application backends
# ------------------------------------------------------------

apply_boot_args_proxmox() {
  local -a desired_args=("$@")

  [[ -f "$PVE_CMDLINE_FILE" ]] || die "$PVE_CMDLINE_FILE not found"
  has_cmd proxmox-boot-tool || die "proxmox-boot-tool not found"

  if [[ ! -f "$PVE_CMDLINE_BACKUP" ]]; then
    cp -a "$PVE_CMDLINE_FILE" "$PVE_CMDLINE_BACKUP"
    ok "Created backup: $PVE_CMDLINE_BACKUP"
  fi

  local current cleaned new_cmdline

  current="$(cat "$PVE_CMDLINE_FILE")"
  cleaned="$(remove_managed_args_from_line "$current")"

  if [[ "${#desired_args[@]}" -gt 0 ]]; then
    new_cmdline="$(echo "$cleaned $(join_by_space "${desired_args[@]}")" | xargs)"
  else
    new_cmdline="$(echo "$cleaned" | xargs)"
  fi

  log "Updating $PVE_CMDLINE_FILE"
  echo "$new_cmdline" > "$PVE_CMDLINE_FILE"

  log "Refreshing Proxmox boot entries"
  proxmox-boot-tool refresh
}

apply_boot_args_bls() {
  local -a desired_args=("$@")
  local -a remove_args=()
  local key

  for key in "${MANAGED_ARG_KEYS[@]}"; do
    remove_args+=("$key")
  done

  log "Removing old managed KSPP boot args from all kernels"
  grubby --update-kernel=ALL --remove-args="$(join_by_space "${remove_args[@]}")"

  if [[ "${#desired_args[@]}" -gt 0 ]]; then
    log "Adding KSPP boot args to all kernels: $(join_by_space "${desired_args[@]}")"
    grubby --update-kernel=ALL --args="$(join_by_space "${desired_args[@]}")"
  fi
}

apply_boot_args_grub() {
  local -a desired_args=("$@")

  [[ -f "$GRUB_FILE" ]] || die "$GRUB_FILE not found"
  backup_grub

  local current cleaned new_cmdline

  current="$(get_grub_cmdline)"
  cleaned="$(remove_managed_args_from_line "$current")"

  if [[ "${#desired_args[@]}" -gt 0 ]]; then
    new_cmdline="$(echo "$cleaned $(join_by_space "${desired_args[@]}")" | xargs)"
  else
    new_cmdline="$(echo "$cleaned" | xargs)"
  fi

  log "Updating GRUB_CMDLINE_LINUX"
  set_grub_cmdline "$new_cmdline"
  update_grub_cfg
}

apply_boot_args() {
  case "$(boot_backend)" in
    proxmox)
      apply_boot_args_proxmox "$@"
      ;;
    bls)
      apply_boot_args_bls "$@"
      ;;
    grub)
      apply_boot_args_grub "$@"
      ;;
  esac
}

get_default_kernel_args() {
  case "$(boot_backend)" in
    proxmox)
      cat "$PVE_CMDLINE_FILE" 2>/dev/null || echo "(unknown)"
      ;;
    bls)
      grubby --info=DEFAULT 2>/dev/null \
        | sed -n 's/^args=//p' \
        | sed -E 's/^"//; s/"$//'
      ;;
    grub)
      if [[ -f "$GRUB_FILE" ]]; then
        get_grub_cmdline
      else
        echo "(unknown)"
      fi
      ;;
  esac
}

print_arg_state() {
  local line="$1"
  local wanted="$2"
  local key="${wanted%%=*}"
  local word found=""

  for word in $line; do
    if [[ "$word" == "$wanted" ]]; then
      echo "OK        $wanted"
      return 0
    fi

    if [[ "${word%%=*}" == "$key" ]]; then
      found="$word"
    fi
  done

  if [[ -n "$found" ]]; then
    echo "DIFF      wanted: $wanted    found: $found"
    return 1
  fi

  echo "MISSING   $wanted"
  return 1
}

show_arg_state() {
  local line="$1"
  local label="$2"
  shift 2

  echo
  echo "[$label]"

  if [[ "$#" -eq 0 ]]; then
    echo "(none expected)"
    return
  fi

  local wanted
  for wanted in "$@"; do
    print_arg_state "$line" "$wanted" || true
  done
}

enable() {
  need_root

  write_sysctl_file
  apply_boot_args "${KSPP_ARGS[@]}"

  ok "KSPP server-safe hardening enabled."
  warn "Boot parameters require reboot before they appear in /proc/cmdline."
  log "After reboot, run: $0 status"
}

disable() {
  need_root

  if [[ -f "$SYSCTL_FILE" ]]; then
    rm -f "$SYSCTL_FILE"
    ok "Removed $SYSCTL_FILE"
  else
    log "$SYSCTL_FILE already absent"
  fi

  apply_boot_args

  ok "Removed managed KSPP boot args."
  warn "Runtime sysctl values may remain until reboot or until overridden by another sysctl file."
  warn "Boot parameter removal also requires reboot."
}

status() {
  local current_cmdline next_args klog failed=0
  current_cmdline="$(cat /proc/cmdline 2>/dev/null || true)"
  next_args="$(get_default_kernel_args)"
  klog="$(get_kernel_log)"

  echo "===== KSPP STATUS + VERIFY ====="
  echo

  echo "[Boot mode]"
  boot_backend_label

  echo
  echo "[Current running kernel cmdline]"
  echo "$current_cmdline"

  echo
  echo "[Configured default kernel cmdline - next boot]"
  echo "$next_args"

  echo
  echo "[Persistent sysctl file]"
  if [[ -f "$SYSCTL_FILE" ]]; then
    cat "$SYSCTL_FILE"
  else
    echo "(none)"
  fi

  echo
  echo "[Runtime sysctl values]"
  local key
  for key in "${RUNTIME_SYSCTL_KEYS[@]}"; do
    if sysctl_exists "$key"; then
      sysctl "$key" 2>/dev/null || true
    else
      echo "$key = (missing)"
    fi
  done

  echo
  echo "[Expected runtime sysctl verification]"
  local line expected actual
  for line in "${KSPP_SYSCTL[@]}"; do
    key="${line%%=*}"
    expected="${line#*=}"

    if sysctl_exists "$key"; then
      actual="$(sysctl -n "$key" 2>/dev/null || true)"

      if [[ "$actual" == "$expected" ]]; then
        echo "OK        $key=$actual"
      else
        echo "WARN      $key expected $expected, found $actual"
        failed=1
      fi
    else
      echo "SKIP      $key is missing on this kernel"
    fi
  done

  show_arg_state "$current_cmdline" "KSPP boot args in current running kernel" "${KSPP_ARGS[@]}"
  show_arg_state "$next_args" "KSPP boot args configured for next boot" "${KSPP_ARGS[@]}"

  echo
  echo "[Kernel boot warnings about managed args]"
  local unknown_lines matched_unknown="" managed
  unknown_lines="$(echo "$klog" | grep -Ei 'Unknown kernel command line parameters|unknown parameter|invalid.*parameter|Malformed early option' || true)"

  for managed in "${MANAGED_ARG_KEYS[@]}"; do
    if echo "$unknown_lines" | grep -Fq "$managed"; then
      matched_unknown+="$(echo "$unknown_lines" | grep -F "$managed")"$'\n'
    fi
  done

  if [[ -n "$matched_unknown" ]]; then
    echo "$matched_unknown"
    failed=1
  else
    echo "OK        no unknown/invalid warning found for managed KSPP args"
  fi

  echo
  echo "[Copy Fail / algif_aead mitigation]"

  if echo "$current_cmdline" | tr ' ' '\n' | grep -qx 'initcall_blacklist=algif_aead_init'; then
    echo "OK        initcall_blacklist=algif_aead_init is present in current cmdline"
  else
    echo "WARN      initcall_blacklist=algif_aead_init is not active in current cmdline"
    echo "          Reboot is required after enable."
    failed=1
  fi

  if has_cmd python3; then
    local afalg_test
    afalg_test="$(
      python3 - <<'PY' 2>&1
import socket

AF_ALG = getattr(socket, "AF_ALG", 38)

try:
    s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    print("WARN: AF_ALG AEAD bind succeeded")
except OSError as e:
    print("OK: AF_ALG AEAD bind failed:", e)
PY
    )"

    echo "$afalg_test"

    if echo "$afalg_test" | grep -q '^WARN:'; then
      failed=1
    fi
  else
    echo "SKIP      python3 not found, cannot test AF_ALG AEAD bind"
  fi

  echo
  echo "[page_alloc.shuffle runtime state]"
  if [[ -r /sys/module/page_alloc/parameters/shuffle ]]; then
    local shuffle
    shuffle="$(cat /sys/module/page_alloc/parameters/shuffle)"

    case "$shuffle" in
      1|Y|y|on|true)
        echo "OK        /sys/module/page_alloc/parameters/shuffle = $shuffle"
        ;;
      *)
        echo "WARN      /sys/module/page_alloc/parameters/shuffle = $shuffle"
        failed=1
        ;;
    esac
  else
    echo "WARN      /sys/module/page_alloc/parameters/shuffle not found"
    echo "          Kernel may lack CONFIG_SHUFFLE_PAGE_ALLOCATOR=y"
    failed=1
  fi

  echo
  echo "[mem auto-init state]"
  local meminit_state
  meminit_state="$(echo "$klog" | grep -i 'mem auto-init:.*heap alloc:' | tail -n1 || true)"

  if [[ -n "$meminit_state" ]]; then
    echo "$meminit_state"

    if echo "$meminit_state" | grep -q 'heap alloc:on'; then
      echo "OK        init_on_alloc appears active"
    else
      echo "WARN      init_on_alloc does not appear active in mem auto-init log"
      failed=1
    fi
  else
    echo "WARN      no detailed mem auto-init line found in kernel log"
    echo "          Try: journalctl -k -b -o cat | grep -i 'mem auto-init'"
    failed=1
  fi

  echo
  echo "[randomize_kstack_offset support]"
  local cfg_tmp
  cfg_tmp="$(mktemp /tmp/kspp.kernel.config.XXXXXX)"

  if read_kernel_config >"$cfg_tmp" 2>/dev/null; then
    if grep -q '^CONFIG_HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET=y' "$cfg_tmp" && \
       grep -q '^CONFIG_RANDOMIZE_KSTACK_OFFSET=y' "$cfg_tmp"; then
      echo "OK        kernel config supports randomize_kstack_offset"
    else
      echo "WARN      kernel config may not support randomize_kstack_offset"
      failed=1
    fi

    echo
    echo "[Kernel config hints]"
    grep -E 'CONFIG_SHUFFLE_PAGE_ALLOCATOR|CONFIG_INIT_ON_ALLOC|CONFIG_HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET|CONFIG_RANDOMIZE_KSTACK_OFFSET|CONFIG_SLUB|CONFIG_BPF_JIT|CONFIG_CRYPTO_USER_API|CONFIG_CRYPTO_USER_API_AEAD' "$cfg_tmp" || true
  else
    echo "WARN      kernel config not readable from /boot/config-$(uname -r) or /proc/config.gz"
    failed=1
  fi

  rm -f "$cfg_tmp"

  echo
  echo "[Interpretation]"
  echo "OK in current cmdline means the bootloader passed the arg for this boot."
  echo "OK in next-boot cmdline means it should persist after future reboots."
  echo "No unknown/invalid kernel warning means the kernel probably accepted it."
  echo "Some early/static params do not expose a runtime boolean."

  echo
  if [[ "$failed" -eq 0 ]]; then
    echo "[+] Status verification looks good."
  else
    echo "[!] Status verification found warnings. Review output above."
  fi

  echo "=============================="
}

usage() {
  cat <<EOF
Usage: $0 {enable|disable|status|help}

Modes:
  enable   Apply server-safe KSPP hardening
  disable  Remove managed KSPP settings
  status   Show status and verification
  help     Show this help

Server-safe profile includes:
  Sysctl:
    kptr_restrict, dmesg_restrict, unprivileged_bpf_disabled,
    randomize_va_space, protected hardlinks/symlinks/fifos/regular,
    bpf_jit_harden, perf_event_paranoid=3, yama.ptrace_scope=2

  Boot args:
    slab_nomerge
    init_on_alloc=1
    page_alloc.shuffle=1
    randomize_kstack_offset=on
    initcall_blacklist=algif_aead_init

Tier 3 (operator opt-in, applied when conf tier == 3):
  init_on_free=1 — stacks on init_on_alloc=1 (~3-8% combined ceiling)

Considered but not shipped (see docs/kernsec.md "Considered but not shipped"):
  kernel.io_uring_disabled=2 — held: probe cost on every DetectHostProfile()
  vsyscall=none              — held: static-Go false-positives in probe + Elf_Verneed parsing needed
  debugfs=off                — held: ManagedBootArgKeys regression for operator-set values

Boot backend support:
  Proxmox boot tool / systemd-boot
  BLS / grubby
  Legacy GRUB / update-grub / grub-mkconfig

Important:
  Boot args require reboot before appearing in /proc/cmdline.
EOF
}

case "$MODE" in
  enable)
    enable
    ;;
  disable)
    disable
    ;;
  status|"")
    status
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac
