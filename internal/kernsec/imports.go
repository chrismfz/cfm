package kernsec

// Force-import internal/sysctl for its package init() side effect:
// registers the cfm-sysctl-tweaks catalog with managedsysctl.Default()
// so kernsec.Resolve can mark KSEC-SCT-net.* rules as
// ManagedExternally (audit-only) rather than try to write keys
// sys_tweaks owns.
//
// In the production cfm binary, cmd/cfm/main.go already imports
// internal/sysctl so the init runs unconditionally. This blank
// import makes the same invariant hold for the kernsec test binary
// (`go test ./internal/kernsec/...`) and any future caller that
// imports kernsec without sysctl. Without it, the registry is empty
// in test environments and the cross-component check silently no-ops.
import _ "cfm/internal/sysctl"
