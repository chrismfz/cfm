# cfm-php — CFM PHP Zend Extension (seed)

## Status

Idea-stage. No timeline. No implementation plan.

This is a seed doc, not a design. It exists so the architectural intent
is on record and so [`cfm-lsm.md`](./cfm-lsm.md) has somewhere to point
when it explains why dangerous-PHP-function interception is out of
scope for the LSM component. Anything more detailed than the sketch
below is deliberately deferred to a future, dedicated proposal made
when (and if) this project becomes funded work.

## Why this exists

Imunify360 Proactive Defense closes a real gap on Imunify-licensed
hosts: dangerous PHP VM-level calls — `exec`, `system`, `shell_exec`,
`passthru`, `proc_open`, `popen`, `eval`, `assert`, `create_function`,
`preg_replace` with the `/e` modifier, base64+`eval` chains, obfuscated
webshell call graphs — are intercepted before they reach the kernel.
The CFM target stacks include many deployments that do not have that
layer: DirectAdmin hosts without Imunify, stock cPanel hosts without
the Imunify add-on, Proxmox-hosted PHP. On those hosts the PHP VM
layer is wide open.

`cfm-php` is the forward-looking placeholder for a CFM-built Zend
extension that fills the same gap for non-Imunify hosts. It is named
here only so the architectural relationship to `cfm-lsm` is clear:
both components address userspace post-exploit behaviour, but at
different layers, and the LSM design doc would have been
scope-stretched if this idea had lived inside it.

## Reference architecture — how Imunify PD does it

Imunify360 Proactive Defense (mod_imunify360-php / "PHP Immunity") is
**a Zend extension loaded into every PHP process** via `php.ini`. It
is not a kernel mechanism — there are no LSM hooks, no BPF, no syscall
filter involved.

The mechanism is:

1. The Zend extension hooks `zend_execute_ex` and
   `zend_execute_internal` so it sees every PHP function call and
   every `include` / `eval` before the Zend VM dispatches it.
2. It maintains a signature and heuristic database for the dangerous
   call surface, with cloud-side rule updates.
3. On a match it can block the call, sanitise the argument, or just
   log — a per-rule monitor / enforce decision tree, much like CFM's
   own three-mode pattern in `kernsec` and (planned) `cfm-lsm`.

Limitations even of Imunify PD that any successor design needs to
acknowledge up front:

- PD's visibility ends at the PHP→child boundary. Once a PHP process
  spawns a shell, PD does not follow it. (This is the gap
  `CFML-EXEC-001` and `CFML-EXEC-003` in `cfm-lsm` are designed to
  cover.)
- PD must be loaded into every PHP SAPI to be effective. Hosts that
  mix alt-php, system PHP, LSAPI, FPM, and CLI can end up with
  coverage gaps in `php.ini` that translate to coverage gaps in PD.

## High-level scope (sketch only)

These are sketches, not commitments. They exist so a future implementer
has a sane starting point.

- **Target.** PHP 7.4 and newer, including CloudLinux alt-php and
  stock distro PHP.
- **Hook layer.** Zend extension, same hook points as Imunify PD
  (`zend_execute_ex`, `zend_execute_internal`).
- **Interception list.** The standard dangerous-function set: `exec`,
  `system`, `shell_exec`, `passthru`, `proc_open`, `popen`, `eval`,
  `assert`, `create_function`, `preg_replace` with `/e`, and the
  base64+`eval`-style obfuscation patterns.
- **Mode.** Per call class, three modes: `disabled` / `monitor` /
  `enforce`. Mirror CFM's existing pattern.
- **Telemetry.** Emit into the same CFM event pipeline as `cfm-lsm`
  and `webdetector`, so PHP VM-level detections correlate with HTTP
  layer and process layer events on the same host.

## Relationship to cfm-lsm

`cfm-php` and `cfm-lsm` are a two-layer defence-in-depth:

- `cfm-php` catches PHP VM-level call patterns — the dangerous
  function before the OS ever sees it.
- `cfm-lsm` catches the kernel-visible consequences — memfd exec and
  reverse shells once a process has been spawned.

Each layer sees what the other cannot. On Imunify-licensed hosts
`cfm-php` would be inactive or observation-only, deferring to
Imunify PD; on non-Imunify hosts it would carry the PHP-VM layer
itself.

## Out of scope for this doc

Anything beyond the sketch above. No detailed interception list, no
implementation language choice (compiled C extension vs
PHP-via-`auto_prepend_file`), no licensing commitments, no detection
rule format, no `cfm php` CLI design, no packaging story. Those
decisions land in a future, dedicated proposal when `cfm-php`
becomes a real project.

## Open questions

A short list of things to figure out when this becomes real work:

1. **PHP 8.x JIT interaction with Zend extension hooks.** Imunify PD
   has had churn here historically; any successor will too.
2. **Distribution.** Shipped as a separate `cfm-php-ext` package, or
   bundled with the CFM agent? Affects rollout and update cadence.
3. **License and update channel.** CFM is open; the rule corpus
   could be too, but a cloud update channel implies infrastructure
   cost.
4. **Interaction with `mod_imunify360-php` when both are present.**
   Avoid double-blocking and double-logging. The right default on
   Imunify hosts is probably `monitor` for `cfm-php`, with PD
   continuing to do the enforcement.

## References

- [`cfm-lsm.md`](./cfm-lsm.md) — sibling component, the kernel-LSM
  layer this PHP-layer component would complement.
- PHP internals documentation on Zend extensions
  (`zend_execute_ex`, `zend_execute_internal`,
  `zend_compile_string` hook points).
- Imunify360 Proactive Defense public documentation, as prior art
  for the hook layer and the interception list.
