# Roadmap — challenge engine (PoW difficulty, solver, enforcement)

Status: **open**. Written 2026-07-28, from measurements taken against a live
distributed solver farm on a production edge.

Bots now complete the whole cookie + JS + PoW flow correctly. "Solved" is no
longer evidence of a human, so the challenge engine needs work in two separate
directions: making the proof cost something again, and acting on the farms the
new `challenge_solver_farm` detector finds. This file records what was measured
so the next person does not have to re-derive it — and so the obvious move
(just raise the difficulty) is not made without the numbers.

---

## 1. Do NOT simply raise `defaultPowDifficulty`

`defaultPowDifficulty = 16` in `internal/webdetector/pow.go` looks low, and
raising it is the intuitive fix. It is a trap in the current design.

Measured (headless Chromium vs Go, identical message shape, same machine):

| solver | rate |
|---|---|
| the shipped browser solver (`await crypto.subtle.digest` per candidate) | **48.8 kH/s** |
| the same loop without its `setTimeout` yield | 51.2 kH/s |
| synchronous JS SHA-256, tight loop | 192.6 kH/s |
| naive native Go, 1 core | **4.49 MH/s** |
| naive native Go, 4 cores | 15.96 MH/s |

That is a **~92x handicap on the honest client before any tuning** — and the
native side is unoptimised: the PoW prefix is 173 bytes, i.e. two full SHA-256
blocks that a real solver precomputes as a midstate, plus SIMD multi-lane. A
tuned native solver is realistically 500–1000x the browser.

Expected time-to-solve:

| difficulty | browser (shipped) | native 1 core | native 4 cores |
|---|---|---|---|
| 16 (today) | 1.3 s | 15 ms | 4 ms |
| 18 | 5.4 s | 58 ms | 16 ms |
| 20 | 21.5 s | 233 ms | 66 ms |
| 22 | 1.4 min | 933 ms | 263 ms |

Raising difficulty scales both sides equally, so it never separates them — it
only moves the honest user's cost. With `defaultPowTTL = 2 * time.Minute` and
solve time exponentially distributed, difficulty 20 already loses roughly a
third of mobile clients to TTL expiry (an infinite challenge loop), and 22 loses
about a quarter of *desktop* clients.

**Prerequisite: fix the solver first.** One `await crypto.subtle.digest()` per
candidate pays promise/microtask overhead on every hash. A synchronous SHA-256
in a Web Worker is already ~4x measured; WASM should approach native. With that,
difficulty can rise by several bits at unchanged user-visible cost, and the
asymmetry drops from ~1000x to single digits.

## 2. Then: per-vhost difficulty

`PowConfig` (`internal/webdetector/pow.go`) is built by `defaultPowConfig()` and
is process-wide. Its own comment says "έτοιμο για επέκταση (π.χ. ανά vhost)" but
nothing wires it. The issue site (`challenge_server.go`, the `cfg.Difficulty`
call into `issuePowChallenge`) already has the forwarded host available, so the
plumbing is short once there is somewhere to read a per-vhost value from.

This is the actuator that actually fits a solver farm: a farm solving ~100k
times pays proportionally, a real visitor pays once. It is the intended
implementation behind `ACTION = harden` (not yet a valid value — see §4).

## 3. Do not reach for memory-hard PoW

Argon2id was measured as an alternative and rejected. The problem is that a
memory-hard PoW is expensive to **verify**, not just to solve — the server
redoes the whole computation on every submission:

| parameters | server cost per verify | under flood (4 cores) |
|---|---|---|
| today (SHA-256) | ~0.0002 ms | effectively unbounded |
| Argon2id 8 MiB | 6.4 ms | 434/s |
| Argon2id 64 MiB | 115 ms | **13.4/s** |

An attacker fetches challenge pages cheaply, obtains valid HMAC tokens, and
submits garbage solutions — each costing a full Argon2 computation before it can
be rejected. That is an amplification DoS against the daemon that does not exist
today. It also needs a WASM blob shipped in the challenge page and risks OOM on
low-end mobile.

More fundamentally it defends against the wrong adversary: memory-hardness
resists GPU/ASIC solvers, and the farms observed here run *real headless
Chrome at browser speed* (see §5). Revisit only if `solve_ms` telemetry starts
showing clusters solving far faster than a browser can.

## 4. Enforcement actuators for `challenge_solver_farm`

`ACTION` in `[challenge_solver_farm]` currently accepts `observe` (default) and
`logonly`. `deny` and `block` are reserved and refuse to activate; the reasoning
is in the config comments and in `solverfarm.Action`. Summary:

- **`block` does not work here** — 1.07 solves per address means the address is
  gone before the alert fires, and the residential pool means the ban lands on a
  real visitor.
- **`deny` has no safe subject** — vhost-wide 403 takes the customer's site
  down; the narrow form is a UA-cluster traffic rule, which a farm evades by
  randomising a header.
- **`harden`** (raise the vhost's PoW difficulty while flagged) is the one worth
  building, and it is blocked on §1 and §2.
- **`throttle`** (rate-limit challenge *issuance* for a flagged vhost) is the
  fallback: independent of IP and UA so it cannot be evaded, but it delays
  legitimate visitors during an attack.

## 5. What the telemetry already says

`solve_ms` (real client-side solve latency, recorded since 2026-07-28) is the
signal that tells us whether §1/§3 are needed. Baseline from 105,307 paired
solves on the production capture:

| population | p10 | median | p90 | under 0.3 s |
|---|---|---|---|---|
| all solves | 3.13 s | 6.23 s | 11.39 s | **0.0%** |
| the farm (Chrome/118 cluster) | 3.59 s | 6.55 s | 11.63 s | 0.0% |
| a legitimate Chrome/145 population | 2.50 s | 3.03 s | 4.34 s | 0.1% |

Note the farm is **slower** than legitimate traffic, and nothing solved under
0.3 s. These are genuine browsers, not native solvers — which is why a
"suspiciously fast solve" rule catches nothing today, and why §3 is not urgent.
If that distribution ever collapses toward zero for some cluster, revisit.

## 6. TLS fingerprint ↔ UA coherence (log-first since 2026-07-28)

Every other signal on a solve is written by the client: the User-Agent, the
cookies, the PoW solution, the timing. The TLS handshake is written by its TLS
stack before a byte of HTTP is sent. A client claiming `Chrome/118` whose
handshake does not look like Chrome's is lying in a way no header edit can fix —
and the observed farm sends one exact User-Agent for **100%** of its solves, so a
coherence check would still hold if it randomised that tomorrow.

**What ships today.** `configs/lua/cfm_tlsfp.lua` stamps `X-CFM-TLS` on the
request the edge forwards to `/__cfm_verify`; `internal/tlsfp` parses it and
reduces it to an 8-character id. Wire format is positional and versioned:

```
1|$ssl_protocol|$ssl_ciphers|$ssl_curves|$ssl_alpn_protocol|$server_protocol|$ssl_session_reused
```

This is a poor-man's JA3, not a JA4 — nginx exposes the offered cipher suites and
curves plus the negotiated protocol and ALPN, but not the extension list or its
order. A real JA4 needs a module or a patched edge. This needs neither, which is
why it goes first.

**Where it lands.** `tls_fp=<id>` on every `result=solved` line in
`cfm.challenges.log`, `payload.tls_fp` on the `challenge_solved` history event,
and one `tls_fp=<id> first_seen ua=… tls=…` dictionary line per distinct
fingerprint (the tuple is a few hundred bytes; writing it per solve would add
tens of MB a day). So `grep tls_fp=<id>` finds both the definition and every
solve that used it.

**Explicitly not a rule yet.** The mapping from fingerprint to browser identity
must be derived from captured traffic, not written from memory — the same
discipline `internal/uaplausible` documents, and here it is stronger: the cipher
names come from the edge's OpenSSL build, so a table lifted from another fleet is
not even comparable. Give it a week of log, then build the table from solves
whose UA is corroborated by other means.

Three things to check when reading that data rather than assume:

- whether `$ssl_ciphers`/`$ssl_curves` stay populated on **resumed** sessions
  (that is what field 7 is for — `r` means resumed, `.` means not);
- how much of the fleet reaches the edge through a TLS-terminating middlebox
  (corporate inspection, antivirus proxy, VPN client, CDN), which produces a
  legitimate fingerprint↔UA mismatch;
- the id's stability across an edge OpenSSL upgrade, since it hashes names.

**Why it is worth doing anyway, even against uTLS.** A farm can mimic any
fingerprint with uTLS — but not while running real headless Chrome, which is what
`solve_ms` says it runs today (§5). Moving to uTLS costs it the browser and forces
a native PoW solve, which collapses `solve_ms` toward zero — already measured. The
two signals box the adversary in from opposite sides; neither does that alone.

## 7. Related

- `internal/webdetector/pow.go` — difficulty, TTL, token format
- `internal/webdetector/challenge_server.go` — issue site and the browser solver
- `internal/detectors/solverfarm/` — the farm detector and `Action`
- `internal/detectors/cookiediscard/` — the re-solver detector
- `internal/tlsfp/` + `configs/lua/cfm_tlsfp.lua` — the TLS fingerprint signal
- `docs/DETECTORS.md` — `challenge_solver_farm` operator documentation
