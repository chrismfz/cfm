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

Two solves in the same window ran **59.4 s** (Chrome on a Nova residential line)
and **26.3 s** (Firefox Android). The p90 above is 11.4 s, so these are the tail
rather than the norm — but difficulty 16 costs a weak phone or an old desktop
close to a minute, and that is a real user sitting in front of a spinner. If §2
(per-vhost difficulty) ever lands, this tail is the argument for lowering it,
not raising it.

**`challenge_cookie_discard` in its first three hours of production**: 20+
alerts, each address doing 20–60 solves in a 2–5 minute burst and then falling
silent while the next takes over. Mostly US residential ISPs (Frontier, Charter,
AT&T, Comcast, Taylor Telephone) — but **not exclusively**: the busiest single
exit in the 16:17 window was `109.166.36.188`, AS212238 Datacamp in Japan, a
datacenter. An earlier note in this file said "every one a US residential ISP";
that was drawn from one window and is corrected here. The pool mixes residential
and datacenter exits, which matters because an ASN-based allowlist would not
have covered it either way. That

**And the same night showed the shape `cookiediscard` structurally cannot see —
which is why `solver_farm` earns its keep.** Between 22:35:45 and 22:38:05, ~31
addresses from AS398781 (plus one from a Twitter range carrying the identical
UA) each solved **exactly once** on `www.mathematica.gr`, every one on a
different `viewtopic.php`, all `X11; Linux x86_64 … Chrome/149`, all
`tls_fp=95070673`, across ~31 distinct /24s. One solve per exit defeats a
per-address threshold by construction — `MIN_SOLVES = 8` can never fire — while
31 subnets in 140 s is exactly what the per-vhost subnet-spread rule is for. The
two detectors are mirror images on purpose (`cookiediscard` keys on the address,
`solverfarm` on the vhost); this capture is the evidence that neither alone is
enough.

**`solver_farm` did not fire on it, and the reason is `WINDOW`, not the
thresholds.** The shipped default is `WINDOW = "60s"`; an operator who lowers
`MIN_SUBNETS`/`MIN_SOLVES` and leaves the window alone inherits it. Sliding a
60 s window over the swarm's real timestamps peaks at **18 solves / 18 subnets**
— the subnet threshold (16) was met and the solve threshold (20) missed **by
two**. The attack is not below the thresholds; it is wider than the window.

Swept against the 23-hour production corpus (111,537 solves, 79 vhosts), one
evaluation per `EVERY`=30 s:

| WINDOW | 16/20 catches the swarm | vhosts that ever fire |
|---|---|---|
| 60 s | no | `electroexpert.gr`, `www.mathematica.gr` |
| **120 s** | **yes** (28 solves / 28 subnets) | the same two |
| 300 s | yes | those two + `www.vitolighting.com` |

The false-positive column is the point: across **79 vhosts** only three ever
fire anywhere in the grid, and all three are independently known to be under
attack. Widening to 120 s buys the detection without touching the thresholds and
without pulling in one new vhost. 300 s adds `www.vitolighting.com`, itself under
the `chrome_impossible_patch` flood — more coverage, not a false positive. The
caveat worth keeping: the corpus is 23 hours during which three vhosts were
attacked, so a legitimately viral vhost on a quiet day is not represented in it.

**`cookiediscard`'s `MIN_SOLVES` has no headroom left to give, and that is the
useful finding.** Peak solves per address in any 10-minute window over the same
corpus: **97,484 of 97,556 addresses (99.93%) solved exactly once**, 72 ever
reached 2, 9 reached 4, and only 4 reached 5 or more. Every threshold from **5
to 12 selects the identical four addresses.** The shipped 8 sits in the middle
of an empty canyon between 4 and the farm's 20–60, so lowering it to 6 changes
nothing whatsoever, and lowering it to 4 buys five addresses at the price of
sitting on the edge of the human distribution. Leave it alone; if this detector
ever needs to be more aggressive the lever is `WINDOW`, not `MIN_SOLVES`.
serial shape — one exit at a time rather than many in parallel — is the thing
the detector was built to see, and it is also why a per-vhost concurrency rule
misses it entirely. No false positive has appeared: a human who clears cookies
does it a handful of times an hour, not fifty times in three minutes, and the
`MIN_SOLVES = 8` threshold sits above the natural gap measured at 5 in the
offline corpus. The detector still ships alert-only (`BLOCK` unset); this is the
evidence that would justify `BLOCK = "dryrun"` and then a TTL block, in that
order.

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

**GREASE is stripped before hashing.** RFC 8701 stacks — Chrome above all —
insert a code point chosen at random *per connection* into the cipher list and
the supported_groups, and nginx renders values OpenSSL does not recognise as hex,
so a GREASE value lands in `$ssl_ciphers`/`$ssl_curves` as `0x?a?a` and changes
on every connection. Left in, one real client would produce up to 16×16 distinct
ids: the grouping would be gone and the first_seen dictionary would fill with
noise until it hit its bound. This is why JA4 strips GREASE and why the original
JA3 was criticised for not doing so. `internal/tlsfp` drops the sixteen GREASE
code points from both lists before hashing, keeps `Raw` verbatim as the evidence,
preserves the offered order (which is stable per stack and part of what makes the
fingerprint discriminating), and records `grease=true|false` on the first_seen
line — so whether GREASE survives OpenSSL's ClientHello parsing on this edge at
all comes out of the data instead of an assumption.

**Confirmed in production on first deploy (2026-07-28), within a minute of
start.** Two of the open questions above are answered by the data, not by
argument:

- **GREASE does survive into these variables**, so the stripping is load-bearing
  rather than defensive. The first fingerprint recorded was
  `grease=true` with `0xfafa` leading the cipher list and `0xdada` leading the
  curves. Reconstructing the hash over that exact tuple: unstripped, this single
  client would have produced **256 distinct ids** (16 GREASE values × 2
  positions), and the 5000-entry dictionary would have been exhausted by about
  **19 real clients**. Stripped, it is one id — `95070673`.
- **A resumed session still carries the full cipher and curve lists.** That first
  record ended in `|r` and had all fifteen ciphers and four groups present, so
  resumption does not thin the fingerprint and field 7 does not need to gate
  anything.

**First 23 minutes of production data: three distinct fingerprints, and one of
them is a lie.** All three ids reproduce exactly from their logged tuples, so
the implementation is verified end to end.

| id | grease | what carries it |
|---|---|---|
| `95070673` | true | almost everything — Chrome 40 through 150, Edge, Samsung Browser, on Windows / macOS / Android / Linux, bots and real visitors alike |
| `42d907e9` | true | iPhone Safari (21 ciphers incl. 3DES, `secp521r1`) |
| `6edad59b` | **false** | a single client claiming `Chrome/150.0.0.0` |

Two lessons, one disappointing and one very much not.

**The resolution is low.** One id covers the entire Chromium family across a
decade of claimed versions, because the offered cipher list and curve list have
been frozen across Chromium releases for years — which is precisely why JA3/JA4
hash the *extension list and its order*, the one thing nginx cannot report. So
this will never pin "which Chrome version"; do not build a rule that assumes it
can. What it does resolve is **TLS-stack generation**, and that turns out to be
enough: every `chrome_impossible_patch` bot in the capture presented
`95070673` — a modern Chromium ClientHello, TLS 1.3, `0x11ec` and all — while
claiming `Chrome/40`–`Chrome/60` on macOS 10_12. A real Chrome 40 predates all
three by years. The UA rules caught those independently, so the fingerprint is
corroboration there rather than a new detection.

**A `grease=false` fingerprint appeared and looked like a catch.** `6edad59b`
carries a cipher list byte-for-byte identical to Chrome's *plus*
`TLS_EMPTY_RENEGOTIATION_INFO_SCSV`, with no GREASE and no `0x11ec`, on a client
claiming `Chrome/150.0.0.0`. A real Chrome sends GREASE on every connection by
construction, so the reading was: a non-Chromium stack wearing Chrome's cipher
list, invisible to `uaplausible` because the UA is well-formed.

**Three hours of data said otherwise, and this is the correction that matters
most.** `6edad59b` went on to appear on three Greek residential ISP addresses
(Nova, Vodafone) doing `search.php?author_id=`, `memberlist.php` and a webmail
logout, under two different Chrome majors. Those are logged-in humans, not a
scraper. The overwhelmingly likely explanation is a **TLS-terminating middlebox**
— an antivirus or security suite intercepting TLS on the client machine — which
is precisely the legitimate `grease=false` producer this section had already
flagged as the reason not to ship the rule. `19877aeb` shows the same shape:
first seen on a `Dataprovider.com` crawler, then on ordinary Greek residential
users.

So: **`grease=false` on its own is not a bot signal.** Anyone tempted to write
that rule should read this paragraph first. It was one observation, it looked
clean, and it was wrong.

**What still looks right is `c2e09593`**, and it is a different shape: no GREASE,
no `0x11ec`, **empty ALPN with `HTTP/1.1`**, and every sighting on a datacenter
ASN (Tencent Cloud, Alibaba Cloud — US, Germany, Singapore, Hong Kong) under
Chrome majors scattered across 104, 106, 109, 112, 120, 124, 131. A single TLS
stack claiming seven Chrome versions from cloud ranges is a scraper library, not
a browser. The candidate rule is therefore not `grease=false` alone but a
**conjunction** — no GREASE *and* one of {no ALPN/HTTP-1.1-only, datacenter ASN,
UA-version spread across one fingerprint}. Measure each leg separately before
combining them.

**The resolution is also better than the first 23 minutes suggested.** Ten
distinct fingerprints appeared, and they separate cleanly *between* engine
families even though they cannot separate *within* Chromium: Firefox
(`00b68027`, three Gecko versions, Greek ISPs), Firefox on Android
(`2696c4f4`), Safari and CriOS on Apple platforms (`42d907e9`), the iPhone
Google-app webview (`2bfd7bbb`, distinct from Safari), and Meta's crawler
(`6821efa4`). Engine-family attribution is real; version attribution is not.

**The 512-byte field bound was too small, and production found it, not a
test.** Meta's crawler (`6821efa4`) offers the full OpenSSL-style suite list;
its cipher field measured exactly 512 characters and ended
`...:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-S` — cut mid-name. The comment
above the bound said it "sits above anything a real stack sends", which was
simply wrong. Fixed on 2026-07-28: `MAX_FIELD` 1024, `MAX_TOTAL` 2048 (which
must stay `<= tlsfp.maxHeader`), the cut now lands on a `:` boundary, and a cut
field ends in a `TRUNC` token. The token is deliberately part of the hashed
value — otherwise a truncated list would hash equal to a client that genuinely
offered exactly that shorter prefix, and nothing in the log would separate them.
`Print.Truncated` and `trunc=` on the `first_seen` line exist so a truncated id
is never read as a whole one: it is stable per client, but two clients whose
offers agree up to the bound collapse onto it.

**Two ids can be one browser, and the fingerprint does not know it.** Two
findings from the same three hours, both worth having before anyone writes a
"new id ⇒ suspicious" rule:

- `0ed5b601` and `95070673` are both `Chrome/150.0.0.0` on Windows and, after
  GREASE stripping, offer **the same fifteen suites and the same four groups** —
  in a different order, with ChaCha20 promoted to the front of each tier.
  Reordering by whether the platform has AES hardware acceleration is the
  obvious reading, and the corroboration is in the same line: that solve took
  **59.4 seconds**, the slowest in the window, i.e. a weak CPU. Obvious is not
  confirmed — pair the ordering against device class across a week before
  claiming it.
- `00b68027` and `93ba418f` are both `Firefox/153.0` on Windows with **identical
  curve lists**, differing by a single trailing `DES-CBC3-SHA`. One browser
  version, two ids. The cause is not established and must not be guessed.

So an id is a TLS-offer shape, not a client identity. A rule may say "this shape
is a scraper"; it may never say "this shape is new, therefore suspicious".

**Empty ALPN with HTTP/1.1 is not a bot signal either.** `c41a0f3f` is
Google-Read-Aloud from AS15169 — empty ALPN, `HTTP/1.1`, and GREASE present. It
would trip the ALPN leg of the `c2e09593` conjunction on its own. That is what a
conjunction is for: `c2e09593` is no-GREASE *and* empty-ALPN *and* datacenter
*and* UA-version spread. Each leg alone has now been observed on legitimate
traffic — GREASE on Greek residential users behind a middlebox, ALPN on a Google
crawler. Do not ship any single leg.

**A full night confirmed `c2e09593` and produced a better candidate.** Thirteen
sightings across the 2026-07-28 evening capture, and the ASN column has no
exceptions at all: Tencent (US, Germany, Singapore, Hong Kong), Alibaba
(Germany, Singapore, Hong Kong, Japan), Byteplus (Singapore, Hong Kong).
**Zero residential.** The UA spread widened to eight Chrome majors — 103, 104,
107, 116, 117, 120, 131, 133 — on one TLS stack. Its distinguishing shape is
also structural rather than an absence: the three TLS 1.3 suites come **last**,
after the ECDHE block, which no browser print in this capture does.

**The cleaner marker is a positive one: DHE-RSA suites and X448.** Measured
across the capture rather than recalled:

| id | DHE-RSA | X448 | TLS1.3 suites last | carried by |
|---|---|---|---|---|
| `95070673` | no | no | no | Chrome/145 — the majority print |
| `00b68027` | no | no | no | Firefox 153 — real browser |
| `c2e09593` | no | no | **yes** | datacenter only, 8 Chrome majors |
| `6821efa4` | **yes** | **yes** | no | `meta-externalagent` — a *declared* crawler |
| `9ca6ad0b` | **yes** | **yes** | no | claims plain `Chrome/139`, from AWS |

`6821efa4` is the control: a bot that says it is a bot, carrying DHE-RSA and
X448. `9ca6ad0b` has the same TLS shape and a UA with no bot token at all. That
is the lie the fingerprint is for — and unlike `grease=false` it is a *positive*
marker (offering suites and a group), not a missing one, so a TLS-terminating
middlebox does not produce it by omission. **Still a hypothesis**: what is
established is that in this corpus no browser print carries DHE-RSA or X448 and
two non-browser prints carry both. Confirm against a week before writing a rule,
and expect corporate proxies to be the false-positive class to measure.

**`19877aeb` is the counter-example that keeps the caution honest.** In one
night it appeared on `ClaudeBot/1.0` (AWS), on Greek residential Nova/OTEnet
users, and on Saudi Telecom. One id, a declared crawler and ordinary humans. An
id is a TLS-offer shape; it is not a client, and it is not an intent.

**Every `tls_fp=-` line in the capture is a panel scope** — `scope=panel:2083`
or `scope=panel:2096`, without exception. That is the expected result and worth
recording so nobody hunts a bug: the cPanel/WHM listeners terminate TLS
themselves and never traverse the edge's `/__cfm_verify` location, so nothing
stamps `X-CFM-TLS` on them. A `-` on a **vhost** scope would be a real signal
(edge misconfiguration, or a request reaching the challenge server directly);
a `-` on `panel:*` is structural. Coverage of the fingerprint is therefore
"everything through the edge", not "everything", and any coverage metric must
exclude panel scopes or it will read as a permanent ~x% gap.

Still open, and still to be answered from the log rather than assumed:

- how much of the fleet reaches the edge through a TLS-terminating middlebox
  (corporate inspection, antivirus proxy, VPN client, CDN), which produces a
  legitimate fingerprint↔UA mismatch;
- the id's stability across an edge OpenSSL upgrade, since it hashes names;
- **what `0x11ec` is.** It appears as the first non-GREASE group, ahead of
  X25519, on both the Chromium fingerprint and the Safari one. A post-quantum
  hybrid group is the obvious reading; it entered browsers at known versions, so
  its presence or absence dates the stack. **Confirm it against the corpus
  before building any rule on it** — pair the group against the UAs that carry
  it across a week of solves. Do not take the identification from memory,
  including this note's.

## 7. What this cannot do without an edge module

Worth stating plainly so nobody re-derives it: the ceiling on the current
approach is that nginx reports the *contents* of the cipher and curve lists but
not the **extension list or its order**, which is what actually separates one
Chromium build from another and what a real JA3/JA4 hashes. Every Chromium-family
browser therefore lands on one id. Raising the resolution means a module or a
patched edge, and that is a much bigger commitment than this was — take it only
if a week of `grease`/group data proves the coarse signal insufficient.

**Why it is worth doing anyway, even against uTLS.** A farm can mimic any
fingerprint with uTLS — but not while running real headless Chrome, which is what
`solve_ms` says it runs today (§5). Moving to uTLS costs it the browser and forces
a native PoW solve, which collapses `solve_ms` toward zero — already measured. The
two signals box the adversary in from opposite sides; neither does that alone.

## 8. Level-2 humanity gate (proposed — design, not built)

This section records a design worked out in discussion, so the reasoning is not
lost. **Nothing here is built or measured yet**; the numbers to justify each
threshold do not exist until the evidence signal in §8.2 has run. Treat every
"human vs farm" claim below as a hypothesis to confirm against real logs, the
same discipline §5/§6 impose.

### 8.1 The reframing: proof-of-work cannot separate two real browsers

Everything above §5 measures one thing repeatedly: today's farm runs **real
headless Chrome** (`solve_ms` median 6.55 s, nothing under 0.3 s — §5). PoW
proves "a CPU did work"; the farm has CPUs, and Playwright/Puppeteer *is* a
browser. So harder PoW (§1), memory-hard PoW (§3), and Chrome-build checks are
all taxes the honest user pays while the farm shrugs — because none of them
asks the one question that actually divides the populations: *is there a human
here?*

The escape is a **proof-of-humanity / proof-of-interaction** step, and its
whole viability rests on being **escalation-gated** — off by default, on only
when a vhost is demonstrably under attack. Always-on humanity friction destroys
conversion and accessibility for everyone; under-attack friction is paid by
real users only in the rare window when the alternative is the site drowning in
farm traffic. This is the `harden` actuator §4 reserved, with one correction:
level-2 changes the *kind* of proof, not the PoW *difficulty* (§4's original
`harden = raise difficulty` does not work against a browser farm, per §1).

### 8.2 First step — passive interaction-entropy as evidence (zero UX, no gate)

The current interstitial (`challenge_server.go`, the browser solver at the
`solvePow()` / auto-`fetch("/__cfm_verify")` block) is fully automatic: it
solves PoW and submits with **zero user interaction**. That ~1.3 s PoW window
is a free place to *observe* interaction without adding any UX: attach passive
listeners (`pointermove` / `scroll` / `touchstart` / `keydown` + timing) and
submit a **compact, NON-PII summary** — event count, distinct event types,
active-ms, a coarse entropy/timing bucket — in an extra header on the verify
POST. Never raw pointer paths (volume + PII); a few scalars, the way `tls_fp`
is 8 chars and `solve_ms` is one number.

It lands exactly where `solve_ms` and `tls_fp` already land: on the
`challenge_solved` history event (`engine.go` payload) and on the
`result=solved` line in `cfm.challenges.log`. A third evidence signal of the
same class — **collected on every solve, carried for attribution, never a
gate** by itself (a single solve's score is attacker-controllable; Playwright
can synthesise events).

Targeting note: this signal only exists in real-browser mode. A non-JS client
never reaches the verify POST (it fails the existing JS+cookie+PoW gate), so
interaction-entropy adds nothing against non-JS bots — it aims squarely at the
JS-executing headless-browser farm, which is the threat.

### 8.3 How the evidence is used — a ladder, thresholds last

1. **Attribution on existing alerts (immediate, zero risk).** When
   `solver_farm` / `cookiediscard` fire, attach the interaction distribution of
   the flagged cluster, exactly as UA/`tls_fp` breakdowns already ride on the
   alert. Makes the finding actionable; changes no decision; needs no threshold.
2. **Aggregate detector signal (the payoff, after burn-in).** Per-solve is
   spoofable, so — like `solver_farm` — key on the **population over a
   vhost/window**: the fraction of solves with human-plausible interaction
   *collapsing* from its baseline. Matching a human *distribution* across
   thousands of solves is far harder than faking one gesture. New leg inside
   `solver_farm`, or its own detector.
3. **Correlation — the §7 boxing-in, third wall.** Cross interaction with
   `solve_ms` and `tls_fp`: fast + coherent-TLS + zero-interaction is a
   different animal from slow + middlebox-TLS + rich-interaction. The
   conjunction forces the farm to *simultaneously* run a real browser (high
   `solve_ms`, coherent TLS) **and** reproduce a human interaction
   distribution.

### 8.4 The gate — two decisions, not one

When "something is wrong" is established, it drives level-2. Keep two decisions
distinct — the split is the entire false-positive story:

- **Trigger (vhost-level, aggregate): "is this vhost under attack now?"**
  Decided on the population signal (§8.3 leg 2, alongside `solve_ms` collapse /
  `tls_fp` cluster / subnet spread). Turns level-2 **mode** on for the vhost.
  Reuses the existing `vhostUnderAttack` auto on/off machinery with its
  hysteresis + holddown, so it does not flap and **auto-exits** when the farm
  leaves — a vhost must never stay stuck in puzzle-mode after the attack ends.
- **Per-request soft-gate: "who, inside that mode, actually sees the puzzle?"**
  Never everyone — that is the FP disaster. High-confidence-human requests
  still pass with the light challenge; only the suspicious stream gets the
  puzzle.

**The light challenge is the probe.** Interaction-entropy is collected *during*
the light PoW, so a brand-new request has no score yet — which is a feature,
not a chicken-and-egg problem. The flow is:

> light PoW (collects interaction) → interaction bar not met → **then** puzzle
> before clearance is minted.

The light step becomes the detector, and failing its interaction bar escalates
to the puzzle **within the same flow**, keyed on a signal the client just
produced. (Pre-JS signals — `tls_fp` at handshake, UA plausibility, ASN — can
pre-filter, but interaction is post-solve and fits naturally as the second
rung.)

### 8.5 Honest reality check

A puzzle is **not unbreakable**: a farm can pipe it to a human-solver service
(2captcha and similar). The win is **economic** — it converts the farm's cost
from "free PoW" to "paid human solve per request", and only for the duration of
the attack. At ~100k solves/day that is a punishing bill for the attacker,
while a real visitor pays it only in the rare under-attack window. "Would it
work" honestly means *it moves the cost curve*, not *it builds a wall*. Design
and message it that way.

### 8.6 Non-negotiables for level-2

- **Hard operator bypass + allowlist + fail-open.** A humanity gate *will* lock
  out screen readers, keyboard-only clients, API/cron clients, `/.well-known`
  ACME/DCV validators (remember the two carve-outs), and some mobile webviews.
  Without an allowlist and a fail-open story, level-2 drops legitimate traffic
  worse than the farm does.
- **Accessibility.** Any visual/interaction puzzle needs an accessible path
  (audio, or a non-visual alternative), or it is an outage for a class of real
  users the moment it triggers.
- **Auto-exit with holddown**, driven by the aggregate signal cooling — and
  note this leans on the manual-vs-auto vhost-challenge lifecycle: the auto
  cool-down must not stomp an operator's manual challenge, and vice versa (the
  class of bug fixed in `manualChallengeCoversClear`). Level-2 escalation must
  honour the same rule.
- **Config surface.** Extends `solverfarm.Action` (`observe` / `logonly` today;
  `harden` / `throttle` reserved — §4). Level-2 is a new action tier; grow the
  accepted vocabulary deliberately, since `detectors.conf` is a packaged
  conffile and every new value costs an upgrade prompt.

### 8.7 Sequencing

Evidence-only → measure human-vs-farm distributions on real logs → aggregate
detector → escalation trigger → per-request soft-gate → puzzle. **No threshold
before its burn-in** — the same path `solve_ms` and `tls_fp` walked. Step 1
(attribution) ships without any of the later machinery and is the correct first
commit.

## 9. Related

- `internal/webdetector/pow.go` — difficulty, TTL, token format
- `internal/webdetector/challenge_server.go` — issue site and the browser solver
- `internal/detectors/solverfarm/` — the farm detector and `Action`
- `internal/detectors/cookiediscard/` — the re-solver detector
- `internal/tlsfp/` + `configs/lua/cfm_tlsfp.lua` — the TLS fingerprint signal
- `docs/DETECTORS.md` — `challenge_solver_farm` operator documentation
- `internal/webdetector/manual_challenge.go` — manual vhost challenge lifecycle
  (`manualChallengeCovering` / `manualChallengeCoversClear`), the auto-exit
  rule level-2 must honour (§8.6)
