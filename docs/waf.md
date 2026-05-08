# CFM WAF and Challenge-Clearance Boundary

## Purpose

This document defines the intended security boundary between CFM challenge clearance and WAF inspection, records current observed issues in the Lua enforcement path, and proposes an architecture for shared-hosting deployments where legitimate administrative traffic and exploit traffic frequently overlap.

## Security principle

Challenge is a bot/human gate.

WAF is payload inspection.

They should complement each other, not replace each other.

## Intended security boundary

`cfm_clearance` is evidence that a browser or client completed a CFM challenge for the relevant scope. It is a gate signal, not a payload-safety signal.

A valid clearance proves only that the client passed the configured browser/client challenge flow. It must not be treated as proof that the current request payload, URL, headers, cookies, upload body, CMS action, plugin action, upload filename, or file content is safe. Clearance should therefore skip repeated challenge gates, but it should not skip exploit detection or WAF inspection for requests that are bound for origin.

For every origin-bound request after clearance, exploit and WAF inspection should continue. The origin allow decision should be made only after the request has passed mandatory security checks, including WAF evaluation and any configured block/log/challenge policy conversion.

## Threat model

CFM commonly runs in front of shared-hosting servers with a wide attack surface:

- outdated WordPress, Joomla, and Drupal installations;
- vulnerable plugins and themes;
- compromised webmaster/admin accounts;
- public upload handlers;
- admin AJAX and REST endpoints;
- XML-RPC endpoints;
- backup and migration plugins;
- abandoned file managers;
- plugin/theme editors;
- webshell/backdoor upload attempts;
- malware droppers and command-execution payloads.

A challenge is useful against bots, scanners, and unauthenticated automated abuse. It is not sufficient protection against:

- authenticated attackers;
- compromised legitimate browsers;
- attackers exploiting real application flaws;
- malicious payloads submitted after challenge clearance.

Therefore, WAF inspection should continue after challenge clearance.

### Shared-hosting considerations

Shared hosting makes post-clearance WAF inspection especially important because authenticated, browser-capable, or challenge-capable clients may still generate dangerous origin-bound requests.

Relevant risks include:

- **Outdated CMS and plugins:** WordPress, Joomla, Drupal, and similar application stacks often contain unpatched themes, plugins, modules, or extensions. Attackers commonly exploit known vulnerabilities through normal HTTP endpoints.
- **Compromised admin accounts:** A valid human browser session can belong to an attacker using stolen credentials. Passing a browser challenge does not prove the admin action is legitimate.
- **Malicious upload endpoints:** CMS media libraries, plugin importers, backup restore functions, and custom upload handlers may accept files or multipart payloads that place executable content on disk.
- **Webshell/backdoor placement:** Attackers frequently attempt to upload PHP webshells, encoded stagers, backdoors, or polyglot files through endpoints that are reachable only after login or only from browser-like clients.
- **Noisy legitimate admin/plugin traffic:** Real admin actions, page builders, AJAX endpoints, REST APIs, XML-RPC integrations, backup plugins, security scanners, and migration tools can produce noisy parameters and large POST bodies. The WAF policy must distinguish between reasons that should block after clearance and reasons that should log after clearance.

## Current risk: clearance can bypass WAF

In the current `configs/lua/cfm.lua` flow, the solved-cookie fast path appears before inline WAF inspection.

The simplified flow is:

```text
POST resume handling
valid clearance cookie? -> allow origin and return
inline cfm_waf.lua
forced challenge
bridge/webdet rule decision
```

That means a valid `cfm_clearance` cookie can allow the request to reach Apache/origin before `cfm_waf.lua` inspects it. In `configs/lua/cfm.lua`, the solved-cookie fast path validates `cfm_clearance` early and, when valid, immediately routes the request to Apache with `X-CFM-Action: allow_cookie`. Because this return occurs before the inline WAF section, a valid `cfm_clearance` can allow an origin-bound request before `cfm_waf.lua` runs.

This is risky for paths such as:

- `/admin`
- `/wp-admin`
- `/wp-login.php`
- `/xmlrpc.php`
- `/admin/upload`
- plugin/theme editors
- file-manager endpoints
- backup/migration endpoints

Example risk:

1. A rule challenges `/admin`.
2. The attacker solves the challenge.
3. The attacker submits a malicious upload to `/admin/upload`.
4. The clearance fast path allows the request to origin.
5. `cfm_waf.lua` does not inspect the payload.
6. A backdoor may be placed if the application is vulnerable.

The practical result is that a client that solved a challenge may be able to send exploit payloads, malicious uploads, or CMS/plugin abuse traffic to origin without inline WAF inspection in this path.

## Current risk: first-match WAF behavior

`configs/lua/cfm_waf.lua` appears to use first-match return semantics. Many detectors return immediately with this shape:

```lua
return true, reason, ttl, action
```

This means an early low-severity `logonly` hit can prevent later higher-severity rules from being evaluated.

Example:

```text
Request triggers:
- WAF_CT_ANOMALY -> logonly
- WAF_UPLOAD_CONTENT:UPLOAD_PHP_TAG -> block
```

If the content-type anomaly is evaluated first and returns `logonly`, the upload-content rule may never run.

This makes the meaning of `logonly` ambiguous:

```text
safe meaning:
  after evaluating all rules, strongest match is logonly

current risky meaning:
  first matching rule was logonly
```

For shared hosting, the safe meaning is required. The final WAF action should not depend on detector order when multiple detectors match the same request.

## Recommended architecture

The enforcement path should separate CFM control endpoints, clearance validation, WAF inspection, and origin allow decisions.

The preferred request flow is:

1. Request enters the normal web listener.
2. CFM control endpoints bypass Lua through exact nginx locations:
   - `/__cfm_challenge`
   - `/__cfm_verify`
3. For origin-bound requests:
   - apply POST resume handling;
   - validate `cfm_clearance` but do not allow yet;
   - run `cfm_waf.lua`;
   - evaluate all relevant WAF rules;
   - compute the highest-severity WAF result.
4. Enforce the WAF result:
   - `block` -> block;
   - `logonly` -> log and continue;
   - `challenge` without clearance -> challenge;
   - `challenge` with clearance -> do not re-challenge; apply post-clearance policy.
5. If clearance is valid:
   - allow origin;
   - skip repeated webdet/rule challenge gates.
6. If clearance is not valid:
   - continue forced challenge and bridge/webdet rule decisions.

Additional architectural requirements:

- **Bypass Lua only for exact CFM control endpoints.** Exact internal/control endpoints such as `/__cfm_challenge` and `/__cfm_verify` should bypass Lua to avoid self-interference and challenge loops. The bypass should be exact-match only, not a broad prefix that could hide origin traffic.
- **Validate clearance for origin-bound requests, but do not allow yet.** For normal origin-bound requests, validate `cfm_clearance` and store the result in request context. Do not immediately proxy to origin solely because clearance is valid.
- **Run WAF before clearance-origin allow.** Inline WAF inspection should evaluate the request before any clearance-based allow to Apache/origin.
- **Evaluate all relevant WAF rules.** `cfm_waf.lua` should continue evaluating relevant rules after a match, collect findings, and return the highest-severity decision for the request.
- **Use clearance to skip repeated challenge gates, not WAF inspection.** Clearance should prevent repeated challenge prompts for clients that already solved the challenge. It should not suppress `block` decisions, payload inspection, exploit signatures, upload scanning, or logging.

## WAF severity model

WAF rules should be evaluated using an explicit severity order:

```text
block > challenge > logonly > no hit
```

A request may match multiple WAF rules. The final enforcement action should be based on the highest-severity match, not the first match.

Recommended internal representation:

```lua
local ACTION_SEVERITY = {
  disabled = 0,
  logonly = 1,
  challenge = 2,
  block = 3,
}
```

The WAF can still record all hits for logging and diagnostics, but enforcement should use the strongest effective action.

## Post-clearance WAF policy

Moving WAF before clearance-origin allow introduces one important issue: WAF rules with action `challenge` can loop.

Example loop if not handled:

1. Request triggers WAF challenge.
2. User solves challenge.
3. Browser retries the original request with `cfm_clearance`.
4. WAF sees the same payload.
5. WAF challenges again.
6. Repeat.

Therefore, post-clearance WAF challenge behavior must be explicit.

Recommended policy:

```text
WAF block    -> block, even after clearance
WAF logonly  -> log and allow, after all WAF rules are evaluated
WAF challenge without clearance -> challenge
WAF challenge with clearance -> convert to configured post-clearance action
```

Recommended shared-hosting defaults:

```text
high-risk WAF challenge reason + clearance -> block
noisy WAF challenge reason + clearance     -> logonly / allow-with-log
```

A second challenge after valid clearance should not be the default because it does not make the payload safer and can create loops.

Post-clearance behavior should be explicit and loop-safe:

- **`block` remains `block`.** A rule that resolves to `block` should block even when `cfm_clearance` is valid.
- **`logonly` logs and allows after full evaluation.** A `logonly` finding should be recorded, but the request should be allowed only after all relevant rules have been evaluated and no higher-severity decision is found.
- **`challenge` without clearance challenges.** If the request triggers a `challenge` decision and has no valid clearance, the normal challenge flow should run.
- **`challenge` with clearance must not loop.** If the request triggers a `challenge` decision and already has valid clearance, CFM should not send the client back into the same challenge loop.

### High-risk reasons

High-risk WAF reasons should include low-false-positive exploit and malware indicators, such as:

- strong RCE markers;
- shell execution markers;
- PHP webshell body scoring;
- uploaded PHP/JSP/webshell content;
- dangerous multipart upload filenames;
- command execution payloads;
- downloader chains using `wget`, `curl`, `bash`, or `sh`;
- `base64`, `eval`, `exec`, and `system` payloads;
- known exploit markers with low legitimate use.

Examples of reason families to classify as high risk:

- `WAF_RCE`
- `WAF_UPLOAD_CONTENT`
- `WAF_UPLOAD_FNAME`
- `WAF_UPLOAD_OBFUSCATION`
- `WAF_CMD_PAYLOAD`
- `WAF_B64_INJECT`
- `WAF_SHELLSHOCK`

Exact reason matching should be based on the current strings emitted by `configs/lua/cfm_waf.lua`.

### Noisy or compatibility-sensitive reasons

Some detections can be noisy in shared hosting and should usually remain `logonly` or allow-after-clearance unless tuned:

- broad SQLi heuristics;
- broad XSS heuristics;
- generic suspicious user agents;
- unusual but legitimate admin/plugin parameters;
- page builder payloads;
- backup/migration plugin payloads;
- serialized data;
- broad content-type anomalies;
- generic debug toggles.

These should still be logged because they are useful for tuning and investigation.


## Proposed new WAF rules and signals

The rules below are proposed additions after the request-flow fixes above: WAF must run before clearance-origin allow, WAF must choose the highest-severity result, and post-clearance `challenge` must not loop. These signals should initially land as scored findings with per-rule configuration, not as unconditional hard blocks, so operators can tune behavior on real shared-hosting traffic.

### Placement: front line versus detector files

CFM already has path-oriented detector inputs such as `webdetector_challenge_paths.txt` and `webdetector_malpaths.txt` through `MALPATH_FILE` and `CHALLENGE_PATHS_FILE`. Those remain useful for broad webdetector policy and route-level challenge decisions.

The webshell and payload rules in this section should still be considered for the front-line Edge/Lua WAF path when they inspect origin-bound requests. The distinction is:

- **Webdetector path lists:** good for route/path challenge policy and cheap suspicious-path matching.
- **Edge/Lua WAF signals:** required for post-clearance payload inspection, multipart upload inspection, highest-severity aggregation, and block/log/challenge policy decisions before origin.

When a signal is path-only and extremely cheap, it can exist in both systems if deduplication and logging are clear. The important invariant is that a valid `cfm_clearance` must not bypass the Edge/Lua WAF version of the signal for origin-bound traffic.

### Phase 1: webshell delivery and droppers

#### W1. Known-bad webshell path names

Known webshell filenames are high-confidence attack probes and are safe to evaluate as literal path strings. These are fast checks and should be near-zero false positive when scoped to exact path components and suspicious query strings.

Example rule data:

```lua
local WEBSHELL_PATHS = {
  "/b374k.php", "/c99.php", "/r57.php", "/wso.php", "/alfa.php",
  "/indoxploit.php", "/marijuana.php", "/0byt3m1n1.php", "/anonghost.php",
  "/p0wny.php", "/x.php", "/cmd.php", "/shell.php", "/sh.php", "/up.php",
  "/priv8.php", "/up0.php", "/file_manager.php", "/hax.php", "/eval.php",
  "/system.php", "/cmd2.php", "/sa.php", "/marg.php", "/lol.php",
  "/idx.php", "/injec.php", "/buce.php",
}
```

Additional query-bearing probes can be tracked separately so matching stays exact and explainable:

```lua
local WEBSHELL_QUERY_PROBES = {
  "/upload.php?type=",
  "/admin.php?password=",
  "/login.php?login=admin&pass=admin",
}
```

Suggested behavior:

- implement as `detect_known_webshell_path(uri, args)` or as a high-weight score signal inside the existing bad-UA/path scorer;
- score `+6`, which places the request into block-class severity under the proposed scoring model;
- keep a rule knob such as `rule_known_webshell_path` so operators can run `logonly`, `challenge`, or `block` during rollout.

#### W2. Webshell magic strings in body

Known webshell banners and PHP execution primitives are useful upload/body signals, especially when combined with multipart upload context. Candidate literals include:

```text
b374k
WSO 2.5
IndoXploit
@eval(
@assert(
<?php echo `
<?php system(
<?php exec(
if(isset($_POST[
$auth_pass=
shell_exec(
FilesMan
PhpJackal
0xPNST
Mini Shell
```

Suggested behavior:

- extend `detect_php_webshell_body` with a literal list and score contribution;
- do not treat every single generic PHP function as an automatic block in isolation;
- default ambiguous primitives such as `system(`, `exec(`, and `shell_exec(` to `challenge` or scored `logonly` unless paired with upload context, obfuscation, command payload, or known webshell markers;
- promote to `block` when multiple webshell indicators combine, when the payload is multipart upload content, or when a known banner/tool name appears.

This caution matters because custom administrative scripts, deployment hooks, and developer tools can legitimately contain PHP code that references `system`, `exec`, or `shell_exec`. The safe default is to score these primitives and let the highest-severity accumulator combine them with stronger context.

#### W3. PHP function obfuscation

Legitimate PHP rarely partially hex- or octal-encodes function names or reconstructs dangerous functions through character concatenation. These patterns are strong signals when they appear in request bodies, uploaded files, or query parameters.

Example indicators:

```text
\x65val
\x73ystem
e\x76al
\x65xec
\145\166\141\154
chr(101).chr(118).chr(97).chr(108)
hex2bin($_POST[
include $_
include_once $_
```

Recent malware samples often mix case changes, octal escapes, hex escapes, temporary writable directories, request-keyed payload decode, `include` of a transient file, and immediate unlink. Instead of matching a single brittle sample, prefer composable signals such as:

- encoded characters inside function names or superglobal keys;
- `chr(...)` or array-index reconstruction of function names;
- `hex2bin` or custom XOR decode from `$_POST` / `$_REQUEST`;
- writes to `/tmp`, `/var/tmp`, `/dev/shm`, `sys_get_temp_dir()`, or `session_save_path()` followed by `include` / `include_once`;
- `unlink` immediately after include;
- mixed-case PHP built-ins in otherwise compact code.

Suggested behavior:

- score a single strong obfuscation hit around `+5`;
- promote to block-class when obfuscation combines with upload context, webshell magic strings, command execution, or temporary-file include/unlink behavior;
- keep exact matching tied to current strings emitted by `configs/lua/cfm_waf.lua` so reason families stay stable for policy conversion.

#### W4. Polyglot file upload detection

A common shared-hosting attack is an image upload that is actually executable content. In the multipart parser, detect cases where a part claims to be an image or has an image-like extension but the first bytes contain executable markers.

Suggested test:

```text
multipart part Content-Type: image/*
or filename extension: .png/.jpg/.jpeg/.gif/.webp/.ico/.svg
and first 64 bytes contain: <?php, <?=, <script, or <%
```

Suggested behavior:

- score `+6` for PHP/server-side executable markers in image uploads;
- score JavaScript in SVG separately because legitimate SVG can contain script in some workflows, but it is often unsafe in CMS uploads;
- default PHP/JSP/ASP markers in image uploads to block-class after validation on local traffic.

### Phase 2: post-exploitation and RCE payloads

#### R1. Reverse shell command patterns

Reverse shell strings in URL, body, or uploaded content are very high-confidence RCE/post-exploitation signals.

Candidate literals:

```text
bash -i >& /dev/tcp/
sh -i >& /dev/tcp/
nc -e /bin/sh
nc -e /bin/bash
perl -e 'use Socket'
python -c 'import socket'
python -c "import socket"
ruby -rsocket -e
socat tcp-connect
php -r '$sock=fsockopen
powershell -nop -c
powershell -ep bypass
```

Suggested behavior:

- implement `detect_reverse_shell_payload(body, args)`;
- assign instant block-class score for exact literals;
- still record the reason family, for example `WAF_RCE:REVERSE_SHELL`, so post-clearance high-risk conversion is deterministic.

#### R2. Cron and systemd persistence

Persistence installation commands are rarely legitimate web-app input.

Candidate literals:

```text
crontab -l
crontab -e
(crontab -l ;
echo "* * * * *
* * * * * curl
/etc/cron.d/
/var/spool/cron/
[Unit]
Description=
ExecStart=/
After=network.target
systemctl enable
systemctl --user enable
```

Suggested behavior:

- score `+6` for exact persistence strings;
- combine with downloader/C2 strings for immediate block-class severity;
- classify reasons under a high-risk family such as `WAF_RCE:PERSISTENCE`.

#### R3. LD_PRELOAD and userspace rootkit signatures

Userspace rootkit artifacts are extremely high-confidence when present in inbound HTTP payloads.

Candidate literals:

```text
LD_PRELOAD=
/etc/ld.so.preload
libprocesshider.so
mafix.so
bdvl.so
libkeylogger.so
libnss-rootkit
echo > /proc/sysrq-trigger
```

Suggested behavior:

- score `+6` or higher;
- combine with file write, command execution, or downloader indicators;
- classify as high-risk, for example `WAF_RCE:ROOTKIT_ARTIFACT`.

#### R4. Living-off-the-land Windows binaries and PowerShell payloads

Even Linux-hosted shared environments receive cross-platform malware, dropper code, and Windows payloads in PHP shells or scanner traffic.

Candidate literals:

```text
certutil -urlcache -split -f http
bitsadmin /transfer
mshta http
mshta vbscript:
regsvr32 /s /u /n /i:http
IEX (New-Object Net.WebClient)
iex(iwr
iex (iwr
Invoke-Expression (New-Object
-EncodedCommand
-enc
```

Suggested behavior:

- score these as RCE/dropper indicators;
- treat `-EncodedCommand` or `-enc` followed by a long base64 blob as high confidence;
- combine with the existing base64-blob detector for block-class severity.

### Phase 3: known-CVE and topical fingerprints

#### C1. Log4Shell patterns

Log4Shell probes remain common scanner traffic and are cheap to detect across headers, query strings, and bodies.

Candidate literals:

```text
${jndi:ldap://
${jndi:rmi://
${jndi:dns://
${${::-j}${::-n}${::-d}${::-i}
${lower:j}${lower:n}
${env:
```

Suggested behavior:

- single exact hit should be block-class;
- inspect headers as well as body/query because these payloads often target `User-Agent`, `Referer`, and custom headers;
- reason family: `WAF_CVE:LOG4SHELL`.

#### C2. Generic Java deserialization markers

Java serialization markers are rare in normal shared-hosting traffic and high signal for deserialization exploitation.

Candidate markers:

```text
rO0ABXNyAB
\xac\xed\x00\x05
```

Suggested behavior:

- scan both textual/base64 form and raw body bytes where available;
- classify under `WAF_CVE:JAVA_DESERIALIZATION`;
- default to challenge or block depending on local false-positive results.

#### C3. Maintained CVE signature template

Individual CVE patterns should not be hard-coded forever in Lua source because they become stale. Prefer a small signature file that can be updated independently:

```text
# /etc/cfm/cve_signatures.txt
# reason<TAB>score<TAB>literal
WAF_CVE:LOG4SHELL	6	${jndi:ldap://
WAF_CVE:JAVA_DESERIALIZATION	6	rO0ABXNyAB
```

Suggested behavior:

- load signatures at worker init and refresh them with a cache/lock pattern similar to `refresh_waf_excludes_if_needed`;
- support literal matching first; add glob/regex only if needed and bounded;
- include per-signature score and reason family;
- ship updates without requiring a full package redeploy.

### Phase 4: C2 and exfiltration callbacks

#### X1. Hardcoded malware infrastructure and tunnel services

These strings are suspicious when they appear inside POST bodies or uploaded scripts sent to the protected server, not merely as the request target.

Candidate literals:

```text
pastebin.com/raw/
cdn.discordapp.com/attachments/
api.telegram.org/bot
ngrok.io
trycloudflare.com
requestbin.io
webhook.site
mockbin.org/bin/
```

Suggested behavior:

- score `+5` in body/upload contexts;
- combine with RCE, downloader, SSRF, or webshell indicators for block-class severity;
- avoid blocking legitimate pages that merely link to these services unless additional exploit context exists.

#### X2. Coinminer URLs and tooling

Post-compromise coinminer installation is a common monetization path for opportunistic web RCE on shared-hosting servers.

Candidate literals:

```text
xmrig --url
xmrig.exe
minerd
pool.minexmr.com
xmrpool
supportxmr.com
cryptonight
randomx
nicehash
stratum+tcp://
stratum+ssl://
```

Suggested behavior:

- score `+5`;
- combine with command execution, downloader chains, and persistence strings;
- classify under `WAF_RCE:COINMINER` or `WAF_C2:COINMINER`.

### Phase 5: behavioral and combined-signal heuristics

#### B1. POST Content-Length inconsistencies

If declared `Content-Length` differs materially from the body length observed by Lua, the request may be a smuggling probe or parser-confusion attempt.

Suggested behavior:

- score `+4` when declared length and observed body length differ beyond expected buffering/truncation behavior;
- account for `client_body_buffer_size`, body truncation limits, and OpenResty request-body APIs to avoid false positives;
- classify under `WAF_HTTP_SMUGGLING:CONTENT_LENGTH_MISMATCH`.

#### B2. HTTP method oddities

Suspicious methods should contribute score when used outside expected locations.

Candidate methods:

```text
TRACE
TRACK
DEBUG
CONNECT
PROPFIND
SEARCH
```

Suggested behavior:

- score `+2` for odd methods;
- raise severity when `CONNECT` targets non-proxy paths or `PROPFIND`/`SEARCH` targets non-DAV paths;
- fold into existing IIS/Tomcat/exploit-method checks where practical.

#### B3. Ultra-long single URL segment

A single path segment of 256 or more characters is rarely legitimate and often indicates overflow probing, shellcode delivery, DGA-style paths, or evasion.

Suggested behavior:

- add a sibling to the existing long-base64 detector;
- score `+3` for any single path segment length `>= 256`;
- raise severity if the segment also contains high-entropy/base64-like content.

#### B4. Oversized header bag

Large headers are already constrained by nginx settings, but Lua-level accounting can identify evasion fingerprints.

Suggested behavior:

- sum `ngx.req.get_headers()` value bytes;
- score `+3` when total header value bytes exceed 16 KB and the request lacks normal explanations such as large `Cookie` or `Authorization` headers;
- log header names and total sizes, not sensitive values.

#### B5. Method, UA, and path combo fingerprint

Some scanner probes are only high-confidence as combinations.

Suggested combo:

```text
POST + empty User-Agent + Content-Length: 0 + URI ends in .php
```

This often represents a webshell ping checking whether a planted PHP file exists and executes.

Suggested behavior:

- score `+6` for the full combination;
- keep individual parts lower severity to avoid punishing benign automation;
- classify under `WAF_BAD_UA:WEBSHELL_PING` or `WAF_WEBSHELL:PING`.

## Rule rollout and false-positive management

New rules should land safely and become stricter only after measurement.

Recommended rollout process:

1. **Start as score signals.** All new rules should initially record scored findings rather than unconditional instant blocks.
2. **Replay legitimate traffic.** Build a sanitized corpus from roughly one week of recent `access.cfm.log` traffic and replay it against the new rules in tests.
3. **Replay attack samples.** Maintain fixtures for webshell uploads, reverse shells, CVE probes, C2 callbacks, miner downloaders, and noisy admin/plugin traffic.
4. **Promote gradually.** Promote rules from `logonly` to `challenge` to `block` based on production hit rate and sample performance. A candidate promotion threshold is: fires on less than `0.01%` of legitimate traffic and on nearly all relevant attack samples.
5. **Add per-rule kill switches.** Mirror existing `rule_*` config knobs so a misbehaving rule can be disabled or downgraded live without redeploying.
6. **Track false positives as tuning data.** When a block is later judged legitimate, adjust the score, context requirements, or action; do not only disable the rule permanently.
7. **Prefer combinations for noisy signals.** Generic PHP functions, broad SQLi/XSS heuristics, and compatibility-sensitive admin/plugin payloads should gain severity through context rather than blocking alone.

## Panel DNAT and hosting-control-plane traffic

It can make sense to apply the WAF to panel DNAT paths as well, especially for upload-capable control-plane features such as cPanel File Manager, DirectAdmin file manager, plugin/theme editors, backup restore tools, and migration/import workflows. A hijacked hosting account can use a legitimate panel session to upload a webshell or dropper.

Recommended approach:

- keep exact CFM control endpoints bypassed as described above;
- consider a panel-specific WAF profile for DNAT/control-plane routes rather than blindly reusing the public-web profile;
- inspect uploads, filenames, multipart bodies, archive restores, and file-manager writes for high-risk webshell/RCE indicators;
- default noisy admin compatibility signals to `logonly` while allowing high-confidence upload/RCE/webshell indicators to block;
- log enough context for incident response, but avoid logging sensitive panel credentials or full uploaded file contents.

## Implementation direction

### 1. Run WAF before clearance-origin allow

In `configs/lua/cfm.lua`, avoid returning to origin immediately after a valid clearance cookie.

Instead:

```text
validate clearance
run WAF
enforce WAF
then allow origin if clearance is valid
```

Add comments explaining that clearance proves challenge completion, not payload safety.

### 2. Refactor WAF to highest-severity decision

In `configs/lua/cfm_waf.lua`, change `_M.check(ctx)` from first-match return to hit accumulation.

Instead of this pattern:

```lua
if hit then
  return true, reason, ttl, mode
end
```

use a helper:

```lua
record_waf_hit(final, hits, reason, ttl, mode)
```

At the end:

```lua
return final.hit, final.reason, final.ttl, final.action, hits
```

If API compatibility is required, preserve the existing four return values and add an optional fifth return value for hit details.

### 3. Prevent post-clearance WAF challenge loops

In `configs/lua/cfm.lua`, handle:

```lua
waf_action == "challenge" and clearance_ok
```

Do not challenge again by default.

Instead, convert based on policy:

```text
high-risk reason -> block
other reason -> logonly / allow-with-log
```

Make this configurable if practical.

Suggested settings:

```text
CFM_WAF_AFTER_CLEARANCE_CHALLENGE=logonly
CFM_WAF_AFTER_CLEARANCE_HIGH_RISK=block
```

### 4. Preserve CFM control endpoint bypasses

The exact nginx locations for CFM control endpoints should continue bypassing `cfm.lua`:

- `/__cfm_challenge`
- `/__cfm_verify`

These endpoints should proxy directly to `cfm_challenge`. They should not be WAF-inspected, challenged, or sent to the origin application.

### 5. Add tests

Add tests or fixtures for:

- no clearance plus WAF challenge -> challenge;
- valid clearance plus no WAF hit -> allow origin;
- valid clearance plus WAF block -> block;
- valid clearance plus WAF challenge high-risk -> block;
- valid clearance plus WAF challenge noisy -> `logonly` / allow;
- `logonly` hit followed by challenge hit -> final challenge;
- `logonly` hit followed by block hit -> final block;
- challenge hit followed by block hit -> final block;
- multiple `logonly` hits -> final `logonly`.

## Desired final behavior

### Protected admin page with benign request

```text
GET /admin
  -> challenge rule fires
  -> user solves
  -> cfm_clearance set

GET /admin/dashboard
  -> WAF inspects
  -> no WAF hit
  -> clearance skips repeated challenge
  -> origin receives request
```

### Malicious upload after challenge

```text
POST /admin/upload
  -> WAF inspects
  -> WAF_UPLOAD_CONTENT or WAF_RCE hit
  -> high-risk action blocks
  -> origin never receives webshell
```

### Noisy low-risk rule after challenge

```text
POST /admin/plugin-settings
  -> WAF inspects
  -> broad/noisy challenge-grade heuristic
  -> valid clearance exists
  -> convert to logonly/allow-with-log
  -> origin receives request
  -> logs retain tuning signal
```

## Proposed implementation tasks

1. **Run WAF before clearance-origin allow in `configs/lua/cfm.lua`.** Move the valid-clearance fast path so it records clearance state, refreshes/touches clearance as needed, and only allows origin after WAF and forced-gate handling have completed.
2. **Refactor `configs/lua/cfm_waf.lua` from first-match to highest-severity decision.** Replace immediate returns from rule checks with finding collection or a decision accumulator. Severity ordering should prefer `block` over `challenge` over `logonly` over no action.
3. **Add post-clearance WAF challenge-loop prevention.** When WAF returns `challenge` and clearance is valid, convert the result through the configured post-clearance policy instead of re-challenging.
4. **Add tests and fixtures for clearance plus WAF behavior.** Cover valid-clearance allows, post-clearance blocks, high-risk and noisy post-clearance challenge conversion, and highest-severity WAF aggregation.

## Expected invariant

A solved `cfm_clearance` should mean: "do not repeatedly challenge this client for the same gate." It should never mean: "trust this request payload" or "skip WAF inspection before origin."

## Implementation progress

This section tracks what has actually shipped, separately from the design above. Future sessions should append here rather than rewriting earlier sections.

### Step 1 — DONE: highest-severity WAF aggregation in `cfm_waf.lua`

Implementation task #2 from the list above is complete. Behaviour change inside `cfm_waf.lua` only; `cfm.lua` is untouched in this step, so the clearance fast-path issue (task #1) and the challenge-loop issue (task #3) are still present.

What changed:

- Added a module-level `ACTION_SEVERITY` table (`disabled=0, logonly=1, challenge=2, block=3`) and constant `SEV_BLOCK`.
- `_M.check(ctx)` now keeps a `final_*` accumulator and a `hits` array and uses a local `record(reason, ttl, action)` closure. `record()` stores every match, updates `final_*` only when the new severity is strictly greater, and returns `true` only when the just-recorded action is `block`.
- All 35 first-match `return true, reason, ttl, mode` sites are replaced by `if record(reason, ttl, mode) then goto done end`. There is exactly one `::done::` label, before the final return.
- Short-circuit on `block`: once any rule lands a block-class hit, remaining detectors are skipped (block is the cap and cannot be exceeded).
- `_M.check` now returns a 5-tuple: `(hit, reason, ttl, action, hits)`. The first four are unchanged from before, so existing callers in `cfm.lua` keep working without modification. `hits` is for future logging/diagnostics.
- CPU gating: hoisted the repeated `lower(method) == "post" and body ~= ""` check into a single `body_inspect_ok` local computed once at the top of `_M.check`. Eight body/upload rules (15, 16, 17, 18, 19, 22, 33) now use that local. No semantic change, just one `lower()` call instead of eight.
- `host` is still referenced bare (not via `ctx.host`) inside rules 25/27/28. That is a pre-existing oversight and was deliberately left alone; touching it is not part of Step 1.

Why severity-aggregation matters here: the previous first-match behaviour meant an early `WAF_CT_ANOMALY:logonly` hit would suppress a later `WAF_UPLOAD_CONTENT:block` hit on the same request. With the accumulator, a `block` hit anywhere in the rule list wins, regardless of order, and lower-severity matches are still preserved in `hits` for future logging without affecting enforcement.

What this does NOT yet fix:

- A valid `cfm_clearance` cookie still bypasses the WAF entirely. The fast-path `return` in `cfm.lua` (Step 1 in the request flow, around the `allow_cookie` line) runs before `_M.check` is ever called. So the severity refactor only affects requests that reach the WAF at all.
- Post-clearance `challenge` loop prevention is not implemented; it cannot be implemented until Step 2 moves WAF before clearance-allow.
- The `hits` table is returned but not yet consumed anywhere. `cfm.lua` still only reads the first four return values.

### Step 2 — TODO: move WAF before clearance-origin allow in `cfm.lua`

Smallest possible diff: in `cfm.lua` around the `allow_cookie` early return, validate clearance into `ngx.ctx.cfm_clearance_ok` (and refresh as today), but do NOT `return` yet. Let control fall through into the existing inline-WAF block. Then, only after WAF finishes (no hit, or `logonly`), honour the clearance allow.

Risks to watch: replayed POST handling, sliding-clearance refresh side-effects, and any `X-CFM-Action: allow_cookie` consumers downstream. Do not move the CFM control endpoints (`/__cfm_challenge`, `/__cfm_verify`) — they are bypassed at nginx-level for a reason.

### Step 3 — TODO: post-clearance challenge-loop prevention

Becomes meaningful only after Step 2. Logic: when `waf_action == "challenge"` and clearance is valid, convert to either `block` (high-risk reason family prefix) or `logonly` (everything else). Drive via two env knobs:

- `CFM_WAF_AFTER_CLEARANCE_CHALLENGE` (default `logonly`)
- `CFM_WAF_AFTER_CLEARANCE_HIGH_RISK` (default `block`)

High-risk reason families to start with: `WAF_RCE`, `WAF_UPLOAD_CONTENT`, `WAF_UPLOAD_FNAME`, `WAF_UPLOAD_OBFUSCATION`, `WAF_CMD_PAYLOAD`, `WAF_B64_INJECT`, `WAF_SHELLSHOCK`. Match by reason prefix (everything before the first `:`).

### Step 4 — TODO: tests and fixtures

The 9 cases enumerated in "Add tests" above. Aim for fixtures that exercise both the highest-severity aggregation (e.g. a request that triggers logonly-then-block in that order) and the post-clearance conversion matrix.
