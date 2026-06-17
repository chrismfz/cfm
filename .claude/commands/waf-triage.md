---
description: Triage a WAF false positive / rule using the WAF runbooks
argument-hint: [rule id, path, app name, or pasted log line]
---
Triage this WAF issue: $ARGUMENTS

Use `docs/waf.md`, `docs/waf-analysis-2026-05-08.md`, and
`docs/challenge-waf-release-checklist.md`, plus the lessons in `CLAUDE.md` §6.

1. Identify the rule(s) involved in `configs/lua/cfm_waf.lua` /
   `configs/lua/cfm_rules.lua` and explain what they match.
2. Decide: is `$ARGUMENTS` a legitimate request being caught (false positive)
   or a real attack signal? Cross-check known offenders (Joomla K2 / elFinder
   `cmd=<verb>`, `/.well-known/`, panel/AutoSSL traffic).
3. Propose the **least-aggressive** fix: prefer an exclude or a
   `logonly → challenge` demotion over removing/weakening a block rule.
   Show the exact config change.
4. Before suggesting a reload, run the Lua validation gate:
   `luac -p configs/lua/*.lua` and the LuaJIT `require` smoke-test from the
   checklist.
5. Add a `CHANGELOG.md` `[Unreleased]` entry describing the rule change.

Do not reload OpenResty/Angie yourself — output the operator steps instead.
