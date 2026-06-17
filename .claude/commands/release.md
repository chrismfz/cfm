---
description: Cut a date-stamped CFM release (stamp CHANGELOG, build, sync)
---
Perform the CFM release ritual. Version == today's date (`YYYY.MM.DD`, what
`make release` stamps).

1. Compute today's date with `date +%Y.%m.%d`.
2. In `CHANGELOG.md`, rename the `## [Unreleased]` heading to `## <today>`.
   - If the `[Unreleased]` section is empty (only `_Nothing yet._`), stop and
     ask me whether there is really anything to release.
   - After renaming, add a fresh empty block at the top:
     `## [Unreleased]` followed by `_Nothing yet._`.
3. Show me the `CHANGELOG.md` diff and the exact commands you intend to run,
   then **wait for my explicit confirmation** before building.
4. After I confirm: run `make release`, then `make sync`.
5. Report the produced artifact names/paths.

NEVER run `make sync` without my explicit confirmation — it publishes packages
to the remote repo. Commit the CHANGELOG change only if I ask.
