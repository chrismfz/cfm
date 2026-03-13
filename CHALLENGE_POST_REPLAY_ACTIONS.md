# Challenge interception and POST replay (OpenResty mode)

In OpenResty mode, `nginx_bridge` can challenge any request, including state-changing `POST`s
(WordPress post submit, plugin upload, forum thread submit, etc.).

## What is now implemented

A bounded **OpenResty/Lua-side hold + replay** path is now available in `configs/cfm.lua`:

- when a request is going to be challenged and it is an eligible `POST`, Lua reads and stores
  a short-lived copy of the body in shared memory (`cfm_decisions`)
- client is redirected to challenge with a one-time replay token (`cfm_rt`)
- after challenge solve, browser returns to `next` (with `cfm_rt`)
- Lua consumes token once, reconstructs original `POST` (`method`, `uri`, `Content-Type`, body),
  and forwards it to origin

## Safety limits (important)

Replay is intentionally restricted:

- only `POST`
- only content types:
  - `application/x-www-form-urlencoded`
  - `application/json`
  - `text/plain`
- body must be `<= CFM_POST_RESUME_MAX_LEN` (default `65536` bytes)
- token TTL is short (`CFM_POST_RESUME_TTL_SEC`, default `90`)
- token is single-use (deleted on first consume)
- replay is bound to same client IP + host

If limits are not met, flow falls back to normal challenge behavior (no replay).

## Why this shape

This avoids unsafe generic buffering of huge multipart/plugin uploads and avoids unlimited
sensitive payload retention in memory, while still preserving many normal form/API posts.

## Behavior on re-challenge during replay

Replayed requests do **not** use solved-cookie fast path first; they pass through WAF/decision
checks again. If the replayed request is challenged again, Lua hard-blocks it (`403`) to avoid
infinite challenge loops.

## Tunables

Environment variables read by `cfm.lua`:

- `CFM_POST_RESUME_ENABLE` (default `1`)
- `CFM_POST_RESUME_MAX_LEN` (default `65536`)
- `CFM_POST_RESUME_TTL_SEC` (default `90`)

## Remaining limitation

Large binary/multipart uploads (for example plugin zip uploads) are still intentionally excluded
from replay for safety. For those, challenge earlier in session (GET/navigation) or rely on app-
side resumable upload support.
