# Scoped mode post-deploy verification (test environment)

Use this checklist immediately after deploying to test. It verifies scoped/admin session separation, page rendering, token identity, and late-token behavior.

## Preconditions

- Test deployment is reachable.
- You have:
  - One admin credential for `/cfm-admin/`.
  - One scoped cPanel user able to open the plugin.
- Browser devtools available.
- Use **two tabs** in the same browser profile:
  - **Tab A** = admin session.
  - **Tab B** = scoped cPanel plugin session.

## 1) Establish both auth contexts

1. In **Tab A**, sign in as admin and open:
   - `/cfm-admin/webdetector/`
2. In **Tab B**, open the cPanel plugin as the scoped user.

Expected:
- Tab A is in admin context.
- Tab B is in scoped context.

## 2) Verify scoped UI visibility across subpages

In **Tab B**, open each page and confirm it renders and shows scoped mode badge:

- `/cfm-admin/webdetector/controls/`
- `/cfm-admin/webdetector/vhost/`
- `/cfm-admin/webdetector/forensics/`
- `/cfm-admin/webdetector/waf/`

Expected:
- Page loads without redirect loops or blank state.
- Scoped badge remains visible on each page.

## 3) Verify token identity via API

Open devtools Network in each tab and inspect `GET /cfm-admin/api/v1/tokens/me`.

Expected payload semantics:

- **Tab A (admin):** response indicates non-scoped/admin context (`scoped:false`).
- **Tab B (plugin scoped user):** response indicates scoped context (`scoped:true`).

## 4) Verify authorization boundaries

From **Tab B (scoped)**, attempt known admin-only actions/endpoints used by WebDetector controls.

Expected:
- Admin-only writes/actions are blocked (403/denied behavior).
- Scoped-safe read endpoints continue to return successful responses.

From **Tab A (admin)**, confirm admin operations still function normally.

## 5) Reload race check (late-token behavior)

1. Hard reload once in both tabs.
2. Repeat checks from sections 2–4.

Expected:
- No transient mode flip after reload.
- Scoped badge and `tokens/me` scoped state remain consistent with tab context.
- No delayed token race causing scoped tab to momentarily gain admin capabilities.

## 6) Pass/fail outcome template

- **PASS** if all expectations above hold in both initial load and post-reload cycle.
- **FAIL** if any of the following occur:
  - Scoped page missing scoped badge.
  - `tokens/me` scoped bit mismatches tab context.
  - Scoped user can execute admin-only write/action.
  - Reload introduces temporary auth-state mismatch.

## Optional evidence capture

Capture and attach:

- Screenshot per subpage showing scoped badge (Tab B).
- Network capture snippets for `tokens/me` in Tab A and Tab B.
- Any failing request/response pair for auth-boundary regressions.
