# cPanel plugin token transport

The cPanel plugin uses **postMessage** as the primary token delivery mechanism for the embedded WebUI iframe.

## Transport order

1. **Primary (required):** parent page sends scoped token to iframe using `postMessage`.
2. **Iframe ACK handling:** parent page expects a `cfmTokenAck` message from iframe. If ACK does not arrive before timeout, the plugin displays a user-visible warning banner and does **not** attempt URL token fallback.

## Expected origin injection

The cPanel plugin now appends `cfmExpectedOrigin=<parent_origin>` to the iframe URL before first load. The iframe auth context treats this value as the highest-priority expected `postMessage` origin (equivalent to injecting `window.__CFM_EXPECTED_ORIGIN__` or a `meta[name="cfm-expected-origin"]` value inside the iframe page).

If a token delivery message is rejected because of an origin mismatch, the iframe logs a debug warning that includes both the received origin and the expected origin.

## URL token transport status

URL token transport (`?token=<scoped_token>`) is **disabled by default** and **unsupported in production**.

- Parent-side plugin template no longer appends token query parameters as a fallback transport.
- Iframe-side auth context keeps URL parsing only behind a strict feature flag (`window.CFMFeatureFlags.enableLegacyUrlTokenTransport === true`) for backwards compatibility during controlled migrations.
- When the flag is enabled and URL token parsing is used, the iframe logs a deprecation warning.

Production deployments must keep URL token transport disabled because query parameters may be captured in access logs and intermediary tooling.
