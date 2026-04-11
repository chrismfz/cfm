# cPanel plugin token transport

The cPanel plugin uses **postMessage** as the primary token delivery mechanism for the embedded WebUI iframe.

## Transport order

1. **Primary (recommended):** parent page sends scoped token to iframe using `postMessage`.
2. **Compatibility fallback only:** parent page performs a one-time iframe reload with `?token=<scoped_token>` if no iframe ACK is received shortly after load.

## Expected origin injection

The cPanel plugin now appends `cfmExpectedOrigin=<parent_origin>` to the iframe URL before first load. The iframe auth context treats this value as the highest-priority expected `postMessage` origin (equivalent to injecting `window.__CFM_EXPECTED_ORIGIN__` or a `meta[name="cfm-expected-origin"]` value inside the iframe page).

If a token delivery message is rejected because of an origin mismatch, the iframe logs a debug warning that includes both the received origin and the expected origin.

## Important warning

URL token transport is a compatibility path and should be disabled whenever `postMessage` is reliable in your environment, because query parameters may be captured in access logs and intermediary tooling.
