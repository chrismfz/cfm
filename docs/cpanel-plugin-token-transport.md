# cPanel plugin token transport

The cPanel plugin uses **postMessage** as the primary token delivery mechanism for the embedded WebUI iframe.

## Transport order

1. **Primary (recommended):** parent page sends scoped token to iframe using `postMessage`.
2. **Compatibility fallback only:** parent page performs a one-time iframe reload with `?token=<scoped_token>` if no iframe ACK is received shortly after load.

## Important warning

URL token transport is a compatibility path and should be disabled whenever `postMessage` is reliable in your environment, because query parameters may be captured in access logs and intermediary tooling.
