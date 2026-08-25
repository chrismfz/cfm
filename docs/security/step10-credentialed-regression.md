# Step 10 — credentialed live regression checklist

Proves the source-fixed findings hold on a **live** box, using a CLI-minted scoped
token (the read-only MCP cannot mint or POST). Run on/against the target; set the
three variables first. Nothing here changes production state (reads + rejected writes
+ one throwaway scoped token).

```bash
BASE="https://SERVER:6061"          # direct TLS control plane (or the edge https URL)
ADMIN_TOKEN="…"                     # AUTH_TOKEN from /etc/cfm/cfm.conf (admin)
# Mint a throwaway VIEWER-scoped token on the box:
#   cfm webtop tokens create --vhosts example.com --label audit-retest --ttl 1h
SCOPED_TOKEN="…"
C="curl -sS -o /dev/null -w %{http_code} -k"   # -k: self-signed :6061 fallback is expected
```

## R02 — pprof is admin-only (#1341)

```bash
$C $BASE/debug/pprof/heap                                    # want 401 (anon)
$C -H "Authorization: Bearer $SCOPED_TOKEN" $BASE/debug/pprof/heap   # want 403 (scoped MUST be denied)
$C -H "Authorization: Bearer $ADMIN_TOKEN"  $BASE/debug/pprof/heap   # want 200
```

## R03 — mutating endpoints are POST-only (#1350)

```bash
# GET on a mutator → 405 + Allow: POST; POST reaches the handler (auth-gated).
curl -sS -k -D- -o /dev/null -H "Authorization: Bearer $ADMIN_TOKEN" \
  $BASE/api/v1/challenge/vhost/add | grep -Ei '^HTTP|^Allow'         # want 405 + Allow: POST
$C -X POST -H "Authorization: Bearer $ADMIN_TOKEN" $BASE/api/v1/challenge/vhost/add  # want 400/200 (not 405)
```

## R01 — direct `:6060` browser transport (#1351)

```bash
H6060="http://SERVER:6060"
# Direct external browser GET of an admin route → 302 to :6061; a write → 403.
curl -sS -D- -o /dev/null -H "Accept: text/html" $H6060/cfm-admin/ | grep -Ei '^HTTP|^Location'   # want 302 → https://…:6061
$C -X POST -H "Accept: text/html" $H6060/cfm-admin/login                                          # want 403 (no plaintext admin write)
# Loopback stays served (run ON the box):
ssh SERVER 'curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:6060/cfm-admin/'           # want 200/302 (not blocked)
```

## R10 — direct security/cache headers (#1352)

```bash
curl -sS -k -D- -o /dev/null $BASE/login | grep -Ei 'x-content-type-options|referrer-policy'      # want nosniff + strict-origin-when-cross-origin
curl -sS -k -D- -o /dev/null $BASE/api/v1/system/status | grep -Ei 'cache-control|vary'            # anon 401 → want no-store + Vary
```

## Step 8 — rate limiting (#1355)

```bash
# Hammer a cheap read well past the (honest-high) scoped ceiling; expect an eventual 429 + Retry-After.
for i in $(seq 1 1200); do \
  code=$(curl -sS -k -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $SCOPED_TOKEN" $BASE/api/v1/system/status); \
  [ "$code" = "429" ] && { echo "429 after $i"; curl -sS -k -D- -o /dev/null -H "Authorization: Bearer $SCOPED_TOKEN" $BASE/api/v1/system/status | grep -i retry-after; break; }; \
done
# Check the trip is API-visible and NOT an nft block:
#   MCP: cfm_log_tail (grep event=ratelimit_trip)   ·   firewall_blocks (the token's IP must NOT appear)
```

## `:6061` self-signed fallback (#1356)

```bash
# By-IP (no SNI) must still complete a TLS handshake via the self-signed fallback.
echo | openssl s_client -connect SERVER:6061 2>/dev/null | grep -E 'subject=|Verify return code'  # want a cert (self-signed) — handshake completes
# With the real hostname, the real cert is preferred:
echo | openssl s_client -connect SERVER:6061 -servername HOSTNAME 2>/dev/null | grep 'subject='
```

## Step 6 — session-cookie Secure is automatic (#1357)

```bash
# Login over TLS :6061 → cfm-sid; Secure. (Use a real admin login; capture Set-Cookie.)
curl -sS -k -D- -o /dev/null -X POST $BASE/login -d 'user=…&pass=…' | grep -i '^set-cookie'        # want cfm-sid=…; Secure
# Login over loopback http :6060 (run ON the box) → cfm-sid-http-fallback; NOT Secure.
ssh SERVER 'curl -sS -D- -o /dev/null -X POST http://127.0.0.1:6060/login -d "user=…&pass=…" | grep -i set-cookie'  # want cfm-sid-http-fallback=…; no Secure
# Startup deprecation warning if AUTH_SECURE_COOKIE is present:
ssh SERVER 'grep -i "AUTH_SECURE_COOKIE is deprecated" /var/log/cfm/cfm.api.log | tail -1'
```

## Scope boundary (R02/scoped model)

```bash
# A scoped viewer must be denied admin-only endpoints (403), not served.
$C -H "Authorization: Bearer $SCOPED_TOKEN" $BASE/api/v1/auth/token   # want 403 (mint is admin-only)
```

## Close-out

- Revoke the throwaway token: `cfm webtop tokens revoke <id>` (or let the `--ttl` expire).
- Record results against `Audit_Results.md` R01/R02/R03/R10 (flip LIVE-PENDING → verified).
