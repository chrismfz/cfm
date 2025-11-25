#!/bin/sh
# /usr/bin/cfm-scan.sh
# Bridge between ModSecurity and CFM scanner

CFM_BIN="/usr/bin/cfm"

FILE="$1"   # temp file path from @inspectFile

# Pull info from env (we set these in cfm-modsec.conf)
IP="${CFM_REMOTE_ADDR:-$REMOTE_ADDR}"
XFF="${CFM_XFF:-}"
HOST="${CFM_HOST:-$HTTP_HOST}"
URI="${CFM_REQUEST_URI:-$REQUEST_URI}"
METHOD="${CFM_REQUEST_METHOD:-$REQUEST_METHOD}"
UA="${CFM_USER_AGENT:-$HTTP_USER_AGENT}"
REF="${CFM_REFERER:-$HTTP_REFERER}"
REQID="${CFM_UNIQUE_ID:-}"
FNAME="${CFM_FILENAME:-}"
FSIZE="${CFM_FILESIZE:-}"
SCRIPT="${CFM_SCRIPT_PATH:-}"
CTYPE="${CFM_CONTENT_TYPE:-}"

# Call CFM. The idea: "scanner" subcommand just enqueues and returns fast.
# You can adjust flags to match whatever CLI you implement.
"$CFM_BIN" scanner \
  --path "$FILE" \
  --source "modsec" \
  --ip "$IP" \
  --xff "$XFF" \
  --host "$HOST" \
  --uri "$URI" \
  --method "$METHOD" \
  --ua "$UA" \
  --referer "$REF" \
  --request-id "$REQID" \
  --filename "$FNAME" \
  --filesize "$FSIZE" \
  --script "$SCRIPT" \
  --ctype "$CTYPE" \
  >/dev/null 2>&1

# Always return success to ModSecurity (we don't block the request here)
exit 0
