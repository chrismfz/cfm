#!/bin/sh
set -eu

lua_file="configs/lua/cfm_panel.lua"
for token in "CFM_PANEL_SELFTEST_ONLY" "cfm_panel_selftest" "return cfm_panel_selftest()"; do
    if ! grep -Fq "$token" "$lua_file"; then
        echo "missing $token in $lua_file" >&2
        exit 1
    fi
done
