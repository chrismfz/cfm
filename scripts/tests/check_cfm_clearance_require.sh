#!/usr/bin/env bash
set -euo pipefail

luajit -e 'package.path = "configs/?.lua;" .. package.path; require("cfm_clearance")'
echo "OK: require('cfm_clearance') succeeds"
