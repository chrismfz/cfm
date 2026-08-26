#!/bin/sh
# cpanel-plugin-refresh.sh — non-disruptive refresh of the LIVE cPanel/WHM plugin
# code on a package upgrade.
#
# The cfm package ships the plugin SOURCE under /usr/share/cfm/plugins/; the live
# plugin under /usr/local/cpanel is installed manually via install.sh. This helper
# refreshes ONLY the plugin CODE files (PHP lib + CGIs + template) in place, so
# plugin fixes (e.g. the WHM direct-login change) ride a normal apt/yum upgrade.
# It deliberately does NOT register_appconfig / install_plugin / restart cpsrvd —
# those belong to first-time install.sh, and to any appconfig/icon change.
#
# It acts only when cPanel is present AND the plugin is already installed (marker:
# the live bootstrap.php exists) — it never installs the plugin where it was not
# already present. Single source of truth called best-effort from BOTH the deb
# postinst and the rpm %post (mirrors package-proxy-config-deploy.sh) so the two
# packaging scripts can't drift.

set -u

SRC=/usr/share/cfm/plugins/cfm-plugin-cpanel
LIB=/usr/local/cpanel/base/cfm/lib
TEMPLATES=/usr/local/cpanel/base/cfm/templates
WHM_CGI=/usr/local/cpanel/whostmgr/docroot/cgi/cfm_whm.cgi
CPANEL_CGI=/usr/local/cpanel/base/3rdparty/cfm_cpanel.cgi

# Act only on a cPanel host where the plugin is already installed. The live
# bootstrap.php is the install marker; without it we never create the plugin.
[ -d /usr/local/cpanel ] || exit 0
[ -d "$SRC/lib" ] || exit 0
[ -f "$LIB/bootstrap.php" ] || exit 0

ok=1
refresh() { # <src-relative> <dest> <mode>
    _src="$SRC/$1"
    if [ ! -f "$_src" ]; then
        echo "WARNING: CFM plugin source missing: $_src"
        ok=0
        return
    fi
    if ! install -m "$3" "$_src" "$2" 2>/dev/null; then
        echo "WARNING: CFM plugin refresh failed: $2"
        ok=0
    fi
}

# A prior install.sh created all of these; refresh them as a consistent SET so a
# new bootstrap.php never runs against a stale or missing cfm_api.php. Any copy
# failure is surfaced (below) rather than masked with a false success line.
refresh lib/bootstrap.php   "$LIB/bootstrap.php"   0644
refresh lib/cfm_api.php     "$LIB/cfm_api.php"     0644
refresh templates/index.php "$TEMPLATES/index.php" 0644
refresh lib/cfm_whm.cgi     "$WHM_CGI"             0755
refresh lib/cfm_cpanel.cgi  "$CPANEL_CGI"          0755

if [ "$ok" = 1 ]; then
    echo "CFM: refreshed cPanel/WHM plugin code."
else
    echo "WARNING: CFM plugin code refresh incomplete — re-run plugins/cfm-plugin-cpanel/install.sh"
fi
exit 0
