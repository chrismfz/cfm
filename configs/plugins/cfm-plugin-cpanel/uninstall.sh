#!/bin/bash
set -euo pipefail

echo "[+] Uninstalling CFM plugin"

WHM_CGI_DIR="/usr/local/cpanel/whostmgr/docroot/cgi"
CPANEL_CGI_DIR="/usr/local/cpanel/base/3rdparty"
APP_DIR="/var/cpanel/apps"
BASE_LIB_DIR="/usr/local/cpanel/base/cfm"
WHM_ICON_DIR="/usr/local/cpanel/whostmgr/docroot/addon_plugins"
CPANEL_THEME="jupiter"

WHM_CONF="$APP_DIR/cfm_whm.conf"
CPANEL_CONF="$APP_DIR/cfm_cpanel.conf"

# Best-effort unregister
if [ -f "$WHM_CONF" ]; then
    echo "[+] Unregistering WHM appconfig..."
    /usr/local/cpanel/bin/unregister_appconfig "$WHM_CONF" || true
fi

if [ -f "$CPANEL_CONF" ]; then
    echo "[+] Unregistering cPanel appconfig..."
    /usr/local/cpanel/bin/unregister_appconfig "$CPANEL_CONF" || true
fi

# Remove Jupiter plugin entries (old + new ids) if supported
if [ -x /usr/local/cpanel/scripts/uninstall_plugin ]; then
    echo "[+] Removing Jupiter plugin entries..."
    /usr/local/cpanel/scripts/uninstall_plugin cfm --theme="$CPANEL_THEME" || true
    /usr/local/cpanel/scripts/uninstall_plugin cfm_excludes --theme="$CPANEL_THEME" || true
fi

# Remove feature from all feature lists
echo "[+] Removing feature flag from feature lists..."
for f in /var/cpanel/features/*; do
    [ -f "$f" ] || continue
    sed -i '/^cfm_cpanel=/d' "$f" || true
done

# Remove known leftover frontend/dynamicui/cache files
echo "[+] Removing leftover Jupiter/dynamicui cache files..."
rm -rf "/usr/local/cpanel/base/frontend/$CPANEL_THEME/cfm" 2>/dev/null || true
rm -rf "/usr/local/cpanel/base/frontend/$CPANEL_THEME/cfm_excludes" 2>/dev/null || true

rm -f "/usr/local/cpanel/base/frontend/$CPANEL_THEME/dynamicui/dynamicui_cfm.conf" 2>/dev/null || true
rm -f "/usr/local/cpanel/base/frontend/$CPANEL_THEME/dynamicui/dynamicui_cfm_excludes.conf" 2>/dev/null || true
rm -f "/usr/local/cpanel/base/frontend/$CPANEL_THEME/dynamicui/dynamicui_cfm_cpanel.conf" 2>/dev/null || true
rm -f "/usr/local/cpanel/base/frontend/$CPANEL_THEME/dynamicui/dynamicui_cfm_whm.conf" 2>/dev/null || true
rm -f "/usr/local/cpanel/base/frontend/$CPANEL_THEME/dynamicui/"*cfm* 2>/dev/null || true

rm -f /var/cpanel/dynamicui_cache/*cfm* 2>/dev/null || true
rm -f /var/cpanel/pluginscache/*cfm* 2>/dev/null || true

# Remove files
echo "[+] Removing installed files..."
rm -f "$WHM_CGI_DIR/cfm_whm.cgi"
rm -f "$CPANEL_CGI_DIR/cfm_cpanel.cgi"

rm -f "$WHM_CONF"
rm -f "$CPANEL_CONF"

rm -f "$WHM_ICON_DIR/cfm.png"

rm -f "$BASE_LIB_DIR/lib/bootstrap.php"
rm -f "$BASE_LIB_DIR/lib/cfm_api.php"
rm -f "$BASE_LIB_DIR/lib/domain_provider.php"
rm -f "$BASE_LIB_DIR/lib/actions.php"
rm -f "$BASE_LIB_DIR/lib/assets/style.css"
rm -f "$BASE_LIB_DIR/lib/assets/app.js"
rm -f "$BASE_LIB_DIR/templates/index.php"

# Remove empty dirs only if empty
rmdir "$BASE_LIB_DIR/lib/assets" 2>/dev/null || true
rmdir "$BASE_LIB_DIR/lib" 2>/dev/null || true
rmdir "$BASE_LIB_DIR/templates" 2>/dev/null || true
rmdir "$BASE_LIB_DIR" 2>/dev/null || true

# Rebuild UI caches just in case
if [ -x /usr/local/cpanel/bin/dynamicui_update ]; then
    echo "[+] Rebuilding dynamicui cache..."
    /usr/local/cpanel/bin/dynamicui_update || true
fi

if [ -x /usr/local/cpanel/bin/sprite_generator ]; then
    echo "[+] Rebuilding Jupiter sprite cache..."
    /usr/local/cpanel/bin/sprite_generator --theme "$CPANEL_THEME" || true
fi

echo "[+] Reloading cpsrvd..."
/usr/local/cpanel/etc/init/startcpsrvd

echo "[+] Uninstalled successfully"