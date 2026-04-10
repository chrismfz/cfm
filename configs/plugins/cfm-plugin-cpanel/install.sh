#!/usr/bin/env bash
set -euo pipefail

echo "[+] Installing CFM plugin"
echo "    Requires: AUTH_TOKEN set in /etc/cfm/cfm.conf"
echo "    Optional: CPANEL_PLUGIN_BASE_URL = https://hostname:port (if not via OpenResty)"
echo ""


WHM_CGI_DIR="/usr/local/cpanel/whostmgr/docroot/cgi"
CPANEL_CGI_DIR="/usr/local/cpanel/base/3rdparty"
APP_DIR="/var/cpanel/apps"
BASE_LIB_DIR="/usr/local/cpanel/base/cfm"
WHM_ICON_DIR="/usr/local/cpanel/whostmgr/docroot/addon_plugins"
CPANEL_THEME="jupiter"

TMP_PLUGIN_DIR="$(mktemp -d /tmp/cfm_plugin.XXXXXX)"
cleanup() {
    rm -rf "$TMP_PLUGIN_DIR"
}
trap cleanup EXIT

install -d -m 0755 "$WHM_CGI_DIR"
install -d -m 0755 "$CPANEL_CGI_DIR"
install -d -m 0755 "$APP_DIR"
install -d -m 0755 "$BASE_LIB_DIR/lib"
install -d -m 0755 "$BASE_LIB_DIR/templates"
install -d -m 0755 "$BASE_LIB_DIR/lib/assets"
install -d -m 0755 "$WHM_ICON_DIR"

# CGI entry points
install -m 0755 lib/cfm_whm.cgi    "$WHM_CGI_DIR/cfm_whm.cgi"
install -m 0755 lib/cfm_cpanel.cgi "$CPANEL_CGI_DIR/cfm_cpanel.cgi"

# Shared PHP library
install -m 0644 lib/bootstrap.php       "$BASE_LIB_DIR/lib/bootstrap.php"
install -m 0644 lib/cfm_api.php         "$BASE_LIB_DIR/lib/cfm_api.php"


# Canonical cPanel UI template (authoritative runtime UI)
install -m 0644 templates/index.php "$BASE_LIB_DIR/templates/index.php"
# Remove legacy UI file if present from older installs (not used at runtime).
rm -f "$BASE_LIB_DIR/lib/index.php"

# WHM icon
install -m 0644 lib/cfm.png "$WHM_ICON_DIR/cfm.png"

# AppConfig registration
install -m 0644 appconfig/cfm_whm.conf    "$APP_DIR/cfm_whm.conf"
install -m 0644 appconfig/cfm_cpanel.conf "$APP_DIR/cfm_cpanel.conf"

/usr/local/cpanel/bin/register_appconfig "$APP_DIR/cfm_whm.conf"
/usr/local/cpanel/bin/register_appconfig "$APP_DIR/cfm_cpanel.conf"

# Ensure feature exists in all feature lists
for f in /var/cpanel/features/*; do
    [ -f "$f" ] || continue

    if grep -q '^cfm_cpanel=' "$f" 2>/dev/null; then
        sed -i 's/^cfm_cpanel=.*/cfm_cpanel=1/' "$f"
    else
        echo "cfm_cpanel=1" >> "$f"
    fi
done

# Build Jupiter plugin package for visible cPanel icon/search entry
cat > "$TMP_PLUGIN_DIR/install.json" <<'JSON'
[
  {
    "icon": "cfm_cpanel.png",
    "group_id": "security",
    "order": 10000,
    "name": "CFM",
    "type": "link",
    "id": "cfm",
    "uri": "/3rdparty/cfm_cpanel.cgi",
    "target": "_self",
    "featuremanager": 1,
    "feature": "cfm_cpanel",
    "description": "CFM"
  }
]
JSON

# cPanel/Jupiter icon package assets
install -m 0644 lib/cfm.png "$TMP_PLUGIN_DIR/cfm_cpanel.png"

# Optional: if you later create a proper SVG, use that too.
# install -m 0644 lib/cfm_cpanel.svg "$TMP_PLUGIN_DIR/cfm_cpanel.svg"

echo "[+] Installing Jupiter plugin icon/link..."
/usr/local/cpanel/scripts/install_plugin "$TMP_PLUGIN_DIR" --theme="$CPANEL_THEME"

# Rebuild sprite/assets cache just in case
if command -v /usr/local/cpanel/bin/sprite_generator >/dev/null 2>&1; then
    /usr/local/cpanel/bin/sprite_generator --theme "$CPANEL_THEME" || true
fi

echo "[+] Reloading cpsrvd..."
/usr/local/cpanel/etc/init/startcpsrvd

echo "[+] Installed successfully"
