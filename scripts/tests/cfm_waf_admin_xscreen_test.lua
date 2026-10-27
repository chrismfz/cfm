-- Tests for rule 503 (rule_wp_admin_cross_screen, WAF_ADMIN_XSCREEN, logonly):
-- a logged-in WordPress privileged action that did not come from its own form.
--
-- The positives are the tophair.gr kill chain (2026-10-06, from its access
-- log: staff opened order 40544 and their browser, driven by the stored
-- PixelYourSite payload, fetched user-new.php and plugin-install.php, then
-- POSTed user-new.php and update.php?action=upload-plugin with the order
-- screen as the Referer) and each signal on its own. The negatives are the
-- flows two months of titan's logs showed (every form from its own screen),
-- a subdirectory install, the multisite network admin, and the cases the
-- rule leaves alone (no Referer, a cross-host Referer, no login cookie, an
-- ordinary admin-ajax action).

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}

package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")
local det = require("cfm_waf_detectors")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end

local HOST = "www.tophair.gr"
local LOGIN = "wordpress_logged_in_8e1e7c0b=staff%7C1791400000%7Cabc%7Cdef; wordpress_sec_8e1e7c0b=x"
local ORDER = "https://www.tophair.gr/wp-admin/post.php?post=40544&action=edit"

-- o: { method, uri, args, body, ct, referer, cookie, dest, mode, site, user, host }
local function req(o)
  local h = { host = o.host or HOST, referer = o.referer, ["content-type"] = o.ct,
              ["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0",
              ["sec-fetch-dest"] = o.dest, ["sec-fetch-mode"] = o.mode,
              ["sec-fetch-site"] = o.site, ["sec-fetch-user"] = o.user,
              ["sec-purpose"] = o.h_purpose and "prefetch" or nil }
  local cookie = o.cookie
  if cookie == nil then cookie = LOGIN end
  h.cookie = cookie
  return { uri = o.uri, args = o.args or "", method = o.method or "POST",
           raw_uri = o.uri .. ((o.args and o.args ~= "") and ("?" .. o.args) or ""),
           host = o.host or HOST, ip = "2a02:587:6e02:1400:dc5d:81c0:469e:a107",
           headers = h, body = o.body or "", cookie = cookie }
end
-- A browser's form submission: a click-started document navigation.
local function form(o)
  o.dest, o.mode, o.site, o.user = o.dest or "document", o.mode or "navigate", o.site or "same-origin", o.user or "?1"
  return req(o)
end

local function fires(c, label, want)
  local hit, reason, _, action, _, rid = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want, label .. " — reason=" .. want .. " (got " .. tostring(reason) .. ")")
  check(rid == 503, label .. " — rule 503 (got " .. tostring(rid) .. ")")
  check(action == "logonly", label .. " — logonly (got " .. tostring(action) .. ")")
end
local function clean(c, label)
  local hit, reason = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end

local P = "WAF_ADMIN_XSCREEN:"
local USER_NEW_BODY = "action=createuser&_wpnonce_create-user=1a2b3c4d5e&_wp_http_referer=%2Fwp-admin%2Fuser-new.php" ..
                      "&user_login=maintenance&email=m%40x.io&pass1=Qx9&pass2=Qx9&role=administrator&createuser=Add+New+User"
local UPLOAD_CT = "multipart/form-data; boundary=----b"
local UPLOAD_BODY = '------b\r\nContent-Disposition: form-data; name="_wpnonce"\r\n\r\n1a2b3c4d5e\r\n' ..
                    '------b\r\nContent-Disposition: form-data; name="pluginzip"; filename="inline-gallery-widget.zip"\r\n' ..
                    'Content-Type: application/zip\r\n\r\nPK\3\4\20\0\0\0\8\0\r\n------b--\r\n'

-- ── Shipped configuration: 503 is logonly, and it owns the chain's headline ──
check(waf.get_config().rule_wp_admin_cross_screen == "logonly", "503 ships logonly")
fires(req({ uri = "/wp-admin/user-new.php", referer = ORDER, ct = "application/x-www-form-urlencoded", body = USER_NEW_BODY }),
      "defaults: createuser from the order screen", P .. "USER_NEW:FROM:post.php")
fires(req({ uri = "/wp-admin/update.php", args = "action=upload-plugin", referer = ORDER, ct = UPLOAD_CT, body = UPLOAD_BODY }),
      "defaults: upload-plugin from the order screen", P .. "UPLOAD_PLUGIN:FROM:post.php")

set_only({ rule_wp_admin_cross_screen = "logonly" })

-- ── The tophair chain as its access log shows it (Referer = the order) ─────
-- Firefox fetch(): Sec-Fetch-Dest empty, Mode cors/same-origin.
fires(req({ method = "GET", uri = "/wp-admin/user-new.php", referer = ORDER, dest = "empty", mode = "same-origin", site = "same-origin" }),
      "nonce scrape: GET user-new.php by fetch", P .. "NONCE_SCRAPE:user-new.php")
fires(req({ method = "GET", uri = "/wp-admin/plugin-install.php", args = "tab=upload", referer = ORDER, dest = "empty" }),
      "nonce scrape: GET plugin-install.php?tab=upload by fetch", P .. "NONCE_SCRAPE:plugin-install.php")
fires(req({ uri = "/wp-admin/user-new.php", referer = ORDER, dest = "empty", mode = "same-origin", ct = "application/x-www-form-urlencoded", body = USER_NEW_BODY }),
      "createuser by fetch", P .. "USER_NEW:SCRIPT")
fires(req({ uri = "/wp-admin/update.php", args = "action=upload-plugin", referer = ORDER, dest = "empty", ct = UPLOAD_CT, body = UPLOAD_BODY }),
      "upload-plugin by fetch", P .. "UPLOAD_PLUGIN:SCRIPT")
-- The same requests as an access log alone shows them (no Fetch Metadata):
-- the Referer convicts them.
fires(req({ uri = "/wp-admin/user-new.php", referer = ORDER, ct = "application/x-www-form-urlencoded", body = USER_NEW_BODY }),
      "createuser from the order screen (Referer only)", P .. "USER_NEW:FROM:post.php")
fires(req({ uri = "/wp-admin/update.php", args = "action=upload-plugin", referer = ORDER, ct = UPLOAD_CT, body = UPLOAD_BODY }),
      "upload-plugin from the order screen (Referer only)", P .. "UPLOAD_PLUGIN:FROM:post.php")

-- ── Each signal ─────────────────────────────────────────────────────────────
fires(form({ uri = "/wp-admin/user-new.php", referer = "https://www.tophair.gr/wp-admin/admin.php?page=wc-orders&action=edit&id=40544", body = USER_NEW_BODY }),
      "HPOS order screen, real form navigation", P .. "USER_NEW:FROM:admin.php")
fires(form({ uri = "/wp-admin/user-new.php", referer = "https://www.tophair.gr/product/shampoo/", body = USER_NEW_BODY }),
      "a front-end page (payload in a comment or review)", P .. "USER_NEW:FROM:front")
fires(form({ uri = "/wp-admin/user-new.php", referer = "https://www.tophair.gr", body = USER_NEW_BODY }),
      "the home page, no path", P .. "USER_NEW:FROM:front")
fires(req({ uri = "/wp-admin/user-new.php", dest = "iframe", mode = "navigate", site = "same-origin", body = USER_NEW_BODY }),
      "a form posted into a hidden iframe, no Referer", P .. "USER_NEW:FRAME")
fires(form({ uri = "/wp-admin/users.php", referer = "https://www.tophair.gr/wp-admin/edit.php?post_type=shop_order",
             body = "action=dodelete&delete_option=delete&users%5B%5D=7&_wpnonce=a" }),
      "user delete confirmation from the orders list", P .. "USERS:FROM:edit.php")
fires(form({ uri = "/wp-admin/user-edit.php", referer = ORDER, body = "user_id=1&email=evil%40x.io&action=update" }),
      "admin email change from the order", P .. "USER_EDIT:FROM:post.php")
fires(form({ uri = "/wp-admin/profile.php", referer = ORDER, body = "pass1=x&pass2=x&action=update" }),
      "own password change from the order", P .. "PROFILE:FROM:post.php")
fires(form({ uri = "/wp-admin/update.php", args = "action=upload-theme", referer = ORDER, ct = UPLOAD_CT, body = UPLOAD_BODY }),
      "upload-theme from the order", P .. "UPLOAD_THEME:FROM:post.php")
fires(req({ uri = "/wp-admin/admin-ajax.php", referer = ORDER, dest = "empty", ct = "application/x-www-form-urlencoded",
            body = "nonce=a&newcontent=%3C%3Fphp&action=edit-theme-plugin-file&file=functions.php&theme=woodmart" }),
      "file editor save from the order (admin-ajax, Referer)", P .. "FILE_EDITOR:FROM:post.php")
fires(req({ uri = "/wp-admin/update.php", args = "action=upload-plugin", referer = ORDER .. "&x=%2Fwp-admin%2Fplugin-install.php", ct = UPLOAD_CT, body = UPLOAD_BODY }),
      "the form's screen in the Referer's QUERY does not pass", P .. "UPLOAD_PLUGIN:FROM:post.php")
fires(req({ uri = "/wp-admin/update.php", ct = "application/x-www-form-urlencoded", referer = ORDER, body = "action=upload-plugin&x=1" }),
      "action in the POST body ($_REQUEST)", P .. "UPLOAD_PLUGIN:FROM:post.php")
fires(req({ uri = "/wp-admin/admin-ajax.php", referer = ORDER, ct = "application/x-www-form-urlencoded",
            body = "action=edit%2Dtheme%2Dplugin%2Dfile&file=functions.php" }),
      "file editor action url-encoded (passes the decoded-surface gate)", P .. "FILE_EDITOR:FROM:post.php")
fires(req({ uri = "/wp-admin/update.php", args = "action=upload%2Dplugin", referer = ORDER, ct = UPLOAD_CT, body = UPLOAD_BODY }),
      "action url-encoded (PHP decodes it)", P .. "UPLOAD_PLUGIN:FROM:post.php")
fires(form({ uri = "/wp-admin/user-new.php", referer = "https://evil.example/x", site = "cross-site", body = USER_NEW_BODY }),
      "cross-site", P .. "USER_NEW:CROSS_SITE")
fires(form({ uri = "/wp-admin/user-new.php", referer = "https://www.tophair.gr/wp-admin/user-new.php", user = "", body = USER_NEW_BODY }),
      "form.submit() no click started", P .. "USER_NEW:NO_ACTIVATION")
fires(req({ uri = "/blog/wp-admin/user-new.php", referer = "https://www.tophair.gr/blog/wp-admin/post.php?post=1&action=edit", body = USER_NEW_BODY }),
      "subdirectory install", P .. "USER_NEW:FROM:post.php")
fires(req({ uri = "/wp-admin/user-new.php", referer = 'https://www.tophair.gr/wp-admin/x"><svg', body = USER_NEW_BODY }),
      "an odd screen is reduced to a plain token", P .. "USER_NEW:FROM:x___svg")
fires(req({ uri = "/wp-admin/user-new.php", referer = 'https://www.tophair.gr/wp-admin/admin.php/"><svg', body = USER_NEW_BODY }),
      "a Referer screen is cut at its .php", P .. "USER_NEW:FROM:admin.php")
-- review: Apache's AcceptPathInfo runs /wp-admin/user-new.php/x as user-new.php
fires(req({ uri = "/wp-admin/user-new.php/", referer = ORDER, dest = "empty", body = USER_NEW_BODY }),
      "PATH_INFO after the screen (fetch)", P .. "USER_NEW:SCRIPT")
fires(req({ uri = "/wp-admin/update.php/x", args = "action=upload-plugin", referer = ORDER, ct = UPLOAD_CT, body = UPLOAD_BODY }),
      "PATH_INFO after update.php", P .. "UPLOAD_PLUGIN:FROM:post.php")
fires(req({ method = "GET", uri = "/wp-admin/user-new.php/x", dest = "empty" }),
      "PATH_INFO on a nonce scrape", P .. "NONCE_SCRAPE:user-new.php")
-- review: WordPress changes roles with a GET of users.php's own list form
fires(req({ method = "GET", uri = "/wp-admin/users.php", args = "_wpnonce=a&new_role=administrator&changeit=Change&users%5B%5D=7",
            referer = ORDER, dest = "empty" }), "role change by fetch", P .. "USERS_ROLE:SCRIPT")
fires(req({ method = "GET", uri = "/wp-admin/users.php", args = "_wpnonce=a&new_role2=administrator&changeit2=Change&users%5B%5D=7",
            referer = ORDER }), "role change (bottom form) from the order", P .. "USERS_ROLE:FROM:post.php")
fires(req({ method = "GET", uri = "/wp-admin/users.php", args = "action=promote&new_role=administrator&users%5B%5D=7", referer = ORDER }),
      "role change as action=promote", P .. "USERS_ROLE:FROM:post.php")
fires(req({ method = "GET", uri = "/wp-admin/users.php", dest = "empty" }), "users.php fetched for its nonce", P .. "NONCE_SCRAPE:users.php")
-- review: activating the uploaded plugin
fires(req({ method = "GET", uri = "/wp-admin/plugins.php", args = "action=activate&plugin=inline-gallery-widget%2Finline-gallery-widget.php&_wpnonce=a",
            referer = ORDER, dest = "empty" }), "plugin activation by fetch", P .. "ACTIVATE:SCRIPT")
fires(req({ uri = "/wp-admin/plugins.php", ct = "application/x-www-form-urlencoded", dest = "iframe",
            body = "action=activate-selected&checked%5B%5D=x%2Fx.php&_wpnonce=a" }), "bulk activation into an iframe", P .. "ACTIVATE:FRAME")
-- review: a nonce screen loaded into a hidden iframe
fires(req({ method = "GET", uri = "/wp-admin/user-new.php", dest = "iframe", mode = "navigate" }),
      "user-new.php in a hidden iframe", P .. "NONCE_FRAME:user-new.php")
-- review: the file editor through admin-ajax without a Referer
fires(req({ uri = "/wp-admin/admin-ajax.php", dest = "empty", site = "same-origin", ct = "application/x-www-form-urlencoded",
            body = "action=edit-theme-plugin-file&newcontent=x&file=functions.php" }), "file editor, no Referer, same-origin", P .. "FILE_EDITOR:NO_REFERER")

-- ── Legitimate flows (titan, 2026-09/10) ────────────────────────────────────
clean(form({ uri = "/wp-admin/user-new.php", referer = "https://www.tophair.gr/wp-admin/user-new.php", body = USER_NEW_BODY }),
      "Add New User from its own form")
clean(form({ uri = "/wp-admin/update.php", args = "action=upload-plugin", referer = "https://www.tophair.gr/wp-admin/plugin-install.php?tab=upload",
             ct = UPLOAD_CT, body = UPLOAD_BODY }), "plugin upload from plugin-install.php")
clean(form({ uri = "/wp-admin/update.php", args = "action=upload-theme", referer = "https://www.tophair.gr/wp-admin/theme-install.php?browse=popular",
             ct = UPLOAD_CT, body = UPLOAD_BODY }), "theme upload from theme-install.php")
clean(form({ uri = "/wp-admin/users.php", referer = "https://www.tophair.gr/wp-admin/users.php?role=customer", body = "action=-1&new_role=editor&changeit=Change" }),
      "bulk role change from users.php")
clean(form({ uri = "/wp-admin/user-edit.php", referer = "https://www.tophair.gr/wp-admin/user-edit.php?user_id=7&wp_http_referer=%2Fwp-admin%2Fusers.php",
             body = "user_id=7&action=update" }), "edit a user from user-edit.php")
clean(form({ uri = "/wp-admin/profile.php", referer = "https://www.tophair.gr/wp-admin/profile.php", body = "action=update" }), "own profile")
clean(form({ uri = "/wp-admin/profile.php", referer = "https://www.tophair.gr/wp-admin/user-edit.php?user_id=1", body = "action=update" }),
      "own account saved from user-edit.php (its form posts to profile.php)")
clean(form({ method = "GET", uri = "/wp-admin/users.php", args = "_wpnonce=a&new_role=editor&changeit=Change&users%5B%5D=7",
             referer = "https://www.tophair.gr/wp-admin/users.php" }), "role change from users.php's own form")
clean(form({ method = "GET", uri = "/wp-admin/plugins.php", args = "action=activate&plugin=x%2Fx.php&_wpnonce=a",
             referer = "https://www.tophair.gr/wp-admin/update.php?action=upload-plugin" }), "Activate after an upload")
clean(form({ method = "GET", uri = "/wp-admin/plugins.php", args = "action=activate&plugin=x%2Fx.php&_wpnonce=a",
             referer = "https://www.tophair.gr/wp-admin/themes.php?page=tgmpa-install-plugins" }),
      "Activate from a theme's page (activation is Fetch Metadata only)")
clean(form({ method = "GET", uri = "/wp-admin/user-new.php/", referer = "https://www.tophair.gr/wp-admin/users.php" }), "opening user-new.php/")
clean(req({ uri = "/wp-admin/admin-ajax.php", ct = "application/x-www-form-urlencoded", body = "action=edit-theme-plugin-file&file=x" }),
      "file editor, no Referer, no Fetch Metadata (old browser)")
clean(req({ uri = "/wp-admin/admin-ajax.php", referer = "https://www.tophair.gr/wp-admin/theme-editor.php?file=functions.php", dest = "empty",
            ct = "application/x-www-form-urlencoded", body = "action=edit-theme-plugin-file&file=functions.php" }), "file editor from theme-editor.php")
clean(req({ uri = "/wp-admin/admin-ajax.php", referer = "https://www.tophair.gr/wp-admin/plugin-editor.php?plugin=x/x.php", dest = "empty",
            ct = "application/x-www-form-urlencoded", body = "action=edit-theme-plugin-file&plugin=x/x.php" }), "file editor from plugin-editor.php")
clean(req({ uri = "/wp-admin/network/user-new.php", referer = "https://www.tophair.gr/wp-admin/network/user-new.php", body = USER_NEW_BODY }),
      "multisite network admin, own form")
clean(req({ uri = "/blog/wp-admin/user-new.php", referer = "https://www.tophair.gr/blog/wp-admin/user-new.php", body = USER_NEW_BODY }),
      "subdirectory install, own form")
clean(req({ method = "GET", uri = "/wp-admin/user-new.php", referer = "https://www.tophair.gr/wp-admin/users.php", dest = "document", mode = "navigate" }),
      "opening Add New User")
clean(req({ method = "GET", uri = "/wp-admin/user-new.php", dest = "empty", mode = "no-cors", h_purpose = true }),
      "a <link rel=prefetch> of Add New User")
clean(req({ method = "GET", uri = "/wp-admin/plugin-install.php", args = "tab=plugin-information&plugin=x", dest = "iframe", mode = "navigate" }),
      "plugin details in the thickbox iframe (GET)")
clean(req({ uri = "/wp-admin/admin-ajax.php", referer = ORDER, dest = "empty", ct = "application/x-www-form-urlencoded",
            body = "action=woocommerce_get_order_details&order_id=40544" }), "an ordinary admin-ajax call from the order")
clean(req({ uri = "/wp-admin/post.php", referer = ORDER, body = "action=editpost&post_ID=40544" }), "saving the order itself")
clean(req({ uri = "/wp-admin/options.php", referer = "https://www.tophair.gr/wp-admin/admin.php?page=wpseo", body = "option_page=x" }),
      "options.php from a plugin settings page (out of scope)")

-- ── What the rule leaves alone ──────────────────────────────────────────────
clean(req({ uri = "/wp-admin/user-new.php", body = USER_NEW_BODY }), "no Referer, no Fetch Metadata (old browser / no-referrer)")
clean(req({ uri = "/wp-admin/user-new.php", referer = "https://other.example/wp-admin/post.php?post=1&action=edit", body = USER_NEW_BODY }),
      "a cross-host Referer without Sec-Fetch-Site (left to the nonce)")
clean(req({ uri = "/wp-admin/user-new.php", referer = ORDER, cookie = "", body = USER_NEW_BODY }), "no login cookie")
clean(req({ uri = "/wp-admin/user-new.php", referer = "/wp-admin/post.php?post=1&action=edit", body = USER_NEW_BODY }), "a relative Referer")
clean(req({ method = "PUT", uri = "/wp-admin/user-new.php", referer = ORDER }), "another method")
clean(req({ uri = "/wp-content/plugins/x/user-new.php", referer = ORDER }), "not under wp-admin")

check(det.detect_wp_admin_cross_screen("post", nil, nil, nil, nil, nil, nil, nil) == nil, "nil everything")
check(det.detect_wp_admin_cross_screen("post", "/wp-admin/user-new.php", "", "", nil, LOGIN, nil, nil) == nil, "nil headers")

set_only({ rule_wp_admin_cross_screen = "disabled" })
clean(req({ uri = "/wp-admin/user-new.php", referer = ORDER, body = USER_NEW_BODY }), "503 disabled")

if fails > 0 then
  io.stderr:write(("cfm_waf admin cross-screen tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf WordPress admin action from another screen (rule 503)")
