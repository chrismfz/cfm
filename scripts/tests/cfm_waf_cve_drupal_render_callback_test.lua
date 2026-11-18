-- Rule 10030: a Drupal render-array callback key sent as request data
-- (CVE-2026-108097 / SA-CORE-2026-014 and CVE-2018-7600 / Drupalgeddon2).
-- Positives are the payloads a 7-day read of the edge nodes found (2026-11-18);
-- negatives are Drupal / other traffic that carries a `#` or the same words.

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
set_only({ rule_cve_drupal_render_callback = "block" })

local function get(uri, args)
  return { uri = uri, args = args, method = "GET", ip = "203.0.113.60", headers = {}, body = "" }
end
local function post(uri, body, ct)
  return { uri = uri, args = "", method = "POST", ip = "203.0.113.61",
           headers = { ["Content-Type"] = ct or "application/x-www-form-urlencoded" }, body = body }
end
local function fires(ctx, want, label)
  local hit, reason = waf.check(ctx)
  check(hit == true and reason == want, label .. " — want " .. want .. ", got " .. tostring(reason))
end
local function clean(ctx, label)
  local hit, reason = waf.check(ctx)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end

-- ── Positives (fleet payloads, verbatim) ────────────────────────────────────
fires(get("/poc/fieldui", "rows=%7B%22r22c9bee26c%22%3A+%7B%22%23region_callback%22%3A+%22poc_fieldui_process_row%22%2C+%22parent_wrapper%22%3A+%7B%22parent%22%3A+%7B%22%23value%22%3A+%22id%22%7D%7D%7D%7D"),
      "WAF_CVE:CVE_2026_108097:DRUPAL:REGION_CALLBACK", "lab-route #region_callback probe (JSON in the query)")
fires(get("/", "q=user%2Fpassword&name%5B%23post_render%5D%5B0%5D=array_map&name%5B%23suffix%5D=eval%28%24_POST%5Bc%5D%29%3B%2F%2F&name%5B%23type%5D=markup&name%5B%23markup%5D=x"),
      "WAF_CVE:CVE_2018_7600:DRUPAL:POST_RENDER", "Drupalgeddon2 in the query (reached a site with a 200)")
-- Drupalgeddon2's original form: a POST to the registration form
fires(post("/user/register", "form_id=user_register_form&_drupal_ajax=1&mail%5B%23post_render%5D%5B%5D=exec&mail%5B%23type%5D=markup&mail%5B%23markup%5D=id"),
      "WAF_CVE:CVE_2018_7600:DRUPAL:POST_RENDER", "Drupalgeddon2 POST body")
fires(post("/x", '{"rows":{"r1":{"#region_callback":"system","#value":"id"}}}', "application/json"),
      "WAF_CVE:CVE_2026_108097:DRUPAL:REGION_CALLBACK", "#region_callback in a JSON body")
fires(post("/x", '{"rows":{"r1":{"\\u0023region_callback":"system"}}}', "application/json"),
      "WAF_CVE:CVE_2026_108097:DRUPAL:REGION_CALLBACK", "JSON \\u0023 escape of the #")
local mp = table.concat({
  "--b", 'Content-Disposition: form-data; name="form_id"', "", "user_register_form",
  "--b", 'Content-Disposition: form-data; name="mail[#post_render][]"', "", "exec",
  "--b", 'Content-Disposition: form-data; name="mail[#markup]"', "", "id", "--b--", "" }, "\r\n")
fires(post("/user/register", mp, "multipart/form-data; boundary=b"),
      "WAF_CVE:CVE_2018_7600:DRUPAL:POST_RENDER", "Drupalgeddon2 multipart body")
fires(get("/", "a%5B%23pre_render%5D%5B%5D=passthru"), "WAF_CVE:CVE_2018_7600:DRUPAL:PRE_RENDER", "#pre_render key")
fires(get("/", "a%5B%23lazy_builder%5D%5B0%5D=system"), "WAF_CVE:CVE_2018_7600:DRUPAL:LAZY_BUILDER", "#lazy_builder key")
fires(get("/", "a%5B%23access_callback%5D=system"), "WAF_CVE:CVE_2018_7600:DRUPAL:ACCESS_CALLBACK", "#access_callback key")
fires(get("/", "a%255B%2523post_render%255D%255B0%255D=exec"), "WAF_CVE:CVE_2018_7600:DRUPAL:POST_RENDER", "double-encoded key")

-- ── Negatives ───────────────────────────────────────────────────────────────
clean(get("/search", "q=how+to+use+%23post_render+in+drupal"), "the word in a search")
clean(get("/node/12", "destination=%2Fadmin%2Fcontent%23overview"), "a # fragment in a destination")
clean(get("/admin/structure/types/manage/article/display", "fields%5Bbody%5D%5Bregion%5D=content&fields%5Bbody%5D%5Btype%5D=text_default"),
      "Field UI Manage Display save fields")
clean(post("/node/add/article", "title=Render+arrays&body%5B0%5D%5Bvalue%5D=%3Cp%3EUse+%23pre_render+and+%23post_render+callbacks%3C%2Fp%3E&form_id=node_article_form"),
      "a post about render arrays")
clean(get("/", "color=%23ff0000&tag=%23summer"), "hex color and hashtag")
clean(post("/api", '{"tags":["#post_render_tips"],"text":"#region callback"}', "application/json"), "JSON values mentioning the words")
clean(get("/products", "sort%5B%23price%5D=asc"), "an unrelated #key")
clean(post("/node/add/article", "title=Tip&body%5B0%5D%5Bvalue%5D=%24form%5B%27%23post_render%27%5D%5B%5D+%3D+%27my_callback%27%3B&form_id=node_article_form"),
      "a PHP code sample in a post ($form['#post_render'][] = ...)")
clean(post("/api", '{"body":"$form[\\"#post_render\\"][] = 1"}', "application/json"), "an escaped JSON string with the key")

-- The independent FP review (2026-11-18): the words as TEXT in a value, which
-- the first version (a plain find over the whole surface) blocked.
local function enc(x) return (x:gsub("[^%w%-_%.~]", function(c) return string.format("%%%02X", c:byte()) end)) end
local U = "application/x-www-form-urlencoded"
clean(get("/", "s=" .. enc('"#pre_render"')), "a quoted-phrase site search")
clean(get("/search/node", "keys=" .. enc('"#lazy_builder" cache')), "a quoted Drupal site search")
clean(post("/node/12/edit", "title=Render&body%5B0%5D%5Bvalue%5D=" .. enc('<pre>$build["#pre_render"][] = [static::class, "preRender"];</pre>') .. "&form_id=node_article_edit_form", U),
      "a double-quoted PHP sample in a node body")
clean(post("/comment/reply/5", "comment_body%5Bund%5D%5B0%5D%5Bvalue%5D=" .. enc('array("#access_callback" => "user_access")'), U),
      "a D7 sample in a comment")
clean(post("/node/add/article", table.concat({ "--b", 'Content-Disposition: form-data; name="body[0][value]"', "",
      '<pre>$build["#pre_render"][] = 1;</pre>', "--b--", "" }, "\r\n"), "multipart/form-data; boundary=b"),
      "a double-quoted sample in a multipart body")
clean(post("/wp-json/wp/v2/posts/5", '{"content":"## Contents\\n- [#pre_render](#pre_render)\\n"}', "application/json"),
      "a Markdown link in a JSON post")
clean(post("/index.php", "wpTextbox1=" .. enc("See [[#post_render]] below.") .. "&wpSave=Save", U), "a wiki section link")
clean(post("/api/save", '{"code":"$b[\\u0022#pre_render\\u0022] = 1;"}', "application/json"), "a \\u0022-escaped quote in a JSON value")
clean(post("/devel/php", "code=" .. enc('$b["#pre_render"][] = "x";'), U), "Devel execute PHP, double quotes")
clean(post("/admin/structure/webform/manage/contact/source", "elements=" .. enc('name:\n  "#type": textfield\n  "#pre_render":\n    - foo\n'), U),
      "Webform source YAML with double-quoted keys")
clean(post("/admin/structure/block/manage/x", "body%5Bvalue%5D=" .. enc('{{ content["#pre_render"] }}'), U), "a Twig sample")
clean(post("/node/1/edit", "body%5B0%5D%5Bvalue%5D=" .. enc('const el = {"#post_render": fn};'), U), "a JS object literal in prose")
clean(post("/wp-admin/admin-ajax.php", "action=elementor_ajax&actions=" .. enc('{"save":{"code":"$b[\\"#pre_render\\"]"}}'), U),
      "an escaped key inside a JSON field value")

if fails > 0 then
  io.stderr:write("\n" .. fails .. " check(s) failed in cfm_waf_cve_drupal_render_callback_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: rule 10030 Drupal render-array callback keys\n")
