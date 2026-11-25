import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { MENU_GROUPS, UNLISTED_PAGES } from "./nav-menu.js";

const staticRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

// Every index.html under static/, as its /cfm-admin/ URL, split into real
// pages and the stubs a moved page leaves behind.
function pages() {
  const real = [], stubs = [];
  const walk = (dir, url) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) { if (name !== "assets") walk(p, url + name + "/"); continue; }
      if (name !== "index.html") continue;
      (readFileSync(p, "utf8").includes("location.replace(") ? stubs : real).push(url);
    }
  };
  walk(staticRoot, "/cfm-admin/");
  return { real: real.sort(), stubs: stubs.sort() };
}

const items = MENU_GROUPS.flatMap((g) => g.items);

test("the menu and the pages are the same set", () => {
  const { real, stubs } = pages();
  assert.ok(real.length > 10 && stubs.length > 0, "the walk found the pages and the stubs");
  const listed = new Set(items.map((i) => i.href));
  for (const url of real) {
    assert.ok(listed.has(url) || url in UNLISTED_PAGES, url + " is a page with no menu item: add it to a group, or to UNLISTED_PAGES with the reason");
  }
  for (const i of items) {
    assert.ok(real.includes(i.href), i.label + " points at " + i.href + ", which is " + (stubs.includes(i.href) ? "a stub that forwards" : "not a page"));
  }
  for (const url of Object.keys(UNLISTED_PAGES)) {
    assert.ok(real.includes(url), url + " is in UNLISTED_PAGES but is not a page");
    assert.ok(!listed.has(url), url + " is both in the menu and in UNLISTED_PAGES");
  }
});

test("no page twice, no label twice, every item complete", () => {
  const hrefs = new Set(), labels = new Set(), titles = new Set();
  for (const g of MENU_GROUPS) {
    assert.ok(g.title && !titles.has(g.title), "group " + g.title);
    titles.add(g.title);
    assert.ok(g.items.length > 0, g.title + " is empty");
    for (const i of g.items) {
      assert.ok(i.label && i.icon && /^\/cfm-admin\/([a-z0-9-]+\/)*$/.test(i.href), JSON.stringify(i));
      assert.ok(!hrefs.has(i.href), "twice: " + i.href);
      assert.ok(!labels.has(i.label), "twice: " + i.label);
      hrefs.add(i.href);
      labels.add(i.label);
    }
  }
});

test("every icon the menu names is drawn by nav.js", () => {
  const src = readFileSync(join(staticRoot, "assets", "shared", "nav.js"), "utf8");
  const start = src.indexOf("const ICONS = {");
  const block = src.slice(start, src.indexOf("};", start));
  for (const i of items) assert.match(block, new RegExp("\\n\\s*" + i.icon + ":"), i.label + " uses the icon " + i.icon);
});

// The scoped (cPanel) view hides the admin-only pages from the sidebar by
// looking the sidebar up with a selector. That selector once named an element
// a redesign had removed (".top-nav"), and for months nothing was hidden: a
// cPanel user saw every link and was bounced by the daemon on each.
test("the scoped view looks for the sidebar nav.js builds, and hides only pages that exist", () => {
  const boot = readFileSync(join(staticRoot, "assets", "shared", "controller-bootstrap.js"), "utf8");
  const nav = readFileSync(join(staticRoot, "assets", "shared", "nav.js"), "utf8");
  const sel = /navSelector = '\.([a-z-]+)'/.exec(boot);
  assert.ok(sel, "applyScopedChrome's default navSelector");
  assert.ok(nav.includes('nav.className = "' + sel[1] + '"'), "nav.js builds no element with the class " + sel[1]);

  const start = boot.indexOf("const ADMIN_ONLY_NAV_PATHS = new Set([");
  const paths = [...boot.slice(start, boot.indexOf("]);", start)).matchAll(/'(\/cfm-admin[^']*)'/g)].map((m) => m[1] + "/");
  assert.ok(paths.length > 5);
  const known = new Set([...items.map((i) => i.href), ...Object.keys(UNLISTED_PAGES)]);
  for (const p of paths) assert.ok(known.has(p), p + " is admin-only but is no page of the menu");
  // Something is left for a scoped user in the menu, and their landing page is in it.
  const left = items.filter((i) => !paths.includes(i.href)).map((i) => i.href);
  assert.ok(left.includes("/cfm-admin/webdetector/controls/"));
});
