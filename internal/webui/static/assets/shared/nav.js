// Shared sidebar navigation + theme toggle.
//
// Pages carry an empty <aside class="sidebar" data-shared-nav></aside>
// OUTSIDE any Vue mount point; this module fills it (brand, grouped links,
// theme toggle, logout) and wires the mobile burger + backdrop via document
// delegation so Vue re-renders can't detach the handlers.

const ICONS = {
  gauge: '<path d="M12 15l3.5-5.5"/><path d="M20.5 14a8.5 8.5 0 1 0-17 0"/><path d="M2 14h2m16 0h2"/>',
  radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12l6-6.5"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.7 2.6 4 5.7 4 9s-1.3 6.4-4 9c-2.7-2.6-4-5.7-4-9s1.3-6.4 4-9z"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.5-4.5"/>',
  shield: '<path d="M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6l7-3z"/>',
  ban: '<circle cx="12" cy="12" r="9"/><path d="M5.5 5.5l13 13"/>',
  sliders: '<path d="M4 7h10m4 0h2M4 12h2m4 0h10M4 17h10m4 0h2"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="12" r="2"/><circle cx="16" cy="17" r="2"/>',
  bot: '<rect x="5" y="8" width="14" height="11" rx="2"/><path d="M12 4v4M8 4h8"/><circle cx="9.5" cy="13" r="1"/><circle cx="14.5" cy="13" r="1"/>',
  db: '<ellipse cx="12" cy="5.5" rx="7" ry="2.5"/><path d="M5 5.5V18.5c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5V5.5"/><path d="M5 12c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5"/>',
  bell: '<path d="M6 9a6 6 0 1 1 12 0c0 5 2 6 2 6H4s2-1 2-6"/><path d="M10 19a2 2 0 0 0 4 0"/>',
  layers: '<path d="M12 3l9 5-9 5-9-5 9-5z"/><path d="M3 13l9 5 9-5"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3m0 14v3M2 12h3m14 0h3M4.9 4.9l2.1 2.1m10 10l2.1 2.1M19.1 4.9l-2.1 2.1m-10 10l-2.1 2.1"/>',
  bug: '<circle cx="12" cy="13" r="6"/><path d="M12 7V4m-5 3L5 5m12 2l2-2M3 13h3m12 0h3M5 20l2.5-2.5M19 20l-2.5-2.5"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5M21 12H9"/>',
  theme: '<path d="M12 3a9 9 0 1 0 9 9 7 7 0 0 1-9-9z"/>',
  pulse: '<path d="M3 12h4l2.5-7 5 14 2.5-7h4"/>',
  funnel: '<path d="M3 5h18l-7 8v5l-4 2v-7L3 5z"/>',
  virus: '<circle cx="12" cy="12" r="5"/><path d="M12 3v4m0 10v4M3 12h4m10 0h4M5.6 5.6l2.9 2.9m7 7l2.9 2.9M18.4 5.6l-2.9 2.9m-7 7l-2.9 2.9"/><circle cx="12" cy="12" r="1"/>',
  key: '<circle cx="8" cy="14" r="4"/><path d="M11 11l9-9m-4 4l3 3m-6 0l2 2"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
  pass: '<path d="M13 5l7 7-7 7"/><path d="M4 12h15"/><path d="M4 5v14"/>',
};

const MENU_GROUPS = [
  { title: "Overview", items: [
    { label: "Dashboard", href: "/cfm-admin/", icon: "gauge" },
    { label: "Health", href: "/cfm-admin/health/", icon: "pulse" },
  ]},
  { title: "Web protection", items: [
    { label: "WebDetector", href: "/cfm-admin/webdetector/", icon: "radar" },
    { label: "Vhost live", href: "/cfm-admin/webdetector/vhost/", icon: "globe" },
    { label: "Forensics", href: "/cfm-admin/webdetector/forensics/", icon: "search" },
    { label: "Web Bots", href: "/cfm-admin/webdetector/bots/", icon: "bot" },
  ]},
  { title: "Rules & engine", items: [
    { label: "Firewall", href: "/cfm-admin/firewall/", icon: "ban" },
    { label: "WAF engine", href: "/cfm-admin/webdetector/waf/", icon: "shield" },
    { label: "Vhost controls", href: "/cfm-admin/webdetector/controls/", icon: "sliders" },
    { label: "Traffic rules", href: "/cfm-admin/webdetector/rules/", icon: "funnel" },
    { label: "Challenge access", href: "/cfm-admin/webdetector/challenge-access/", icon: "pass" },
    { label: "ClamAV", href: "/cfm-admin/webdetector/clam/", icon: "virus" },
  ]},
  { title: "Services", items: [
    { label: "MySQL governor", href: "/cfm-admin/governor/", icon: "db" },
    { label: "Mail queue", href: "/cfm-admin/mail/", icon: "mail" },
    { label: "Mail Monitor", href: "/cfm-admin/mailmon/", icon: "pulse" },
    { label: "API tokens", href: "/cfm-admin/webdetector/tokens/", icon: "key" },
    { label: "Notifier", href: "/cfm-admin/notifier/", icon: "bell" },
    { label: "Detectors", href: "/cfm-admin/detectors/", icon: "layers" },
  ]},
  { title: "System", items: [
    { label: "Settings", href: "/cfm-admin/settings/", icon: "gear" },
    { label: "Debug", href: "/cfm-admin/debug/", icon: "bug" },
  ]},
];

const THEME_KEY = "cfm-theme";

function svgIcon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.innerHTML = ICONS[name] || "";
  return svg;
}

function normalizePathname(pathname) {
  if (!pathname) return "/";
  return pathname.endsWith("/") ? pathname : `${pathname}/`;
}

// Active item = the LONGEST href that prefixes the current path, so
// /webdetector/waf/ lights up "WAF engine" and not also "WebDetector".
function activeHref(pathname) {
  const path = normalizePathname(pathname);
  let best = null;
  for (const group of MENU_GROUPS) {
    for (const item of group.items) {
      const match = normalizePathname(item.href);
      if (path.startsWith(match) && (!best || match.length > best.length)) {
        best = match;
      }
    }
  }
  return best;
}

function makeItem(item, active) {
  const link = document.createElement("a");
  link.className = "nav-item";
  link.href = item.href;
  if (normalizePathname(item.href) === active) {
    link.classList.add("active");
    link.setAttribute("aria-current", "page");
  }
  link.appendChild(svgIcon(item.icon));
  link.appendChild(document.createTextNode(item.label));
  return link;
}

function currentTheme() {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem(THEME_KEY, theme); } catch { /* private mode */ }
  // Charts (and anything else color-derived) re-render on this.
  window.dispatchEvent(new CustomEvent("cfm-themechange", { detail: { theme } }));
}

function buildSidebar(root) {
  root.replaceChildren();

  const brand = document.createElement("div");
  brand.className = "sidebar-brand";
  brand.innerHTML = '<span class="mark">⬡</span><span class="name">CFM<span class="sub">Firewall Manager</span></span>';
  root.appendChild(brand);

  const nav = document.createElement("nav");
  nav.className = "sidebar-nav";
  const active = activeHref(window.location.pathname);
  for (const group of MENU_GROUPS) {
    const title = document.createElement("div");
    title.className = "nav-group-title";
    title.textContent = group.title;
    nav.appendChild(title);
    for (const item of group.items) nav.appendChild(makeItem(item, active));
  }
  root.appendChild(nav);

  const foot = document.createElement("div");
  foot.className = "sidebar-foot";

  const themeBtn = document.createElement("button");
  themeBtn.type = "button";
  themeBtn.className = "nav-item";
  const themeLabel = () => (currentTheme() === "dark" ? "Light theme" : "Dark theme");
  themeBtn.appendChild(svgIcon("theme"));
  const themeText = document.createTextNode(themeLabel());
  themeBtn.appendChild(themeText);
  themeBtn.addEventListener("click", () => {
    applyTheme(currentTheme() === "dark" ? "light" : "dark");
    themeText.nodeValue = themeLabel();
  });
  foot.appendChild(themeBtn);

  const logout = makeItem({ label: "Logout", href: "/cfm-admin/logout", icon: "logout" }, null);
  logout.classList.add("nav-danger");
  foot.appendChild(logout);
  root.appendChild(foot);
}

function ensureBackdrop() {
  if (!document.querySelector(".nav-backdrop")) {
    const bd = document.createElement("div");
    bd.className = "nav-backdrop";
    document.body.appendChild(bd);
  }
}

function initializeSharedNav() {
  document.querySelectorAll("[data-shared-nav]").forEach(buildSidebar);
  ensureBackdrop();
}

// Click-to-copy on IP/host <code> cells. Deliberately does NOT stop
// propagation: a row's click-through (e.g. drilldown) still happens.
const COPYABLE_RX = /^[0-9a-f.:]+$|^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;
let copyChip = null;
function showCopyChip(text, x, y) {
  if (!copyChip) {
    copyChip = document.createElement("div");
    copyChip.className = "copy-chip";
    document.body.appendChild(copyChip);
  }
  copyChip.textContent = `Copied ${text}`;
  copyChip.style.left = `${x + 10}px`;
  copyChip.style.top = `${y - 28}px`;
  copyChip.classList.add("show");
  window.clearTimeout(showCopyChip._t);
  showCopyChip._t = window.setTimeout(() => copyChip.classList.remove("show"), 1200);
}
document.addEventListener("click", (e) => {
  const code = e.target.closest("code");
  if (!code || e.target.closest("a,button,input,select")) return;
  const text = (code.textContent || "").trim();
  if (!text || text.length > 64 || !COPYABLE_RX.test(text)) return;
  navigator.clipboard?.writeText(text).then(() => showCopyChip(text, e.clientX, e.clientY)).catch(() => {});
});

// Burger + backdrop via delegation: survives Vue mounting over the topbar.
// The scope badge ("Global view") opens the palette — type a vhost to focus
// any page on it, which is what "switching scope" practically means here.
document.addEventListener("click", (e) => {
  if (e.target.closest("[data-nav-burger]")) {
    document.body.classList.toggle("nav-open");
  } else if (e.target.closest(".nav-backdrop") || e.target.closest(".sidebar a")) {
    document.body.classList.remove("nav-open");
  } else if (e.target.closest(".scoped-badge")) {
    if (openPalette) openPalette();
  }
});

// ── Quick search (Ctrl/Cmd+K) ────────────────────────────────────────────
// One palette on every page: type an IP → forensics/analyze actions for it;
// type a hostname → vhost live / forensics / controls / rules actions; or
// just fuzzy-jump to any page from the menu. Pure navigation, no API calls.

const IPV4_RX = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6_RX = /^[0-9a-f:]+:[0-9a-f:]*$/i;
const HOST_RX = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;

// Known vhosts for palette suggestions, fetched lazily when the palette
// first opens (cookie-authed; a scoped token's list is already scoped
// server-side). Failure just means no suggestions.
let knownVhosts = null;
let knownVhostsFetching = false;
function fetchKnownVhosts(onReady) {
  if (knownVhosts !== null || knownVhostsFetching) return;
  knownVhostsFetching = true;
  fetch("/cfm-admin/api/v1/webdet/vhosts", { credentials: "same-origin", headers: { Accept: "application/json" } })
    .then((res) => (res.ok ? res.json() : { rows: [] }))
    .then((data) => {
      const rows = Array.isArray(data) ? data : (data?.rows || []);
      knownVhosts = rows.map((r) => String(r?.host || "").trim()).filter(Boolean).sort();
    })
    .catch(() => { knownVhosts = []; })
    .finally(() => {
      knownVhostsFetching = false;
      if (typeof onReady === "function") onReady();
    });
}

function hostActions(host) {
  const h = encodeURIComponent(host);
  return [
    { label: `Vhost live: ${host}`, hint: "Live charts", href: `/cfm-admin/webdetector/vhost/?host=${h}` },
    { label: `History for ${host}`, hint: "Forensics", href: `/cfm-admin/webdetector/forensics/?host=${h}#history-card` },
    { label: `Controls for ${host}`, hint: "WAF / Challenge / HTTP3 / Clam", href: `/cfm-admin/webdetector/controls/?vhost=${h}` },
    { label: `Traffic rules for ${host}`, hint: "Rules filtered to this vhost", href: `/cfm-admin/webdetector/rules/?vhost=${h}` },
    { label: `ClamAV for ${host}`, hint: "Upload scanning / infections", href: `/cfm-admin/webdetector/clam/?vhost=${h}` },
  ];
}

function paletteActions(query) {
  const q = query.trim();
  const ql = q.toLowerCase();
  const out = [];
  if (q && IPV4_RX.test(q) || q && IPV6_RX.test(q) && q.includes(":")) {
    out.push(
      { label: `History for IP ${q}`, hint: "Forensics", href: `/cfm-admin/webdetector/forensics/?ip=${encodeURIComponent(q)}#history-card` },
      { label: `Analyze IP ${q}`, hint: "Forensics", href: `/cfm-admin/webdetector/forensics/?ip=${encodeURIComponent(q)}` },
      { label: `Firewall: is ${q} blocked?`, hint: "Check / unblock", href: `/cfm-admin/firewall/?q=${encodeURIComponent(q)}` },
    );
  } else if (q && HOST_RX.test(q)) {
    out.push(...hostActions(q));
  }
  // Real vhost suggestions: exact match expands to its actions (unless the
  // literal-hostname branch above already did), partial matches list up to 5.
  if (q && Array.isArray(knownVhosts) && knownVhosts.length) {
    const matches = knownVhosts.filter((h) => h.includes(ql));
    const exact = matches.find((h) => h === ql);
    if (exact && !HOST_RX.test(q)) out.push(...hostActions(exact));
    for (const h of matches.filter((m) => m !== ql).slice(0, 5)) {
      out.push({ label: h, hint: "vhost — open live", href: `/cfm-admin/webdetector/vhost/?host=${encodeURIComponent(h)}`, fill: h });
    }
  }
  for (const group of MENU_GROUPS) {
    for (const item of group.items) {
      if (!q || item.label.toLowerCase().includes(ql) || group.title.toLowerCase().includes(ql)) {
        out.push({ label: item.label, hint: group.title, href: item.href, icon: item.icon });
      }
    }
  }
  return out.slice(0, 12);
}

function buildPalette() {
  const backdrop = document.createElement("div");
  backdrop.className = "palette-backdrop";
  backdrop.innerHTML = `
    <div class="palette" role="dialog" aria-label="Quick search">
      <input class="palette-input" type="text" placeholder="Search pages, or type an IP / vhost…" autocomplete="off" spellcheck="false" />
      <div class="palette-list"></div>
      <div class="palette-foot"><kbd>↑↓</kbd> navigate · <kbd>Enter</kbd> open · <kbd>Esc</kbd> close</div>
    </div>`;
  document.body.appendChild(backdrop);
  const input = backdrop.querySelector(".palette-input");
  const list = backdrop.querySelector(".palette-list");
  let items = [];
  let active = 0;

  const render = () => {
    items = paletteActions(input.value);
    active = Math.min(active, Math.max(0, items.length - 1));
    list.replaceChildren();
    items.forEach((it, i) => {
      const row = document.createElement("a");
      row.className = "palette-item" + (i === active ? " active" : "");
      row.href = it.href;
      const l = document.createElement("span");
      l.textContent = it.label;
      const h = document.createElement("span");
      h.className = "palette-hint";
      h.textContent = it.hint || "";
      row.append(l, h);
      row.addEventListener("mouseenter", () => { active = i; render(); });
      list.appendChild(row);
    });
  };
  const open = (prefill = "") => {
    backdrop.classList.add("open");
    input.value = prefill;
    active = 0;
    fetchKnownVhosts(render);
    render();
    input.focus();
  };
  const close = () => backdrop.classList.remove("open");

  input.addEventListener("input", () => { active = 0; render(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); active = Math.min(active + 1, items.length - 1); render(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); active = Math.max(active - 1, 0); render(); }
    else if (e.key === "Enter" && items[active]) { window.location.href = items[active].href; }
    else if (e.key === "Escape") { close(); }
  });
  backdrop.addEventListener("mousedown", (e) => { if (e.target === backdrop) close(); });

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      if (backdrop.classList.contains("open")) close();
      else open();
    } else if (e.key === "Escape" && backdrop.classList.contains("open")) {
      close();
    }
  });
  return open;
}

let openPalette = null;
function initializePalette() {
  if (!openPalette) openPalette = buildPalette();
}

// Sidebar search button (below brand) so the palette is discoverable
// without knowing the shortcut.
function addSidebarSearch(root) {
  const nav = root.querySelector(".sidebar-nav");
  if (!nav) return;
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "nav-item nav-search";
  btn.appendChild(svgIcon("search"));
  btn.appendChild(document.createTextNode("Search"));
  const kbd = document.createElement("kbd");
  kbd.textContent = "Ctrl K";
  btn.appendChild(kbd);
  btn.addEventListener("click", () => openPalette && openPalette());
  nav.prepend(btn);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    initializeSharedNav();
    initializePalette();
    document.querySelectorAll("[data-shared-nav]").forEach(addSidebarSearch);
  }, { once: true });
} else {
  initializeSharedNav();
  initializePalette();
  document.querySelectorAll("[data-shared-nav]").forEach(addSidebarSearch);
}
