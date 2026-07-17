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
  sliders: '<path d="M4 7h10m4 0h2M4 12h2m4 0h10M4 17h10m4 0h2"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="12" r="2"/><circle cx="16" cy="17" r="2"/>',
  bot: '<rect x="5" y="8" width="14" height="11" rx="2"/><path d="M12 4v4M8 4h8"/><circle cx="9.5" cy="13" r="1"/><circle cx="14.5" cy="13" r="1"/>',
  db: '<ellipse cx="12" cy="5.5" rx="7" ry="2.5"/><path d="M5 5.5V18.5c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5V5.5"/><path d="M5 12c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5"/>',
  bell: '<path d="M6 9a6 6 0 1 1 12 0c0 5 2 6 2 6H4s2-1 2-6"/><path d="M10 19a2 2 0 0 0 4 0"/>',
  layers: '<path d="M12 3l9 5-9 5-9-5 9-5z"/><path d="M3 13l9 5 9-5"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3m0 14v3M2 12h3m14 0h3M4.9 4.9l2.1 2.1m10 10l2.1 2.1M19.1 4.9l-2.1 2.1m-10 10l-2.1 2.1"/>',
  bug: '<circle cx="12" cy="13" r="6"/><path d="M12 7V4m-5 3L5 5m12 2l2-2M3 13h3m12 0h3M5 20l2.5-2.5M19 20l-2.5-2.5"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5M21 12H9"/>',
  theme: '<path d="M12 3a9 9 0 1 0 9 9 7 7 0 0 1-9-9z"/>',
};

const MENU_GROUPS = [
  { title: "Overview", items: [
    { label: "Dashboard", href: "/cfm-admin/", icon: "gauge" },
  ]},
  { title: "Web protection", items: [
    { label: "WebDetector", href: "/cfm-admin/webdetector/", icon: "radar" },
    { label: "Vhost live", href: "/cfm-admin/webdetector/vhost/", icon: "globe" },
    { label: "Forensics", href: "/cfm-admin/webdetector/forensics/", icon: "search" },
    { label: "Web Bots", href: "/cfm-admin/webdetector/bots/", icon: "bot" },
  ]},
  { title: "Rules & engine", items: [
    { label: "WAF engine", href: "/cfm-admin/webdetector/waf/", icon: "shield" },
    { label: "Vhost controls", href: "/cfm-admin/webdetector/controls/", icon: "sliders" },
  ]},
  { title: "Services", items: [
    { label: "MySQL governor", href: "/cfm-admin/governor/", icon: "db" },
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

// Burger + backdrop via delegation: survives Vue mounting over the topbar.
document.addEventListener("click", (e) => {
  if (e.target.closest("[data-nav-burger]")) {
    document.body.classList.toggle("nav-open");
  } else if (e.target.closest(".nav-backdrop") || e.target.closest(".sidebar a")) {
    document.body.classList.remove("nav-open");
  }
});

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initializeSharedNav, { once: true });
} else {
  initializeSharedNav();
}
