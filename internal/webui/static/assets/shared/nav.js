const MENU_ITEMS = [
  { label: "Dashboard", href: "/cfm-admin/", match: "/cfm-admin/" },
  { label: "WebDetector", href: "/cfm-admin/webdetector/", match: "/cfm-admin/webdetector/" },
  { label: "Vhost live", href: "/cfm-admin/webdetector/vhost/", match: "/cfm-admin/webdetector/vhost/" },
  { label: "Forensics", href: "/cfm-admin/webdetector/forensics/", match: "/cfm-admin/webdetector/forensics/" },
  { label: "WAF engine", href: "/cfm-admin/webdetector/waf/", match: "/cfm-admin/webdetector/waf/" },
  { label: "Vhost controls", href: "/cfm-admin/webdetector/controls/", match: "/cfm-admin/webdetector/controls/" },
  { label: "MySQL governor", href: "/cfm-admin/governor/", match: "/cfm-admin/governor/" },
  { label: "Settings", href: "/cfm-admin/settings/", match: "/cfm-admin/settings/" },
  { label: "Debug", href: "/cfm-admin/debug/", match: "/cfm-admin/debug/" },
  { label: "Logout", href: "/cfm-admin/logout", match: "/cfm-admin/logout" },
];

function normalizePathname(pathname) {
  if (!pathname) return "/";
  return pathname.endsWith("/") ? pathname : `${pathname}/`;
}

function isActive(item, pathname) {
  if (item.href === "/cfm-admin/logout") {
    return pathname === "/cfm-admin/logout" || pathname === "/cfm-admin/logout/";
  }

  const normalizedPath = normalizePathname(pathname);
  const normalizedMatch = normalizePathname(item.match);

  if (item.href === "/cfm-admin/") {
    return normalizedPath === "/cfm-admin/";
  }

  return normalizedPath.startsWith(normalizedMatch);
}

function buildNav(navElement) {
  const pathname = window.location.pathname;

  MENU_ITEMS.forEach((item) => {
    const link = document.createElement("a");
    link.className = "btn-quiet";
    link.href = item.href;
    link.textContent = item.label;

    if (isActive(item, pathname)) {
      link.classList.add("btn-nav-active");
      link.setAttribute("aria-current", "page");
    }

    navElement.appendChild(link);
  });
}

function initializeSharedNav() {
  document.querySelectorAll("nav[data-shared-nav]").forEach((navElement) => {
    navElement.replaceChildren();
    buildNav(navElement);
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initializeSharedNav, { once: true });
} else {
  initializeSharedNav();
}
