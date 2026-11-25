// The cfm-admin menu: the ONE list of pages, read by the sidebar and by the
// quick search (nav.js). Grouped by what the operator is doing, not by which
// subsystem a page belongs to:
//
//   Overview  is the node all right
//   Web       what is happening on the sites, and what was stopped
//   Policy    what the node is told to do about it
//   Mail      the queue and the mail counters
//   System    the daemon's own settings and services
//
// nav-menu.test.js pins it to the pages that exist: a new page must be put in
// a group (or in UNLISTED_PAGES, with the reason), and a page that moves
// leaves a stub behind, never a menu item that forwards.
//
// `aka` holds names a page used to have (or the pages it absorbed): the quick
// search answers to them, the sidebar never shows them.
//
// Which of these a scoped (cPanel) user is not shown is decided elsewhere:
// ADMIN_ONLY_NAV_PATHS in controller-bootstrap.js.

export const MENU_GROUPS = [
  { title: "Overview", items: [
    { label: "Dashboard", href: "/cfm-admin/", icon: "gauge" },
    { label: "Health", href: "/cfm-admin/health/", icon: "pulse" },
    { label: "Alerts", href: "/cfm-admin/alerts/", icon: "bell" },
  ]},
  { title: "Web", items: [
    { label: "Traffic", href: "/cfm-admin/webdetector/traffic/", icon: "bot" },
    { label: "Protection", href: "/cfm-admin/webdetector/protection/", icon: "shield", aka: ["WAF log", "WAF engine", "Forensics"] },
    { label: "Vhosts", href: "/cfm-admin/webdetector/vhost/", icon: "globe", aka: ["Vhost live"] },
    { label: "WebDetector", href: "/cfm-admin/webdetector/", icon: "radar" },
  ]},
  { title: "Policy", items: [
    { label: "Vhost controls", href: "/cfm-admin/webdetector/controls/", icon: "sliders" },
    { label: "Traffic rules", href: "/cfm-admin/webdetector/rules/", icon: "funnel" },
    { label: "Exceptions", href: "/cfm-admin/webdetector/exceptions/", icon: "pass", aka: ["Excludes", "Challenge access"] },
    { label: "Site cache", href: "/cfm-admin/webdetector/site-cache/", icon: "bolt" },
    { label: "Firewall", href: "/cfm-admin/firewall/", icon: "ban" },
    { label: "ClamAV", href: "/cfm-admin/webdetector/clam/", icon: "virus" },
  ]},
  { title: "Mail", items: [
    { label: "Mail", href: "/cfm-admin/mail/", icon: "mail", aka: ["Mail queue", "Mail Monitor"] },
  ]},
  { title: "System", items: [
    { label: "Detectors", href: "/cfm-admin/detectors/", icon: "layers" },
    { label: "Notifier", href: "/cfm-admin/notifier/", icon: "bell" },
    { label: "MySQL governor", href: "/cfm-admin/governor/", icon: "db" },
    { label: "API tokens", href: "/cfm-admin/webdetector/tokens/", icon: "key" },
    { label: "Settings", href: "/cfm-admin/settings/", icon: "gear" },
    { label: "Debug", href: "/cfm-admin/debug/", icon: "bug" },
  ]},
];

// Pages that exist and are deliberately not in the menu.
export const UNLISTED_PAGES = {
  "/cfm-admin/webdetector/bots/": "the full UA console; reached from Traffic, which holds the everyday UA rules",
};
