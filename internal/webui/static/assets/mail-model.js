// /cfm-admin/assets/mail-model.js
//
// Pure model for the Mail page (assets/mail.js): which tabs and tables a
// viewer gets, and how the two reports behind the page are worded.
//
//   GET /api/v1/system/mail-queue          the live queue (admin only)
//   GET /api/v1/mail/traffic?hours=&limit= counters over a window (scope-aware:
//                                          a cPanel user gets its own domains)
//
// The page was two pages (Mail queue, Mail Monitor). What a scoped viewer may
// see is decided by the daemon; this model only keeps the page from asking
// for, or drawing a place for, what the daemon will not give them (the queue,
// the per-unix-user and per-provider tables). Tested in mail-model.test.js.

export const TABS = [
  { key: "queue", label: "Queue", adminOnly: true },
  { key: "outbound", label: "Outbound" },
  { key: "inbound", label: "Inbound & logins" },
];

export function tabsFor(scoped) {
  return TABS.filter((t) => !(scoped && t.adminOnly));
}

// pickTab: the tab to open for a requested key (?tab=). A key the viewer does
// not have (a scoped viewer following a link to the queue, a typo) opens the
// first tab they do have.
export function pickTab(requested, scoped) {
  const tabs = tabsFor(scoped);
  const want = String(requested || "").toLowerCase();
  return (tabs.find((t) => t.key === want) || tabs[0]).key;
}

export const WINDOWS = [
  { hours: 1, label: "1h" },
  { hours: 6, label: "6h" },
  { hours: 24, label: "24h" },
  { hours: 72, label: "3d" },
  { hours: 168, label: "7d" },
];
export const DEFAULT_HOURS = 24;

export function pickHours(v) {
  const n = parseInt(v, 10);
  return WINDOWS.some((w) => w.hours === n) ? n : DEFAULT_HOURS;
}

export function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

export function fmtNum(v) {
  return num(v).toLocaleString("en-US");
}

export function fmtAge(secs) {
  const n = num(secs);
  if (n <= 0) return "0s";
  if (n < 60) return Math.round(n) + "s";
  if (n < 3600) return Math.round(n / 60) + "m";
  if (n < 86400) return (n / 3600).toFixed(1) + "h";
  return (n / 86400).toFixed(1) + "d";
}

export function fmtSize(b) {
  const n = num(b);
  if (n >= 1048576) return (n / 1048576).toFixed(1) + "M";
  if (n >= 1024) return (n / 1024).toFixed(1) + "K";
  return n + "B";
}

// The queue report's age buckets, oldest last, each with its share of the
// messages the buckets hold (for the bar).
export const AGE_ORDER = ["<10m", "10m-1h", "1h-6h", "6h-1d", ">1d"];

export function ageBuckets(buckets) {
  const b = buckets && typeof buckets === "object" ? buckets : {};
  const counts = AGE_ORDER.map((k) => num(b[k]));
  const total = counts.reduce((a, c) => a + c, 0);
  return AGE_ORDER.map((label, i) => ({
    label,
    count: counts[i],
    pct: total > 0 ? Math.round((counts[i] / total) * 1000) / 10 : 0,
  }));
}

// TABLES: every table of the page. `src` is the report it reads ("queue" or
// "traffic"), `path` the list inside it. Column kinds: text (default), num,
// age, size, flag (a boolean shown as a pill). `wide` takes the whole row,
// `mid` two columns of the grid (a table of four columns does not fit one). `adminOnly` tables are not
// drawn for a scoped viewer: the daemon leaves their lists out for them, and
// an empty table would read as "nothing happened".
export const TABLES = [
  { key: "q_senders", tab: "queue", src: "queue", path: "top_senders", mid: true,
    title: "Who filled the queue", hint: "by sender address",
    cols: [{ h: "Sender", k: "sender" }, { h: "Total", k: "total", t: "num" }, { h: "Frozen", k: "frozen", t: "num" }, { h: "Deferred", k: "deferred", t: "num" }] },
  { key: "q_sender_domains", tab: "queue", src: "queue", path: "top_sender_domains",
    title: "Sender domains",
    cols: [{ h: "Domain", k: "domain" }, { h: "Messages", k: "count", t: "num" }] },
  { key: "q_rcpt_domains", tab: "queue", src: "queue", path: "top_recipient_domains",
    title: "Recipient domains", hint: "one provider holding most of the queue is usually that provider deferring us",
    cols: [{ h: "Domain", k: "domain" }, { h: "Messages", k: "count", t: "num" }] },
  { key: "q_reasons", tab: "queue", src: "queue", path: "defer_reasons", wide: true,
    title: "Why messages wait",
    cols: [{ h: "Count", k: "count", t: "num" }, { h: "Kind", k: "category" }, { h: "Reason", k: "reason" }] },
  { key: "q_oldest", tab: "queue", src: "queue", path: "oldest", wide: true,
    title: "Oldest messages",
    cols: [{ h: "Age", k: "age_sec", t: "age" }, { h: "Size", k: "size_bytes", t: "size" }, { h: "", k: "frozen", t: "flag", flag: "frozen" },
      { h: "Sender", k: "sender", empty: "<>" }, { h: "Rcpts", k: "recipients", t: "num" }, { h: "ID", k: "id" }] },

  { key: "t_out", tab: "outbound", src: "traffic", path: "top_outbound_senders",
    title: "Top senders", hint: "one far above the rest, especially to many domains, is the usual hacked mailbox",
    cols: [{ h: "Sender", k: "addr" }, { h: "Sent", k: "count", t: "num" }] },
  { key: "t_dom", tab: "outbound", src: "traffic", path: "most_sent_domains",
    title: "Most-sent domains",
    cols: [{ h: "Domain", k: "addr" }, { h: "Sent", k: "count", t: "num" }] },
  { key: "t_local", tab: "outbound", src: "traffic", path: "top_local_submitters", adminOnly: true,
    title: "Sent by scripts", hint: "PHP / cron through sendmail, by unix user",
    cols: [{ h: "Unix user", k: "addr" }, { h: "Submitted", k: "count", t: "num" }] },
  { key: "t_throttled", tab: "outbound", src: "traffic", path: "top_throttled",
    title: "Rate-limited senders",
    cols: [{ h: "Sender", k: "addr" }, { h: "Throttled", k: "count", t: "num" }] },
  { key: "t_prov", tab: "outbound", src: "traffic", path: "deliverability.by_provider", adminOnly: true, mid: true,
    title: "Delivery by provider", hint: "how the big providers treat this server's mail; deferred counts include retries",
    cols: [{ h: "Provider", k: "provider", empty: "(unknown)" }, { h: "Delivered", k: "delivered", t: "num" }, { h: "Deferred", k: "deferred", t: "num" }, { h: "Bounced", k: "bounced", t: "num" }] },
  { key: "t_reasons", tab: "outbound", src: "traffic", path: "deliverability.top_reasons", adminOnly: true, wide: true,
    title: "Why providers defer or bounce",
    cols: [{ h: "Count", k: "count", t: "num" }, { h: "Reason", k: "reason" }] },

  { key: "t_in", tab: "inbound", src: "traffic", path: "top_inbound_mailboxes",
    title: "Busiest mailboxes",
    cols: [{ h: "Mailbox", k: "addr" }, { h: "Received", k: "count", t: "num" }] },
  { key: "t_quota", tab: "inbound", src: "traffic", path: "top_over_quota",
    title: "Over-quota mailboxes", hint: "mail bounced because the mailbox is full",
    cols: [{ h: "Mailbox", k: "addr" }, { h: "Bounces", k: "count", t: "num" }] },
  { key: "t_auth", tab: "inbound", src: "traffic", path: "top_auth_failed",
    title: "Failed logins", hint: "the mailboxes being tried", adminHint: "the mailboxes being tried; attempts on names that are no mailbox are counted together under *",
    cols: [{ h: "Mailbox", k: "addr" }, { h: "Failures", k: "count", t: "num" }] },
];

export function tablesFor(tab, scoped) {
  return TABLES.filter((t) => t.tab === tab && !(scoped && t.adminOnly));
}

export function tableHint(def, scoped) {
  return (!scoped && def.adminHint) || def.hint || "";
}

function dig(obj, path) {
  let cur = obj;
  for (const p of String(path).split(".")) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = cur[p];
  }
  return cur;
}

// cell: one value as the page shows it. A flag cell is {flag} or empty.
export function cell(col, row) {
  const v = row == null ? undefined : row[col.k];
  switch (col.t) {
    case "num": return { text: fmtNum(v), num: true };
    case "age": return { text: fmtAge(v), num: true };
    case "size": return { text: fmtSize(v), num: true };
    case "flag": return v ? { text: col.flag || "yes", flag: true } : { text: "" };
    default: {
      const s = v == null ? "" : String(v);
      return { text: s === "" ? (col.empty || "") : s };
    }
  }
}

// SHOWN is how many rows a table shows until its "Show all" is pressed.
export const SHOWN = 8;

// tableView: the rows of one table from its report, clipped to SHOWN unless
// expanded. A report that carries no list for the table (an older daemon, a
// block left out) gives an empty table, never an error.
export function tableView(def, report, expanded) {
  const list = dig(report, def.path);
  const all = (Array.isArray(list) ? list : []).filter((r) => r && typeof r === "object");
  const shown = expanded ? all : all.slice(0, SHOWN);
  return {
    total: all.length,
    hidden: all.length - shown.length,
    rows: shown.map((r) => def.cols.map((c) => cell(c, r))),
  };
}

// anomalies: the "suspected compromise" rows (a sender far above its own
// history, or a new sender suddenly sending a lot).
export function anomalies(list) {
  return (Array.isArray(list) ? list : []).filter((a) => a && typeof a === "object").map((a) => {
    const isNew = a.kind === "new-sender";
    return {
      addr: a.addr == null ? "" : String(a.addr),
      signal: isNew ? "new sender" : "spike",
      recent: fmtNum(a.recent),
      baseline: isNew ? "—" : String(num(a.baseline_per_hour)),
      ratio: isNew ? "—" : num(a.ratio) + "×",
    };
  });
}

// A source is one of the two reports as the page holds it:
//   { state: "loading" | "ok" | "unavailable" | "error", data, note, error, at }
// "error" keeps the last good `data` (and its `at`), so the page can show it
// as old instead of blank; it is never shown as current.
export function hasData(src) {
  return !!(src && src.data && (src.state === "ok" || src.state === "error"));
}

// tiles: the numbers above the tabs. A number the page does not have is "—",
// never 0.
export function tiles(queue, traffic, scoped) {
  const out = [];
  const dash = "—";
  if (!scoped) {
    const q = hasData(queue) ? queue.data : null;
    out.push({
      key: "queue", label: "In queue now", tab: "queue",
      value: q ? fmtNum(q.total) : dash,
      sub: q ? fmtNum(q.frozen) + " frozen · " + fmtNum(q.deferred) + " deferred" : "",
    });
  }
  const t = hasData(traffic) ? (traffic.data.totals || {}) : null;
  const win = hasData(traffic) && traffic.data.window ? "last " + traffic.data.window : "";
  const add = (key, label, field, tab) => out.push({ key, label, tab, value: t ? fmtNum(t[field]) : dash, sub: win });
  add("outbound", "Sent", "outbound", "outbound");
  add("inbound", "Received", "inbound", "inbound");
  if (!scoped) {
    // Server-wide counters: the daemon gives a scoped viewer zeros for these.
    add("local", "Sent by scripts", "local_submit", "outbound");
    add("rejected", "Rejected", "rejected", "inbound");
  }
  add("throttled", "Rate-limited", "throttled", "outbound");
  add("over_quota", "Over quota", "over_quota", "inbound");
  add("auth_failed", "Failed logins", "auth_failed", "inbound");
  return out;
}

const UNAVAILABLE = {
  queue: "No queue report yet: the exim_queues / postfix_queues detector is off, or its first poll has not run.",
  traffic: "No mail counters yet: the mail-traffic collector is not on.",
};

function clock(at) {
  const d = at ? new Date(at) : null;
  return d && !Number.isNaN(d.getTime()) ? d.toLocaleTimeString() : "";
}

// sourceNote: what to say above a tab's tables about its report, or "" when
// the report is current. {text, bad}.
export function sourceNote(kind, src) {
  if (!src || src.state === "loading") return { text: "Loading…", bad: false };
  if (src.state === "unavailable") return { text: src.note || UNAVAILABLE[kind] || "Not available.", bad: false };
  if (src.state === "error") {
    const why = src.error || "request failed";
    const when = clock(src.at);
    return {
      text: src.data
        ? "Could not refresh (" + why + "). Showing the last read" + (when ? ", from " + when : "") + "."
        : "Could not load (" + why + ").",
      bad: true,
    };
  }
  return { text: "", bad: false };
}

// queueHeadline: the one-line summary of the queue report.
export function queueHeadline(rep) {
  if (!rep) return "";
  let s = (rep.mta || "MTA unknown") + " · " + fmtNum(rep.total) + " in queue · " + fmtNum(rep.frozen) + " frozen · " + fmtNum(rep.deferred) + " deferred";
  const when = clock(rep.measured_at);
  if (when) s += " · measured " + when;
  if (rep.truncated) s += " · listing cut short: the tables below count the first " + fmtNum(rep.parsed) + " messages";
  return s;
}

// trafficHeadline: window and whose mail the counters cover.
export function trafficHeadline(data, scoped) {
  if (!data) return "";
  const who = scoped || data.scope === "scoped" ? "your domains" : "whole server";
  return (data.window ? "last " + data.window + " · " : "") + who;
}
