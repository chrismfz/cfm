// Vhost LOCKDOWN (internal/webdetector/vhost_lockdown.go) for cfm-admin: pure
// helpers, no Vue, tested by challenge-lockdown.test.js.
//
// A lockdown is an attribute of a MANUAL vhost challenge: while it holds,
// nothing gets past that vhost's challenge — no crawler bypass, no verified
// good bot, no exclude-file or Access-Control exemption. Crawlers cannot solve
// it, so they are shut out of the vhost; people solve it as on any challenged
// vhost. CDN fetchers (QUIC.cloud), /.well-known/, webhook endpoints, the
// server itself and already-cleared clients still pass. Default 30m, at most
// 6h (the daemon caps it), never past the challenge.
//
// The daemon reports it as lockdown / lockdown_until on v1/challenge/vhost/status
// and the challenge/vhosts rows, and as challenge_lockdown_until on the
// webdet/vhosts controls rows.

export const LOCKDOWN_TTL_CHOICES = [
  { value: "15m", label: "15 minutes" },
  { value: "30m", label: "30 minutes" },
  { value: "1h", label: "1 hour" },
  { value: "3h", label: "3 hours" },
  { value: "6h", label: "6 hours (max)" },
];

export const LOCKDOWN_HELP =
  "Lockdown: nothing gets past this vhost's challenge — no crawler bypass (Google, Bing, Apple, DuckDuckGo, Skroutz…), " +
  "no verified good bot, no exclude or Access-Control exemption. Crawlers can't solve a challenge, so they are shut out " +
  "of the vhost; people solve it as usual. Still pass: CDN fetchers (QUIC.cloud), /.well-known/ (SSL), webhook endpoints, " +
  "the server itself and visitors already cleared. Use it for a crawler storm, briefly: hours of locked-out crawlers cost " +
  "search ranking, so it ends on its own (at most 6h).";

// lockdownUntil: the lockdown expiry from a status object or a row, or null.
export function lockdownUntil(s) {
  const v = s?.lockdown_until ?? s?.challenge_lockdown_until;
  if (!v) return null;
  const t = new Date(v);
  return Number.isNaN(t.getTime()) ? null : t;
}

export function lockdownActive(s, now = Date.now()) {
  const t = lockdownUntil(s);
  return Boolean(t) && t.getTime() > now;
}

// lockdownLeft renders the time left ("23m", "1h05m"), "" when none.
export function lockdownLeft(s, now = Date.now()) {
  const t = lockdownUntil(s);
  if (!t) return "";
  const sec = Math.floor((t.getTime() - now) / 1000);
  if (sec <= 0) return "";
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (h > 0) return `${h}h${String(m).padStart(2, "0")}m`;
  return m > 0 ? `${m}m` : `${sec}s`;
}

export function lockdownLabel(s, now = Date.now()) {
  const left = lockdownLeft(s, now);
  return left ? `LOCKDOWN · ${left} left` : "";
}

// lockdownRequest is the ONE place a surface decides the call:
//   - lift            → vhost/lockdown {lockdown:false};
//   - armed manually  → vhost/lockdown {lockdown:true, ttl} in place (the
//                       challenge's expiry, reason and tier are kept);
//   - not armed       → vhost/add arming the challenge and the lockdown at
//                       once, for the lockdown's duration.
// status is a v1/challenge/vhost/status answer (manual_active).
export function lockdownRequest(host, status, on, ttl = "30m") {
  if (!on) return { path: "v1/challenge/vhost/lockdown", body: { host, lockdown: false } };
  if (status?.manual_active) return { path: "v1/challenge/vhost/lockdown", body: { host, lockdown: true, ttl } };
  return {
    path: "v1/challenge/vhost/add",
    body: { host, ttl, reason: "panic-lockdown", lockdown: true, lockdown_ttl: ttl },
  };
}
