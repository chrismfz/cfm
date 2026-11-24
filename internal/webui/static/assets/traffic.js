// /cfm-admin/assets/traffic.js
//
// Web Traffic page: who the node's web traffic is and what it costs the
// origin, with the actions an operator takes on it. Reads:
//
//   GET  /api/v1/webdet/traffic-mix?window=      the classes, series, top vhosts, top clients
//   GET  /api/v1/challenge/vhosts                which vhosts are under a challenge
//   GET  /api/v1/webdet/ua-emergency             active box-wide UA rules (cfm bots)
//   GET  /api/v1/webdet/rules                    the emergency traffic rules among them
//
// Acts (each one a click, never automatic):
//
//   POST /api/v1/challenge/ip/add                per-IP challenge on a client's top IPs
//   POST /api/v1/webdet/rules/add                emergency deny / throttle (an expiring traffic rule)
//   POST /api/v1/webdet/rules/update?id=         extend one
//   POST /api/v1/webdet/rules/remove?id=         end one now
//   DELETE /api/v1/webdet/ua-emergency?ua=       undo a cfm bots UA rule
//   POST /api/v1/challenge/vhost/remove          lift a vhost-wide challenge
//
// Which client is offered which action is traffic-model.js (clientActions)
// and emergency-model.js (targets, the rule payload), both tested: a browser
// UA is never a UA target. Every string from the API (UAs,
// hosts, IPs) is attacker-controlled and goes through escapeHTML; rows are
// addressed by index, never by putting a UA into an attribute.

import {
  CLASS_ORDER, CLASS_LABELS, CLASS_COLORS, OTHER_KEY,
  share, fmtPct, fmtCount, fmtBytes, fmtMbps, fmtRate, fmtSeconds,
  classMap, summary, segments, hostBotShare, topIPs, clientActions, challengeableIPs,
  CLIENT_SORTS, clientSort,
} from "./webdet/traffic-model.js";
import {
  EMERGENCY_DURATIONS, EMERGENCY_DEFAULT_SEC, uaPattern, ipTargets, targetsFor, currentRate,
  suggestTotalRate, throttleCut, buildEmergencyRule, extendedUntil, activeEmergencyRules, describeEmergency,
} from "./webdet/emergency-model.js";
import { THROTTLE_PROFILES } from "./webdet/rules-model.js";

(() => {
  const controller = window.CFMControllerBootstrap.initSharedController({});
  const api = controller.createApiClient({ basePath: "/cfm-admin/api", isScoped: () => false });

  const $ = (id) => document.getElementById(id);
  const el = {
    windowSelect: $("windowSelect"), autoState: $("autoState"), refreshBtn: $("refreshBtn"),
    toggleAutoBtn: $("toggleAutoBtn"), actionMsg: $("actionMsg"), windowNote: $("windowNote"),
    tiles: $("tiles"), legend: $("legend"), mixBars: $("mixBars"), mixNote: $("mixNote"),
    seriesChart: $("seriesChart"), clientsBody: $("clientsBody"), hostsBody: $("hostsBody"),
    rulesBody: $("rulesBody"), ipDialog: $("ipDialog"), ipDialogClient: $("ipDialogClient"),
    ipCount: $("ipCount"), ipTTL: $("ipTTL"), ipReason: $("ipReason"),
    ipDialogPreview: $("ipDialogPreview"), ipDialogApply: $("ipDialogApply"), ipDialogCancel: $("ipDialogCancel"),
    undoBtn: $("undoBtn"), emergBody: $("emergBody"),
    emDialog: $("emDialog"), emDialogTitle: $("emDialogTitle"), emDialogClient: $("emDialogClient"),
    emTarget: $("emTarget"), emIPCount: $("emIPCount"), emKind: $("emKind"), emRate: $("emRate"),
    emPer: $("emPer"), emProfile: $("emProfile"), emWhere: $("emWhere"), emVhosts: $("emVhosts"),
    emVhostList: $("emVhostList"), emDuration: $("emDuration"), emReason: $("emReason"),
    emPreview: $("emPreview"), emCaveat: $("emCaveat"), emApply: $("emApply"), emCancel: $("emCancel"),
  };
  // Rows of the emergency dialog, shown or hidden by the choices above them.
  const emRows = {
    ipCount: [$("emIPCountLabel"), el.emIPCount],
    kind: [$("emKindLabel"), el.emKind],
    rate: [$("emRateLabel"), $("emRateField")],
    per: [$("emPerLabel"), el.emPer],
    profile: [$("emProfileLabel"), el.emProfile],
    vhosts: [$("emVhostsLabel"), el.emVhosts],
  };

  const st = {
    auto: true, timer: null, mix: null, challenged: new Map(), rules: [], chart: null, dialogClient: null, busy: false,
    opener: null, lastIPs: [], undoTimer: null,
    trules: [], trulesLoaded: false, emClient: null, emAction: "", emOpener: null,
    sort: (() => { try { return clientSort(localStorage.getItem("cfm-traffic-sort")); } catch (e) { return clientSort(""); } })(),
  };

  const REFRESH_MS = 30000;

  function escapeHTML(s) {
    if (s == null) return "";
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function theme() {
    return document.documentElement.dataset.theme === "light" ? "light" : "dark";
  }
  function color(k) {
    return CLASS_COLORS[theme()][k];
  }

  function flash(text, kind) {
    if (!el.actionMsg) return;
    el.actionMsg.textContent = text;
    el.actionMsg.className = `pill ${kind || ""}`;
    el.actionMsg.style.display = "inline-block";
    clearTimeout(flash.t);
    flash.t = setTimeout(() => { el.actionMsg.style.display = "none"; }, 8000);
  }

  function swatch(k) {
    return `<span aria-hidden="true" style="display:inline-block;width:.7rem;height:.7rem;border-radius:3px;background:${color(k)};margin-right:.35rem;vertical-align:-1px"></span>`;
  }

  // A stacked bar of fractions in CLASS_ORDER, with a 2px surface gap.
  function bar(segs, height, label, withText) {
    const parts = segs.filter((s) => s.fraction > 0).map((s) => {
      const pct = (s.fraction * 100).toFixed(1);
      const text = withText && s.fraction >= 0.07 ? `${pct}%` : "";
      return `<div title="${escapeHTML(`${CLASS_LABELS[s.key]}: ${pct}%`)}" style="flex:${s.fraction} 1 0;min-width:2px;background:${color(s.key)};border-radius:4px;display:flex;align-items:center;padding:0 .4rem;overflow:hidden;white-space:nowrap;font-size:.75rem;font-weight:600;color:#0b1220">${text}</div>`;
    }).join("");
    const aria = segs.map((s) => `${CLASS_LABELS[s.key]} ${(s.fraction * 100).toFixed(1)}%`).join(", ");
    return `<div role="img" aria-label="${escapeHTML(`${label}: ${aria}`)}" style="display:flex;gap:2px;height:${height}px">${parts || '<div class="muted">no traffic</div>'}</div>`;
  }

  // ── render ────────────────────────────────────────────────────────────────

  function renderTiles(mix) {
    const s = summary(mix);
    const top = s.topClient;
    const tiles = [
      ["Origin time spent on bots", fmtPct(s.botOriginShare), `of ${fmtSeconds(s.originSec)} · requests: ${fmtPct(s.botRequestShare)} bots`],
      ["Biggest single client", top ? fmtPct(s.topClientOriginShare) : "—", top ? `${CLASS_LABELS[top.class] || top.class}: ${truncate(top.client, 60)}` : "no traffic"],
      ["Requests", fmtRate(s.rpsAvg), `${fmtCount(s.requests)} in the window`],
      ["Origin errors (5xx)", fmtPct(s.share5xx), "share of all requests"],
    ];
    el.tiles.innerHTML = tiles.map(([h, v, sub]) =>
      `<div class="summary-card"><h4>${escapeHTML(h)}</h4><div class="value" style="font-size:1.5rem;font-weight:700">${escapeHTML(v)}</div><div class="muted" style="font-size:.8rem">${escapeHTML(sub)}</div></div>`).join("");
  }

  function truncate(s, n) {
    s = String(s || "");
    return s.length > n ? `${s.slice(0, n - 1)}…` : s;
  }

  function renderMix(mix) {
    const cm = classMap(mix);
    el.legend.innerHTML = CLASS_ORDER.map((k) => `<span style="margin-right:1rem;white-space:nowrap">${swatch(k)}${escapeHTML(CLASS_LABELS[k])}</span>`).join("");
    const row = (label, field) => `<div style="display:grid;grid-template-columns:7rem minmax(0,1fr);gap:.6rem;align-items:center;margin:.5rem 0"><div class="muted">${escapeHTML(label)}</div>${bar(segments(cm, field), 30, label, true)}</div>`;
    el.mixBars.innerHTML = row("Requests", "requests") + row("Origin time", "origin_sec") + row("Traffic", "bytes");
    el.mixNote.textContent = (mix && mix.note) ? `Note: ${mix.note}.` : "";
  }

  function renderSeries(mix) {
    if (!window.CFMChartTheme || !window.echarts || !el.seriesChart) return;
    if (!st.chart) {
      st.chart = window.CFMChartTheme.initChart(el.seriesChart);
      window.addEventListener("resize", () => st.chart && st.chart.resize());
    }
    const pts = (mix && Array.isArray(mix.series)) ? mix.series : [];
    const xs = pts.map((p) => new Date(p.t * 1000));
    st.chart.setOption({
      tooltip: { trigger: "axis" },
      legend: { show: false },
      grid: { left: 50, right: 16, top: 16, bottom: 30 },
      xAxis: { type: "time" },
      yAxis: { type: "value", name: "requests / 5 min" },
      series: CLASS_ORDER.map((k) => ({
        name: CLASS_LABELS[k], type: "line", stack: "all", areaStyle: {}, showSymbol: false, lineStyle: { width: 2 },
        itemStyle: { color: color(k) }, color: color(k),
        data: pts.map((p, i) => [xs[i], Number((p.requests || {})[k] || 0)]),
      })),
    }, true);
  }

  function renderSortHeaders() {
    for (const b of document.querySelectorAll("button.th-sort[data-sort]")) {
      const on = b.getAttribute("data-sort") === st.sort;
      b.closest("th").setAttribute("aria-sort", on ? "descending" : "none");
    }
    const note = document.getElementById("clientsSortNote");
    if (note) note.textContent = `Top clients by ${CLIENT_SORTS[st.sort].label}.`;
  }

  function renderClients(mix) {
    renderSortHeaders();
    const list = (mix && Array.isArray(mix.clients)) ? mix.clients : [];
    const secs = Number(mix && mix.window_sec) || 1;
    const totalOrigin = Number(mix && mix.total && mix.total.origin_sec) || 0;
    if (!list.length) {
      el.clientsBody.innerHTML = '<tr><td colspan="7" class="muted">No traffic in this window yet.</td></tr>';
      return;
    }
    el.clientsBody.innerHTML = list.map((c, i) => {
      const name = c.client === OTHER_KEY ? "(everything else)" : c.client;
      const acts = clientActions(c).map((a) =>
        `<button type="button" class="${a.kind === "danger" ? "btn-sm btn-danger" : "btn-quiet btn-sm"}" data-act="${a.id}" data-i="${i}">${escapeHTML(a.label)}</button>`).join(" ");
      const ips = c.ips_last_hour ? fmtCount(c.ips_last_hour) : "—";
      const d = c.distributed;
      const tell = d ? ` <span class="pill warn" title="${escapeHTML(`The node's distributed tell (a label, nothing acts on it): this exact browser UA came from ${d.ips} addresses in the last hour, ${Number(d.req_per_ip).toFixed(1)} requests each, ${fmtPct(d.evidence_share)} of them static files / XHR / POST (real visitors: most). A scraper spread over residential proxies, under every per-IP limit.`)}">distributed: ${escapeHTML(fmtCount(d.ips))} IPs · ${escapeHTML(Number(d.req_per_ip).toFixed(1))}/IP · ${escapeHTML(fmtPct(d.evidence_share, 0))} static/XHR</span>` : "";
      return `<tr>
        <td><div style="font-weight:600">${swatch(c.class)}${escapeHTML(CLASS_LABELS[c.class] || c.class)}${tell}</div>
            <div class="muted" style="font-family:ui-monospace,monospace;font-size:.78rem;word-break:break-all">${escapeHTML(truncate(name, 200))}</div></td>
        <td>${escapeHTML(fmtCount(c.requests))}</td>
        <td>${escapeHTML(fmtRate(Number(c.requests || 0) / secs))}</td>
        <td>${escapeHTML(fmtBytes(c.bytes))}<div class="muted" style="font-size:.78rem">${escapeHTML(fmtMbps(c.bytes, secs))}</div></td>
        <td><strong>${escapeHTML(fmtPct(share(c.origin_sec, totalOrigin)))}</strong><div class="muted" style="font-size:.78rem">${escapeHTML(fmtSeconds(c.origin_sec))}</div></td>
        <td>${escapeHTML(ips)}</td>
        <td class="actions-cell">${acts || '<span class="muted">—</span>'}</td>
      </tr>`;
    }).join("");
  }

  function renderHosts(mix) {
    const list = (mix && Array.isArray(mix.hosts)) ? mix.hosts : [];
    if (!list.length) {
      el.hostsBody.innerHTML = '<tr><td colspan="6" class="muted">No vhost traffic in this window yet.</td></tr>';
      return;
    }
    el.hostsBody.innerHTML = list.map((h, i) => {
      const segs = segments(h.classes || {}, "origin_sec");
      const isOther = h.host === OTHER_KEY;
      const ch = st.challenged.get(String(h.host).toLowerCase());
      const pill = ch ? ` <span class="pill warn" title="${escapeHTML(`${ch.mode} vhost challenge: every visitor sees it`)}">vhost challenge (${escapeHTML(ch.mode)})</span>` : "";
      const acts = isOther ? "" : [
        `<a class="btn-quiet btn-sm" href="/cfm-admin/webdetector/vhost/?host=${encodeURIComponent(h.host)}">Live</a>`,
        ch && ch.mode === "manual" ? `<button type="button" class="btn-quiet btn-sm" data-lift="${i}">Lift vhost challenge</button>` : "",
      ].join(" ");
      return `<tr>
        <td>${escapeHTML(isOther ? "(other vhosts, summed)" : h.host)}${pill}</td>
        <td>${escapeHTML(fmtCount(h.total && h.total.requests))}</td>
        <td>${escapeHTML(fmtSeconds(h.total && h.total.origin_sec))}</td>
        <td>${bar(segs, 16, `${h.host} origin time`, false)}</td>
        <td><strong>${escapeHTML(fmtPct(hostBotShare(h)))}</strong></td>
        <td class="actions-cell">${acts}</td>
      </tr>`;
    }).join("");
  }

  function fmtExpiresIn(iso) {
    const ms = new Date(iso) - new Date();
    if (!Number.isFinite(ms) || ms <= 0) return "expired";
    const m = Math.round(ms / 60000);
    return m >= 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : `${m}m`;
  }

  function renderRules() {
    const list = Array.isArray(st.rules) ? st.rules : [];
    if (!list.length) {
      el.rulesBody.innerHTML = '<tr><td colspan="7" class="muted">No active UA rules.</td></tr>';
      return;
    }
    el.rulesBody.innerHTML = list.map((r, i) => `<tr>
      <td><strong>${escapeHTML(r.ua)}</strong></td><td>${escapeHTML(r.action)}</td>
      <td>${escapeHTML(fmtExpiresIn(r.expires_at))}</td><td>${escapeHTML(String(r.hits ?? 0))}</td>
      <td>${escapeHTML(r.created_by || "-")}</td><td>${escapeHTML(r.reason || "")}</td>
      <td><button type="button" class="btn-quiet btn-sm" data-undo="${i}">Undo</button></td></tr>`).join("");
  }

  function renderEmergency() {
    const list = activeEmergencyRules(st.trules);
    st.emList = list;
    if (!list.length) {
      el.emergBody.innerHTML = '<tr><td colspan="6" class="muted">No active emergency rules.</td></tr>';
      return;
    }
    el.emergBody.innerHTML = list.map((r, i) => {
      const d = describeEmergency(r);
      const ips = Array.isArray(r.match?.ip_any) ? r.match.ip_any : [];
      const what = ips.length ? `<span title="${escapeHTML(ips.slice(0, 50).join(", ") + (ips.length > 50 ? ", …" : ""))}">${escapeHTML(d.what)}</span>` : escapeHTML(d.what);
      return `<tr>
        <td><strong>${what}</strong></td><td>${escapeHTML(d.how)}${r.enabled ? "" : ' <span class="pill">off</span>'}</td>
        <td><code>${escapeHTML((r.scope?.vhosts || []).join(", "))}</code></td>
        <td>${escapeHTML(fmtExpiresIn(r.match.until))}</td>
        <td>${escapeHTML(String(r.note || "").replace(/^emergency:\s*/, ""))}</td>
        <td class="actions-cell"><button type="button" class="btn-quiet btn-sm" data-extend="${i}">+1 h</button>
          <button type="button" class="btn-quiet btn-sm btn-danger" data-end="${i}">End now</button></td></tr>`;
    }).join("");
  }

  function renderAll() {
    const mix = st.mix;
    if (!mix) return;
    const secs = Number(mix.window_sec) || 0;
    el.windowNote.textContent = secs ? ` Window shown: ${Math.round(secs / 60)} min, since ${new Date(mix.since * 1000).toLocaleTimeString()}.` : "";
    renderTiles(mix);
    renderMix(mix);
    renderSeries(mix);
    renderClients(mix);
    renderHosts(mix);
    renderRules();
    renderEmergency();
  }

  // ── load ──────────────────────────────────────────────────────────────────

  async function loadAll() {
    const win = el.windowSelect.value || "1h";
    // A reload started later (a new sort or window, the auto-refresh) wins:
    // an older answer arriving after it must not paint the old order under
    // the new header.
    const seq = (st.loadSeq = (st.loadSeq || 0) + 1);
    try {
      const [mix, vhosts, rules, trules] = await Promise.all([
        api(`/v1/webdet/traffic-mix?window=${encodeURIComponent(win)}&hosts=20&clients=25&sort=${encodeURIComponent(CLIENT_SORTS[st.sort].param)}`),
        api("/v1/challenge/vhosts").catch(() => []),
        api("/v1/webdet/ua-emergency").catch(() => []),
        api("/v1/webdet/rules").catch(() => null),
      ]);
      if (seq !== st.loadSeq) return;
      // A failed rules read keeps the last list (and its priorities) rather
      // than showing "none active".
      if (trules && Array.isArray(trules.rows)) { st.trules = trules.rows; st.trulesLoaded = true; }
      st.mix = mix;
      st.challenged = new Map();
      for (const v of Array.isArray(vhosts) ? vhosts : []) {
        if (v && v.status === "active" && v.host) st.challenged.set(String(v.host).toLowerCase(), v);
      }
      st.rules = Array.isArray(rules) ? rules : [];
      renderAll();
    } catch (err) {
      if (seq !== st.loadSeq) return;
      flash(`✖ could not load the traffic mix: ${err.message || err}`, "danger");
    }
  }

  function schedule() {
    clearTimeout(st.timer);
    if (st.auto) st.timer = setTimeout(async () => { await loadAll(); schedule(); }, REFRESH_MS);
  }

  // ── actions ───────────────────────────────────────────────────────────────

  function clientAt(i) {
    const list = (st.mix && Array.isArray(st.mix.clients)) ? st.mix.clients : [];
    return list[Number(i)] || null;
  }

  function updatePreview() {
    const c = st.dialogClient;
    if (!c) return;
    const n = Number(el.ipCount.value) || 50;
    const t = topIPs(c, n);
    const sp = challengeableIPs(t.ips);
    el.ipDialogPreview.innerHTML = `<strong>${escapeHTML(String(t.ips.length))}</strong> of the ${escapeHTML(fmtCount(t.total || t.known))} IPs seen in the last hour, carrying <strong>${escapeHTML(fmtPct(t.coverage))}</strong> of its last-hour requests.` +
      (sp.prefixes.length ? ` <span class="pill warn">${escapeHTML(String(sp.prefixes.length))} of them are IPv6 /64s</span>: a per-IP challenge cannot take a /64, so those are left out (Deny or Throttle can take them).` : "");
  }

  function openIPDialog(c, opener) {
    st.dialogClient = c;
    st.opener = opener || null;
    el.ipDialogClient.textContent = `${CLASS_LABELS[c.class] || c.class}: ${truncate(c.client, 240)}`;
    el.ipReason.value = "";
    updatePreview();
    el.ipDialog.style.display = "flex";
    el.ipCount.focus();
  }

  function closeIPDialog() {
    st.dialogClient = null;
    el.ipDialog.style.display = "none";
    if (st.opener && document.body.contains(st.opener)) st.opener.focus();
    st.opener = null;
  }

  // While the dialog is open: Escape closes it from anywhere, and Tab stays
  // inside it (the page behind holds UA block buttons).
  document.addEventListener("keydown", (ev) => {
    const dlg = el.ipDialog.style.display !== "none" ? el.ipDialog : el.emDialog.style.display !== "none" ? el.emDialog : null;
    if (!dlg) return;
    if (ev.key === "Escape") { ev.preventDefault(); (dlg === el.ipDialog ? closeIPDialog : closeEmergency)(); return; }
    if (ev.key !== "Tab") return;
    const f = [...dlg.querySelectorAll("button, select, input")].filter((x) => !x.disabled && x.offsetParent !== null);
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1];
    if (!dlg.contains(document.activeElement)) { ev.preventDefault(); first.focus(); }
    else if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
    else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
  });

  // Undo for the last per-IP challenge: lifts exactly the IPs it challenged.
  function offerUndo(ips) {
    st.lastIPs = ips.slice();
    clearTimeout(st.undoTimer);
    if (!st.lastIPs.length) { el.undoBtn.style.display = "none"; return; }
    el.undoBtn.textContent = `Undo (lift ${st.lastIPs.length} IP challenge${st.lastIPs.length === 1 ? "" : "s"})`;
    el.undoBtn.style.display = "inline-block";
    st.undoTimer = setTimeout(() => { el.undoBtn.style.display = "none"; }, 10 * 60 * 1000);
  }

  async function undoIPChallenge() {
    const ips = st.lastIPs;
    if (!ips.length) return;
    try {
      const r = await api("/v1/challenge/ip/remove", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ips, reason: "web traffic page: undo" }),
      });
      flash(`✓ lifted ${r.done ? r.done.length : 0} IP challenge(s)`, "ok");
      offerUndo([]);
    } catch (err) {
      flash(`✖ undo failed: ${err.message || err}`, "danger");
    }
  }

  async function applyIPChallenge() {
    const c = st.dialogClient;
    if (!c || st.busy) return;
    const t = topIPs(c, Number(el.ipCount.value) || 50);
    const sp = challengeableIPs(t.ips);
    if (!sp.ok.length) {
      flash("✖ every one of these is an IPv6 /64: use Deny or Throttle for them", "danger");
      return;
    }
    st.busy = true;
    try {
      const r = await api("/v1/challenge/ip/add", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ips: sp.ok,
          ttl_seconds: Number(el.ipTTL.value) || 3600,
          reason: el.ipReason.value.trim() || `web traffic: ${truncate(c.client, 80)}`,
        }),
      });
      const skipped = Array.isArray(r.skipped) ? r.skipped.length : 0;
      const extended = Array.isArray(r.extended) ? r.extended.length : 0;
      const kept = Array.isArray(r.revoked_kept) ? r.revoked_kept.length : 0;
      const notRevoked = Array.isArray(r.not_revoked) ? r.not_revoked.length : 0;
      let text = `✓ challenged ${r.done ? r.done.length : 0} IP(s)`;
      if (sp.prefixes.length) text += `; ${sp.prefixes.length} IPv6 /64(s) left out (not challengeable per IP)`;
      if (extended) text += `, extended ${extended} existing`;
      if (skipped) text += `, ${skipped} skipped (already challenged longer, blocked or never challenged here)`;
      if (kept) text += `. Undo will not restore the clearance of ${kept} already-challenged IP(s): it ends by itself at the chosen time`;
      if (notRevoked) text += `. ⚠ ${notRevoked} IP(s) kept their clearance (revocation list full): clients there that already solved still pass`;
      flash(text, notRevoked ? "warn" : "ok");
      // Undo lifts only the challenges this click set, never one it extended.
      offerUndo(Array.isArray(r.done) ? r.done : []);
      closeIPDialog();
    } catch (err) {
      flash(`✖ challenge failed: ${err.message || err}`, "danger");
    } finally {
      st.busy = false;
    }
  }

  // ── emergency deny / throttle ─────────────────────────────────────────────

  function show(rows, on) {
    for (const n of rows) if (n) n.style.display = on ? "" : "none";
  }

  function emVhosts() {
    if (el.emWhere.value === "*") return ["*"];
    return el.emVhosts.value.split(",").map((x) => x.trim()).filter(Boolean);
  }

  function emOpts() {
    return {
      client: st.emClient,
      target: el.emTarget.value,
      ipCount: Number(el.emIPCount.value) || 50,
      action: st.emAction === "deny" ? "block" : el.emKind.value,
      rate: Number(el.emRate.value),
      per: el.emPer.value,
      profile: el.emProfile.value,
      durationSec: Number(el.emDuration.value),
      vhosts: emVhosts(),
      reason: el.emReason.value,
      rules: st.trules,
    };
  }

  function updateEmergency() {
    const c = st.emClient;
    if (!c) return;
    const deny = st.emAction === "deny";
    const ips = el.emTarget.value === "ips";
    const total = !deny && el.emKind.value === "throttle_total";
    show(emRows.ipCount, ips);
    show(emRows.kind, !deny);
    show(emRows.rate, total);
    show(emRows.per, total);
    show(emRows.profile, !deny && !total);
    show(emRows.vhosts, el.emWhere.value === "list");

    const o = emOpts();
    // The slot is chosen against the node's rules: never without them.
    const built = st.trulesLoaded ? buildEmergencyRule(o) : { error: "The traffic rules could not be read yet (the slot is picked against them): Refresh now." };
    const secs = Number(st.mix && st.mix.window_sec) || 0;
    const rps = currentRate(c, secs);
    const parts = [];
    if (ips) {
      const n = ipTargets(c, o.ipCount).length;
      const t = topIPs(c, o.ipCount);
      parts.push(`<strong>${escapeHTML(String(n))}</strong> IPs, carrying ${escapeHTML(fmtPct(t.coverage))} of its last-hour requests.`);
    } else {
      parts.push(`Every request whose User-Agent matches <code>${escapeHTML(uaPattern(c))}</code>${el.emWhere.value === "*" ? ", on every vhost" : ""}.`);
    }
    if (total) {
      // The rate is the client's node-wide average: for the whole-node budget
      // the cut reads directly; per vhost each vhost gets the rate, so the cut
      // is at most this.
      const cut = fmtPct(throttleCut(rps, o.rate), 0);
      parts.push(`It averaged ${escapeHTML(fmtRate(rps))} over the ${escapeHTML(el.windowSelect.options[el.windowSelect.selectedIndex]?.text || "window")} shown, all vhosts together (a recent surge is higher: pick a shorter window for a closer figure). At ${escapeHTML(fmtRate(o.rate))} ${el.emPer.value === "node" ? "for the node" : "per vhost"}, about <strong>${el.emPer.value === "node" ? "" : "up to "}${escapeHTML(cut)}</strong> of it would get 429 (more in bursts).`);
    }
    if (built.error) parts.push(`<span class="pill danger">${escapeHTML(built.error)}</span>`);
    el.emPreview.innerHTML = parts.join(" ");
    el.emApply.disabled = !!built.error;

    const cav = [];
    if (deny && ips) cav.push("A deny returns 403 to everyone on those addresses: a real visitor behind the same carrier NAT or /64 is refused too. For residential addresses prefer the challenge.");
    if (ips) cav.push("A client that already solved a challenge keeps passing (its clearance cookie is honoured before any rule) until the cookie expires: for a solving farm, challenge its IPs first, which revokes their clearance.");
    if (deny && !ips) cav.push("Every client sending that User-Agent gets 403, on every IP.");
    if (!ips && c.class === "crawler") cav.push("A crawler whose IPs are on the static crawler bypass list (Google, Bing, Apple, DuckDuckGo, …) never reaches traffic rules: the rule will have no effect on it.");
    cav.push("The rule runs before your own rules on those vhosts (allows included) and ends by itself; end or extend it under Active emergency rules.");
    el.emCaveat.textContent = cav.join(" ");
  }

  function openEmergency(c, action, opener) {
    const targets = targetsFor(c);
    if (!targets.length) return;
    st.emClient = c;
    st.emAction = action;
    st.emOpener = opener || null;
    el.emDialogTitle.textContent = action === "deny" ? "Deny (403) for a while" : "Throttle for a while";
    el.emDialogClient.textContent = `${CLASS_LABELS[c.class] || c.class}: ${truncate(c.client, 240)}`;
    el.emTarget.innerHTML = targets.map((t) => `<option value="${t}">${t === "ua" ? `its User-Agent (${escapeHTML(uaPattern(c))})` : "its top IPs (last hour)"}</option>`).join("");
    el.emProfile.innerHTML = THROTTLE_PROFILES.map((p) => `<option value="${escapeHTML(p.key)}">${escapeHTML(p.label)}</option>`).join("");
    el.emDuration.innerHTML = EMERGENCY_DURATIONS.map((d) => `<option value="${d.sec}"${d.sec === EMERGENCY_DEFAULT_SEC ? " selected" : ""}>${escapeHTML(d.label)}</option>`).join("");
    el.emVhostList.innerHTML = ((st.mix && st.mix.hosts) || []).filter((h) => h.host !== OTHER_KEY).map((h) => `<option value="${escapeHTML(h.host)}"></option>`).join("");
    el.emKind.value = "throttle_total";
    el.emPer.value = "node";
    el.emWhere.value = "*";
    el.emVhosts.value = "";
    el.emReason.value = "";
    el.emRate.value = String(suggestTotalRate(currentRate(c, Number(st.mix && st.mix.window_sec) || 0)));
    el.emApply.textContent = action === "deny" ? "Deny" : "Throttle";
    el.emApply.className = action === "deny" ? "btn-danger" : "btn-quiet";
    el.emDialog.style.display = "flex";
    updateEmergency();
    el.emTarget.focus();
  }

  function closeEmergency() {
    st.emClient = null;
    el.emDialog.style.display = "none";
    if (st.emOpener && document.body.contains(st.emOpener)) st.emOpener.focus();
    st.emOpener = null;
  }

  async function applyEmergency() {
    if (!st.emClient || st.busy) return;
    if (!st.trulesLoaded) { flash("✖ the traffic rules could not be read yet: Refresh now", "danger"); return; }
    const built = buildEmergencyRule(emOpts());
    if (built.error) { flash(`✖ ${built.error}`, "danger"); return; }
    st.busy = true;
    try {
      const out = await api("/v1/webdet/rules/add", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(built.rule),
      });
      // Hold its slot until the list reloads: a second action made before
      // that must not pick the same priority.
      st.trules = [...st.trules, (out && out.rule) || built.rule];
      const d = describeEmergency(built.rule);
      flash(`✓ ${d.how}: ${d.what}, until ${new Date(built.rule.match.until).toLocaleTimeString()}`, "ok");
      closeEmergency();
    } catch (err) {
      flash(`✖ ${err.message || err}`, "danger");
    } finally {
      st.busy = false;
    }
    await loadAll();
  }

  async function extendEmergency(r) {
    if (!r) return;
    try {
      // Extend the rule as it is NOW (an edit made meanwhile in Traffic Rules
      // must not be reverted), changing only its until.
      const cur = await api(`/v1/webdet/rules/get?id=${encodeURIComponent(r.id)}`);
      const live = (cur && cur.rule) || r;
      const next = { ...live, match: { ...live.match, until: extendedUntil(live, 3600) } };
      await api(`/v1/webdet/rules/update?id=${encodeURIComponent(r.id)}`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(next),
      });
      flash(`✓ extended to ${new Date(next.match.until).toLocaleString()}`, "ok");
    } catch (err) {
      flash(`✖ ${err.message || err}`, "danger");
    }
    await loadAll();
  }

  async function endEmergency(r) {
    if (!r) return;
    const d = describeEmergency(r);
    if (!window.confirm(`End now: ${d.how} on ${d.what}?`)) return;
    try {
      await api(`/v1/webdet/rules/remove?id=${encodeURIComponent(r.id)}`, { method: "POST" });
      flash(`✓ ended: ${d.how} on ${d.what}`, "ok");
    } catch (err) {
      flash(`✖ ${err.message || err}`, "danger");
    }
    await loadAll();
  }

  async function liftVhost(h) {
    if (!h || !window.confirm(`Lift the manual challenge on ${h.host}? Its visitors stop seeing it.`)) return;
    try {
      await api("/v1/challenge/vhost/remove", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ host: h.host }),
      });
      flash(`✓ lifted the challenge on ${h.host}`, "ok");
    } catch (err) {
      flash(`✖ ${err.message || err}`, "danger");
    }
    await loadAll();
  }

  async function undoRule(r) {
    try {
      await api(`/v1/webdet/ua-emergency?ua=${encodeURIComponent(r.ua)}`, { method: "DELETE" });
      flash(`✓ undone ${r.ua}`, "ok");
    } catch (err) {
      flash(`✖ ${err.message || err}`, "danger");
    }
    await loadAll();
  }

  // ── wiring ────────────────────────────────────────────────────────────────

  for (const b of document.querySelectorAll("button.th-sort[data-sort]")) {
    b.addEventListener("click", () => {
      const next = clientSort(b.getAttribute("data-sort"));
      if (next === st.sort) return;
      st.sort = next;
      try { localStorage.setItem("cfm-traffic-sort", next); } catch (e) { /* per-viewer convenience only */ }
      renderSortHeaders();
      loadAll();
    });
  }
  el.clientsBody.addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-act]");
    if (!btn) return;
    const c = clientAt(btn.getAttribute("data-i"));
    if (!c) return;
    const act = btn.getAttribute("data-act");
    if (act === "challenge_ips") openIPDialog(c, btn);
    else if (act === "throttle") openEmergency(c, "throttle", btn);
    else if (act === "deny") openEmergency(c, "deny", btn);
  });
  el.emergBody.addEventListener("click", (ev) => {
    const ext = ev.target.closest("button[data-extend]");
    if (ext) { extendEmergency((st.emList || [])[Number(ext.getAttribute("data-extend"))]); return; }
    const end = ev.target.closest("button[data-end]");
    if (end) endEmergency((st.emList || [])[Number(end.getAttribute("data-end"))]);
  });
  for (const n of [el.emTarget, el.emIPCount, el.emKind, el.emRate, el.emPer, el.emProfile, el.emWhere, el.emVhosts, el.emDuration]) {
    n.addEventListener("input", updateEmergency);
    n.addEventListener("change", updateEmergency);
  }
  el.emApply.addEventListener("click", applyEmergency);
  el.emCancel.addEventListener("click", closeEmergency);
  el.emDialog.addEventListener("click", (ev) => { if (ev.target === el.emDialog) closeEmergency(); });
  el.hostsBody.addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-lift]");
    if (!btn) return;
    const list = (st.mix && Array.isArray(st.mix.hosts)) ? st.mix.hosts : [];
    liftVhost(list[Number(btn.getAttribute("data-lift"))]);
  });
  el.rulesBody.addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-undo]");
    if (btn) undoRule(st.rules[Number(btn.getAttribute("data-undo"))]);
  });
  el.ipCount.addEventListener("change", updatePreview);
  el.ipDialogApply.addEventListener("click", applyIPChallenge);
  el.ipDialogCancel.addEventListener("click", closeIPDialog);
  el.ipDialog.addEventListener("click", (ev) => { if (ev.target === el.ipDialog) closeIPDialog(); });
  el.undoBtn.addEventListener("click", undoIPChallenge);
  el.windowSelect.addEventListener("change", loadAll);
  el.refreshBtn.addEventListener("click", loadAll);
  el.toggleAutoBtn.addEventListener("click", () => {
    st.auto = !st.auto;
    el.autoState.textContent = st.auto ? "ON" : "OFF";
    el.toggleAutoBtn.textContent = st.auto ? "Stop" : "Start";
    schedule();
  });
  window.addEventListener("cfm-themechange", () => {
    if (st.chart) { st.chart.dispose(); st.chart = null; }
    renderAll();
  });

  loadAll().then(schedule);
})();
