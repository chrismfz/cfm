// Protection page: what the edge stopped and why.
//
//   WAF log   GET v1/waf/engine/summary       grouped by rule / address / vhost;
//                                             opening a group asks for its requests
//   Events    GET v1/webdet/history/events    every event, newest first, paged
//   Overview  the WAF summary's totals and hourly bars, plus (admin only)
//             GET v1/webdet/traffic-mix       the edge outcomes
//
// Both history endpoints answer a scoped (cPanel) caller for its own vhosts,
// so this page serves them too: the vhost filter is then one of theirs, and
// the admin-only parts (edge outcomes, the rule-scoped path exclude) are
// left out. Wording and queries live in protection-model.js (tested).
//
// Every address opens the same panel: who it is (country, ASN, PTR), what
// the WAF and the challenge did with it, and the narrowest exclude that
// would have let a request through.

import * as M from "./protection-model.js";
import { analyzeMixin } from "./feature-forensics.js";
import { fmtCount, fmtPct, outcomeSummary, outcomeLine, OUTCOMES } from "./traffic-model.js";

export const protectionMixin = {
  // The analyze-ip / analyze-host tools (the Tools tab) keep their own mixin:
  // the WebDetector page uses the same one.
  mixins: [analyzeMixin],
  data() {
    let t = M.DEFAULT_TAB, host = "", ip = "", linked = "";
    try {
      const u = new URL(window.location.href);
      host = String(u.searchParams.get("host") || "").trim().toLowerCase();
      ip = String(u.searchParams.get("ip") || "").trim();
      // A link to one address opens where that address filters: its events.
      t = M.tab(u.searchParams.get("tab") || (ip ? "events" : ""));
      // The address goes where the link points: the Tools tab runs its
      // analysis for it (once), the Events tab filters by it. Never both: a
      // link to its events must not start a log analysis on a later click.
      if (t === "tools") linked = ip;
      if (t !== "events") ip = "";
    } catch { /* no URL */ }
    return {
      ptTab: t,
      ptHours: 24,
      ptHost: host,
      ptGroupBy: M.DEFAULT_GROUPING,
      ptFilters: { rule: "", ip: "", country: "" },
      ptSummary: null,
      ptSummaryError: "",
      ptSeq: 0,
      ptOpenKey: "",
      ptOpen: null,
      ptOpenSeq: 0,
      ptEvents: [],
      ptEventsError: "",
      ptEventType: "",
      ptEventIP: ip,
      ptOnlyImpossibleUA: false,
      ptStore: null,
      ptStoreBusy: false,
      ptLinkedIP: linked,
      ptEventsSummary: null,
      ptEventCursors: [], // the cursors of the pages before this one (for "Newer")
      ptEventCursor: null,
      ptEventNext: null,
      ptEventSeq: 0,
      ptMix: null,
      ptPanelIP: "",
      ptPanel: null,
      ptPanelSeq: 0,
      ptNow: Date.now(),
    };
  },

  computed: {
    ptTabs() { return M.tabsFor({ scoped: this.isScoped }); },
    // "impossible UA only" narrows the page shown, as the Forensics page did.
    ptEventTotals() { return M.eventsSummary(this.ptEventsSummary); },
    ptEventsShown() { return this.ptOnlyImpossibleUA ? this.ptEvents.filter((e) => M.impossibleUA(e)) : this.ptEvents; },
    ptWindows() { return M.WINDOWS; },
    ptGroupings() { return Object.entries(M.GROUPINGS).map(([key, g]) => ({ key, label: g.label })); },
    ptGroupHead() { return M.GROUPINGS[M.grouping(this.ptGroupBy)].head; },
    // The WAF summary scopes itself to a scoped caller's vhosts: only the
    // vhost the operator typed narrows it.
    ptAllFilters() { return { host: this.ptHost, ...this.ptFilters }; },
    ptActiveFilters() { return M.activeFilters({ host: this.ptHost, ...this.ptFilters }); },
    // The event history refuses a scoped caller without a vhost: theirs
    // defaults to the first one they hold.
    ptEffectiveHost() {
      const h = String(this.ptHost || "").trim().toLowerCase();
      if (h || !this.isScoped) return h;
      return this.allowedVhosts.find((v) => v && !/[*?]/.test(v)) || "";
    },
    ptGroups() { return M.groupRows(this.ptSummary, this.ptGroupBy); },
    ptTopN() { return M.GROUPINGS[M.grouping(this.ptGroupBy)].n; },
    ptGroupsNote() { return M.groupsNote(this.ptSummary, this.ptGroupBy, this.ptTopN); },
    // The endpoint sends rows: null when nothing matches (a group that aged
    // out of the window between the two requests): always a list here.
    ptOpenRows() { return (this.ptOpen && this.ptOpen.summary && Array.isArray(this.ptOpen.summary.rows)) ? this.ptOpen.summary.rows : []; },
    ptPanelRows() { return (this.ptPanel && this.ptPanel.waf && Array.isArray(this.ptPanel.waf.rows)) ? this.ptPanel.waf.rows : []; },
    ptPanelLiveHosts() { return (this.ptPanel && this.ptPanel.live && Array.isArray(this.ptPanel.live.hosts)) ? this.ptPanel.live.hosts.slice(0, 8) : []; },
    ptPanelRules() { return (this.ptPanel && this.ptPanel.waf && Array.isArray(this.ptPanel.waf.top_rule_bases)) ? this.ptPanel.waf.top_rule_bases : []; },
    ptTiles() { return M.wafTiles(this.ptSummary); },
    ptHist() { return M.histBars(this.ptSummary); },
    ptEventTypes() { return M.EVENT_TYPES; },
    ptOutcome() { return outcomeSummary(this.ptMix && this.ptMix.total && this.ptMix.total.outcomes); },
    ptOutcomeLine() { return outcomeLine(this.ptOutcome); },
    ptOutcomeStops() {
      const o = this.ptOutcome;
      if (!o) return [];
      const max = o.segments.filter((s) => OUTCOMES.find((x) => x.key === s.key).stop).reduce((m, s) => Math.max(m, s.value), 0);
      return o.segments.filter((s) => OUTCOMES.find((x) => x.key === s.key).stop)
        .map((s) => ({ ...s, width: max > 0 ? s.value / max : 0 }));
    },
    ptMixWindow() { return M.windowOf(this.ptHours).mix; },
    ptPanelWho() {
      const top = this.ptPanel && this.ptPanel.waf && Array.isArray(this.ptPanel.waf.top_ips) ? this.ptPanel.waf.top_ips[0] : null;
      if (top) return M.whoLine(top);
      const ev = this.ptPanel && this.ptPanel.events && this.ptPanel.events[0];
      return ev ? M.whoLine(ev) : "";
    },
  },

  methods: {
    ptCount: fmtCount,
    ptPct: (v) => fmtPct(v, 0),
    ptAge(ts) { return M.age(ts, this.ptNow); },
    ptTier: M.tier,
    ptTierTone: M.tierTone,
    ptEventLabel: M.eventLabel,
    ptEventTone: M.eventTone,
    ptEventDetail: M.eventDetail,
    ptWho: M.whoLine,
    ptExceptionsURL: M.exceptionsURL,
    ptImpossibleUA: M.impossibleUA,
    ptSolveTime: M.solveTime,
    ptEventUA: M.eventUA,
    ptBytes(n) {
      const v = Number(n) || 0;
      return v >= 1048576 ? (v / 1048576).toFixed(1) + " MB" : Math.round(v / 1024) + " KB";
    },
    ptPath: M.uriPath,
    ptExcludeOffer(row) { return M.excludeOffer(row, { scoped: this.isScoped }); },
    ptTime(ts) {
      const d = new Date(Number(ts || 0) * 1000);
      return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
    },

    // refreshProtection is the page's hook in core.js refreshAll.
    async refreshProtection() {
      this.ptNow = Date.now();
      // A scoped session never holds the admin tab (a link may name it).
      if (!this.ptTabs.some((t) => t.key === this.ptTab)) this.ptTab = M.DEFAULT_TAB;
      if (this.ptTab === "events") return this.ptLoadEvents();
      if (this.ptTab === "tools") return this.ptLoadStore();
      await this.ptLoadSummary();
      if (this.ptTab === "overview") await this.ptLoadMix();
    },

    async ptLoadSummary() {
      const seq = ++this.ptSeq;
      const url = M.wafQuery({ hours: this.ptHours, limit: 500, top: this.ptTopN, filters: this.ptAllFilters, enrich: M.GROUPINGS[M.grouping(this.ptGroupBy)].enrich });
      try {
        const res = await this.fetchJSON(url);
        if (seq !== this.ptSeq) return; // a newer request is on its way
        this.ptSummary = res;
        this.ptSummaryError = "";
      } catch (err) {
        if (seq !== this.ptSeq) return;
        // A failed read is an error, never an empty log.
        this.ptSummary = null;
        this.ptSummaryError = `The WAF log could not be read: ${this.formatApiError(err)}`;
      }
      if (this.ptOpenKey) await this.ptLoadGroup(this.ptOpenKey);
    },

    async ptLoadGroup(key) {
      const seq = ++this.ptOpenSeq;
      const g = M.GROUPINGS[M.grouping(this.ptGroupBy)];
      const filters = { ...this.ptAllFilters, [g.param]: key };
      try {
        const res = await this.fetchJSON(M.wafQuery({ hours: this.ptHours, limit: 50, top: 5, filters, enrich: true }));
        if (seq !== this.ptOpenSeq || this.ptOpenKey !== key) return;
        this.ptOpen = { key, summary: res, error: "" };
      } catch (err) {
        if (seq !== this.ptOpenSeq || this.ptOpenKey !== key) return;
        this.ptOpen = { key, summary: null, error: this.formatApiError(err) };
      }
    },

    async ptToggleGroup(key) {
      if (this.ptOpenKey === key) { this.ptOpenKey = ""; this.ptOpen = null; return; }
      this.ptOpenKey = key;
      this.ptOpen = null;
      await this.ptLoadGroup(key);
    },

    async ptLoadMix() {
      if (this.isScoped || !this.ptMixWindow) { this.ptMix = null; return; }
      const host = this.ptHost;
      this.ptMix = await this.fetchJSONSafe(`v1/webdet/traffic-mix?window=${this.ptMixWindow}&hosts=1&clients=1${host ? `&host=${encodeURIComponent(host)}` : ""}`, null);
    },

    async ptLoadEvents() {
      const seq = ++this.ptEventSeq;
      if (this.isScoped && !this.ptEffectiveHost) {
        this.ptEvents = [];
        this.ptEventsError = "Pick one of your vhosts to list its events.";
        return;
      }
      const url = M.eventsQuery({ host: this.ptEffectiveHost, ip: this.ptEventIP, type: this.ptEventType, cursor: this.ptEventCursor });
      // The window's totals for the same vhost and address: they do not
      // depend on the page, so they are asked with the first one only.
      if (!this.ptEventCursor) {
        this.fetchJSONSafe(M.eventsSummaryQuery({ hours: this.ptHours, host: this.ptEffectiveHost, ip: this.ptEventIP }), null)
          .then((s) => { if (seq === this.ptEventSeq) this.ptEventsSummary = s; });
      }
      try {
        const res = await this.fetchJSON(url);
        if (seq !== this.ptEventSeq) return;
        this.ptEvents = this.extractRows(res);
        this.ptEventNext = M.nextCursor(res);
        this.ptEventsError = "";
      } catch (err) {
        if (seq !== this.ptEventSeq) return;
        this.ptEvents = [];
        this.ptEventNext = null;
        this.ptEventsError = `The events could not be read: ${this.formatApiError(err)}`;
      }
    },

    // ── Tools (admin) ────────────────────────────────────────────────────
    async ptLoadStore() {
      if (this.isScoped) return;
      this.ptStore = await this.fetchJSONSafe("v1/webdet/history/stats", null);
      // A link that named an address (the palette's "Analyze IP", the
      // WebDetector page's Analyze button) runs the tool for it, once.
      if (this.ptLinkedIP) {
        const addr = this.ptLinkedIP;
        this.ptLinkedIP = "";
        await this.analyzeIP(addr);
      }
    },
    async ptPruneHistory(days) {
      if (!window.confirm("Delete history events older than " + days + " days?")) return;
      this.ptStoreBusy = true;
      try {
        await this.postJSON("v1/webdet/history/prune?days=" + encodeURIComponent(days), {});
        this.actionMsg = "History pruned (older than " + days + " days)";
      } catch (err) {
        this.actionMsg = "History prune failed: " + this.formatApiError(err);
      } finally {
        this.ptStoreBusy = false;
      }
      await this.ptLoadStore();
    },
    async ptTruncateHistory() {
      if (!window.confirm("Delete ALL history events? The WAF log and the events of every vhost go with them. This cannot be undone.")) return;
      this.ptStoreBusy = true;
      try {
        await this.postJSON("v1/webdet/history/truncate?confirm=yes", {});
        this.actionMsg = "History truncated";
      } catch (err) {
        this.actionMsg = "History truncate failed: " + this.formatApiError(err);
      } finally {
        this.ptStoreBusy = false;
      }
      await this.ptLoadStore();
    },
    async ptAnalyzeIP(ip) {
      const addr = String(ip || "").trim();
      this.ptCloseIP();
      if (!addr) return;
      await this.ptSetTab("tools");
      await this.analyzeIP(addr);
    },

    ptResetEvents() { this.ptEventCursors = []; this.ptEventCursor = null; this.ptEventNext = null; },
    async ptEventsOlder() {
      if (!this.ptEventNext) return;
      this.ptEventCursors.push(this.ptEventCursor);
      this.ptEventCursor = this.ptEventNext;
      await this.ptLoadEvents();
    },
    async ptEventsNewer() {
      if (!this.ptEventCursors.length) return;
      this.ptEventCursor = this.ptEventCursors.pop();
      await this.ptLoadEvents();
    },
    async ptSetEventType(key) {
      this.ptEventType = M.eventType(key);
      this.ptResetEvents();
      await this.ptLoadEvents();
    },

    // Any change of what is asked resets what was opened and paged.
    async ptReload() {
      this.ptOpenKey = "";
      this.ptOpen = null;
      this.ptResetEvents();
      await this.refreshProtection();
    },
    async ptSetTab(key) {
      this.ptTab = M.tab(key);
      try {
        const u = new URL(window.location.href);
        u.searchParams.set("tab", this.ptTab);
        window.history.replaceState(null, "", `${u.pathname}${u.search}`);
      } catch { /* no history */ }
      await this.refreshProtection();
    },
    async ptSetGroup(key) {
      this.ptGroupBy = M.grouping(key);
      await this.ptReload();
    },
    async ptSetFilter(key, value) {
      const v = String(value || "").trim();
      if (key === "host") this.ptHost = v.toLowerCase();
      else if (key in this.ptFilters) this.ptFilters[key] = v;
      await this.ptReload();
    },
    async ptClearFilter(key) { await this.ptSetFilter(key, ""); },

    // ── the address panel ────────────────────────────────────────────────
    async ptOpenIP(ip, opener) {
      const addr = String(ip || "").trim();
      if (!addr) return;
      const seq = ++this.ptPanelSeq;
      this._ptOpener = opener || null;
      this.ptPanelIP = addr;
      this.ptPanel = null;
      const host = this.ptEffectiveHost;
      const waf = this.fetchJSONSafe(M.wafQuery({ hours: this.ptHours, limit: 20, top: 5, filters: { host: this.ptHost, ip: addr }, enrich: true }), null);
      // A scoped caller's events need a vhost; an admin's list every vhost.
      const events = (this.isScoped && !host)
        ? Promise.resolve(null)
        : this.fetchJSONSafe(M.eventsQuery({ host: this.isScoped ? host : "", ip: addr }), null);
      // Admin only: what the address is doing right now (the short window).
      const live = this.isScoped ? Promise.resolve(null) : this.fetchJSONSafe("v1/webdet/ip-drilldown?ip=" + encodeURIComponent(addr), null);
      const [w, e, l] = await Promise.all([waf, events, live]);
      if (seq !== this.ptPanelSeq) return;
      this.ptPanel = { waf: w, events: e ? this.extractRows(e).slice(0, 20) : null, live: l };
      await this.$nextTick();
      this.$refs.ptPanelClose?.focus();
    },
    ptCloseIP() {
      this.ptPanelSeq++;
      this.ptPanelIP = "";
      this.ptPanel = null;
      const o = this._ptOpener;
      this._ptOpener = null;
      if (o && document.body.contains(o)) o.focus();
    },
    // The panel's "Filter the WAF log by it": the address is read before the
    // panel is closed (closing empties it), and the WAF log is where it shows.
    async ptFilterWAFBy(ip) {
      const addr = String(ip || "").trim();
      this.ptCloseIP();
      if (!addr) return;
      this.ptFilters.ip = addr;
      this.ptTab = "waf";
      try {
        const u = new URL(window.location.href);
        u.searchParams.set("tab", "waf");
        window.history.replaceState(null, "", `${u.pathname}${u.search}`);
      } catch { /* no history */ }
      await this.ptReload(); // a new filter: any opened group is closed
    },
    async ptShowEventsOf(ip) {
      this.ptCloseIP();
      this.ptEventIP = String(ip || "").trim();
      this.ptResetEvents();
      await this.ptSetTab("events");
    },

    async ptExclude(row) {
      const offer = this.ptExcludeOffer(row);
      if (!offer) return;
      if (!window.confirm(offer.confirm)) return;
      try {
        await this.postJSON(offer.url, {});
        this.actionMsg = `WAF exclude added: ${offer.path} on ${offer.host}, rule ${offer.ruleID}`;
      } catch (err) {
        this.actionMsg = `WAF exclude failed: ${this.formatApiError(err)}`;
      }
    },
  },

  mounted() {
    // While the address panel is open: Escape closes it, Tab stays inside it.
    this._ptKey = (ev) => {
      if (!this.ptPanelIP) return;
      if (ev.key === "Escape") { ev.preventDefault(); this.ptCloseIP(); return; }
      if (ev.key !== "Tab") return;
      const panel = this.$refs.ptPanelEl;
      if (!panel) return;
      const f = [...panel.querySelectorAll("button, a[href], input, select")].filter((x) => !x.disabled && x.offsetParent !== null);
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (!panel.contains(document.activeElement)) { ev.preventDefault(); first.focus(); }
      else if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
      else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", this._ptKey);
  },
  beforeUnmount() {
    if (this._ptKey) document.removeEventListener("keydown", this._ptKey);
  },
};
