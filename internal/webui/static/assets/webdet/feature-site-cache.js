// Site Cache page: per-vhost edge caching (docs/site-cache-runbook.md). Arm a
// vhost's static and/or micro tier, opt a host out, purge, and read the live
// hit counts. Talks to the scope-filtered /api/v1/site-cache/* API; the daemon
// re-validates every write and keeps purge-all admin-only.

import {
  STATIC_RECIPES,
  MICRO_RECIPES_OFFERED,
  MICRO_BUCKETS,
  emptyForm,
  formFromEntry,
  buildPatch,
  offPatch,
  validateForm,
  buildRows,
  tierCounts,
  filterRows,
  sortRows,
  isBucketTTL,
  microBucketSeconds,
  recipeLabel,
  nodeSwitches,
  debugCurl,
  canonHost,
  isWildcard,
  generationSinceMs,
} from "./site-cache-model.js";
import {
  SC_RECIPES,
  scRecipe,
  scRecipeVarsDefaults,
  scRecipeErrors,
  scRecipeBuild,
} from "./site-cache-recipes.js";

// The node switches are re-read at most this often: the detectors config
// endpoint parses the file, and the switches change rarely.
const SWITCHES_TTL_MS = 60 * 1000;

export const siteCacheMixin = {
  data() {
    return {
      scEntries: [],
      scUnloadable: [],
      scStats: [],
      scLoaded: false,
      scLoadError: "",
      scForm: emptyForm(),
      scEditHost: "",
      scOriginal: null,
      scMode: "editor",
      scQuick: "",
      scVhostFilter: "",
      scSearch: "",
      scSortKey: "host",
      scSortDir: "asc",
      scBusy: false,
      scStaticRecipes: STATIC_RECIPES,
      scBuckets: MICRO_BUCKETS,
      scRecipes: SC_RECIPES,
      scRecipeKey: "",
      scRecipeVars: {},
      scSwitches: null,
      scSwitchesAt: 0,
      scCheckHost: "",
      scCheckPath: "/",
      scCopied: false,
    };
  },

  computed: {
    scRows() {
      return buildRows(this.scEntries, this.scStats);
    },
    scCounts() {
      return tierCounts(this.scRows);
    },
    scFiltered() {
      const rows = filterRows(this.scRows, { quick: this.scQuick, vhost: this.scVhostFilter, search: this.scSearch });
      return sortRows(rows, this.scSortKey, this.scSortDir);
    },
    scStatsRows() {
      const vf = this.scVhostFilter;
      const q = this.scSearch.toLowerCase();
      const byHost = new Map(this.scRows.map((r) => [r.host, r]));
      return [...(this.scStats || [])]
        .filter((s) => s && s.host)
        .filter((s) => {
          const r = byHost.get(s.host);
          if (!r) return !vf && (!q || s.host.includes(q));
          return filterRows([r], { vhost: vf, search: q }).length > 0;
        })
        .sort((a, b) => a.host.localeCompare(b.host));
    },
    scValidation() {
      return validateForm(this.scForm, {
        original: this.scOriginal,
        inScope: (h) => this.isHostAllowedByScope(h),
        existing: this.scEntries,
      });
    },
    canSaveSC() {
      return !this.scBusy && this.scValidation.errors.length === 0;
    },
    // A pristine form (no host typed yet) shows no errors: the save button is
    // disabled anyway, and the sentence says what to do.
    scShownValidation() {
      return this.scForm.host.trim() ? this.scValidation : { errors: [], warnings: [] };
    },
    scMicroRecipeOptions() {
      const out = [...MICRO_RECIPES_OFFERED];
      if (this.scForm.microRecipe && !out.includes(this.scForm.microRecipe)) out.push(this.scForm.microRecipe);
      return out;
    },
    // The bucket choices, plus a stored TTL that is not a bucket (set from the
    // CLI), so editing never silently rewrites it.
    scMicroTTLOptions() {
      const out = MICRO_BUCKETS.map((b) => ({ value: `${b}s`, label: `${b} s` }));
      const cur = String(this.scForm.microTTL || "").trim().toLowerCase();
      if (cur && !out.some((o) => o.value === cur)) {
        out.push({ value: cur, label: `${cur} (runs as ${microBucketSeconds(cur)} s)` });
      }
      return out;
    },
    scReviewSentence() {
      const f = this.scForm;
      if (!f.host.trim()) return "Pick a vhost, then turn on a tier (or leave both off for an opt-out).";
      const host = canonHost(f.host);
      const where = isWildcard(host) ? `every sub-host of ${host.slice(2)} without a policy of its own` : host;
      if (!f.staticOn && !f.microOn) return `${where}: never cached (opt-out).`;
      const parts = [];
      if (f.staticOn) parts.push(`static assets cached by the origin's headers, 1 h fallback (${recipeLabel(f.staticRecipe)})`);
      if (f.microOn) parts.push(`anonymous pages micro-cached for ${microBucketSeconds(String(f.microTTL || ""))} s (${recipeLabel(f.microRecipe)})`);
      return `${where}: ${parts.join("; ")}.`;
    },
    scMicroDryRun() {
      return !this.scSwitches || !this.scSwitches.microEnforce;
    },
    scSelectedRecipe() {
      return scRecipe(this.scRecipeKey);
    },
    scRecipeVarErrors() {
      return scRecipeErrors(this.scSelectedRecipe, this.scRecipeVars, { inScope: (h) => this.isHostAllowedByScope(h) });
    },
    // The patches a recipe would send, with what each does to an existing
    // policy: "new", "updates", and whether it starts the cache over.
    scRecipePreview() {
      const patches = scRecipeBuild(this.scSelectedRecipe, this.scRecipeVars, { inScope: (h) => this.isHostAllowedByScope(h) });
      const byHost = new Map(this.scEntries.map((e) => [e.host, e]));
      return patches.map((p) => {
        const cur = byHost.get(p.host) || null;
        let note = cur ? "updates the existing policy" : "new policy";
        if (cur) {
          const staticOn = Boolean(cur.static && cur.static.enabled);
          const microOn = Boolean(cur.micro && cur.micro.enabled);
          const bumps = (p.static && p.static.enabled && !staticOn) ||
            (p.micro && p.micro.enabled && !microOn && cur.micro && cur.micro.recipe);
          if (bumps) note += "; starts its cache over (a new generation)";
        }
        return { patch: p, note };
      });
    },
    scCheckCurl() {
      return debugCurl(this.scCheckHost || this.scForm.host, this.scCheckPath);
    },
  },

  methods: {
    // Wired into core.js refreshAll via the generic refreshLists hook.
    async refreshLists() {
      await this.refreshSiteCache();
    },
    async refreshSiteCache() {
      const statsP = this.fetchJSONSafe("v1/site-cache/stats", { rows: [] });
      try {
        const payload = await this.fetchJSON("v1/site-cache/list");
        this.scEntries = this.extractRows(payload, "rows");
        this.scUnloadable = Array.isArray(payload && payload.unloadable) ? payload.unloadable : [];
        this.scLoadError = "";
        this.scLoaded = true;
      } catch (err) {
        // Keep the last list rather than showing "no policies" on a failed read.
        this.scLoadError = `Could not load the policies: ${this.formatApiError(err)}`;
      }
      this.scStats = this.extractRows(await statsP, "rows");
      await this.refreshSiteCacheSwitches();
    },
    // SITE_CACHE / MICRO_CACHE_ENFORCE from the merged detectors.conf. The
    // endpoint is admin-only, so a scoped page never asks.
    async refreshSiteCacheSwitches(force = false) {
      if (!this.isAdmin) return;
      if (!force && this.scSwitchesAt && Date.now() - this.scSwitchesAt < SWITCHES_TTL_MS) return;
      this.scSwitchesAt = Date.now();
      const payload = await this.fetchJSONSafe("v1/detectors/config?view=merged", null);
      this.scSwitches = nodeSwitches(payload);
    },

    scRecipeLabel: recipeLabel,
    scIsBucket: isBucketTTL,
    scStaticText(row) {
      return row.staticOn ? recipeLabel(row.staticRecipe) : "off";
    },
    scStaticTitle(row) {
      if (!row.staticOn) return row.staticRecipe ? `off (keeps ${recipeLabel(row.staticRecipe)} for a re-enable)` : "off";
      const label = row.staticTTL ? ` Stored TTL ${row.staticTTL} is a label.` : "";
      return `Static assets follow the origin's Cache-Control / Expires, 1 h fallback.${label}`;
    },
    scMicroText(row) {
      return row.microOn ? `${recipeLabel(row.microRecipe)} · ${row.microBucket} s` : "off";
    },
    scMicroTitle(row) {
      if (!row.microOn) return row.microRecipe ? `off (keeps ${recipeLabel(row.microRecipe)} for a re-enable)` : "off";
      const ttl = row.microTTL || "none (1 s)";
      const snap = row.microTTL && !isBucketTTL(row.microTTL) ? ` → snaps to ${row.microBucket} s` : "";
      const cookies = [
        row.strictCookies ? "strict cookies" : "",
        row.authCookies.length ? `auth cookies: ${row.authCookies.join(", ")}` : "",
      ].filter(Boolean).join("; ");
      return `Stored TTL ${ttl}${snap}.${cookies ? " " + cookies + "." : ""}`;
    },
    scGenText(row) {
      const ms = generationSinceMs(row.generation);
      return ms ? this.agoTs(ms / 1000) : (row.generation ? `#${row.generation}` : "-");
    },
    scGenTitle(row) {
      const ms = generationSinceMs(row.generation);
      const when = ms ? ` — cache started ${new Date(ms).toLocaleString()} (last purge or re-enable)` : "";
      return `Generation ${row.generation}${when}`;
    },
    scUpdatedText(row) {
      return row.updatedMs ? this.agoTs(row.updatedMs / 1000) : "-";
    },
    scUpdatedTitle(row) {
      return row.updatedMs ? new Date(row.updatedMs).toLocaleString() : "";
    },
    scHitPillClass(row) {
      if (row.hitPct == null) return "";
      if (row.hitPct >= 50) return "ok";
      if (row.hitPct >= 10) return "warn";
      return "danger";
    },
    scHitTitle(row) {
      const s = row.stats;
      if (!s) return row.optOut ? "Opt-out: nothing to count." : "No counts from the edge yet (pushed about every 60 s, armed vhosts only).";
      return `HIT ${s.hit} · MISS ${s.miss} · EXPIRED ${s.expired} · STALE ${s.stale} · UPDATING ${s.updating} · REVALIDATED ${s.revalidated} · BYPASS ${s.bypass}. Strict ratio: HIT ÷ everything but BYPASS.`;
    },

    // ── List controls ────────────────────────────────────────────────────
    setSCQuick(key) {
      this.scQuick = this.scQuick === key ? "" : key;
    },
    setSCSort(key) {
      if (this.scSortKey === key) {
        this.scSortDir = this.scSortDir === "asc" ? "desc" : "asc";
        return;
      }
      this.scSortKey = key;
      this.scSortDir = key === "hit" || key === "updated" || key === "gen" ? "desc" : "asc";
    },
    scSortArrow(key) {
      if (this.scSortKey !== key) return "";
      return this.scSortDir === "asc" ? "↑" : "↓";
    },

    // ── Editor ───────────────────────────────────────────────────────────
    setSCMode(mode) {
      this.scMode = mode;
    },
    resetSCForm() {
      this.scForm = emptyForm();
      this.scEditHost = "";
      this.scOriginal = null;
      this.applySCScopedDefault();
    },
    // A scoped token with one vhost starts the editor on that vhost (the
    // server enforces the scope regardless).
    applySCScopedDefault() {
      if (this.isScoped && this.allowedVhosts.length === 1 && !this.scForm.host.trim() && !this.scEditHost) {
        this.scForm.host = this.allowedVhosts[0];
      }
    },
    editSC(row) {
      this.scForm = formFromEntry(row.entry);
      this.scEditHost = row.host;
      this.scOriginal = row.entry;
      this.scCheckHost = row.host;
      this.scMode = "editor";
      try { window.scrollTo({ top: 0, behavior: "smooth" }); } catch (e) { /* non-fatal */ }
    },
    // A new micro tier on a node that ENFORCES it serves pages from cache at
    // once: confirm. (Unknown switches — a scoped page — do not prompt; the
    // micro callout says it may be a dry run.)
    confirmSCMicroEnforced(patch) {
      const wasOn = Boolean(this.scOriginal && this.scOriginal.micro && this.scOriginal.micro.enabled);
      if (!patch.micro || !patch.micro.enabled || wasOn || !this.scSwitches || !this.scSwitches.microEnforce) return true;
      return window.confirm(
        `This node enforces the micro tier: anonymous pages of ${patch.host} will be served from cache for ` +
        `${microBucketSeconds(patch.micro.ttl || "")} s. Checked the debug stamp on its logged-in / cart pages first?`);
    },
    async saveSC() {
      if (!this.canSaveSC) return;
      const patch = buildPatch(this.scForm);
      if (!this.confirmSCMicroEnforced(patch)) return;
      this.scBusy = true;
      try {
        const res = await this.postJSON("v1/site-cache/set", patch);
        const entry = (res && res.entry) || null;
        this.actionMsg = `Saved the policy for ${patch.host}. Each edge worker applies it within about 60 s.`;
        await this.refreshSiteCache();
        if (entry) {
          this.scForm = formFromEntry(entry);
          this.scEditHost = entry.host;
          this.scOriginal = entry;
        }
      } catch (err) {
        this.actionMsg = `Save failed: ${this.formatApiError(err)}`;
        console.error("[cfm-admin] site-cache save failed", err);
      } finally {
        this.scBusy = false;
      }
    },

    // ── Row actions ──────────────────────────────────────────────────────
    async runSCAction(label, fn) {
      this.scBusy = true;
      try {
        this.actionMsg = await fn();
        await this.refreshSiteCache();
      } catch (err) {
        this.actionMsg = `${label} failed: ${this.formatApiError(err)}`;
        console.error(`[cfm-admin] site-cache ${label} failed`, err);
      } finally {
        this.scBusy = false;
      }
    },
    offSC(host) {
      const scope = isWildcard(host) ? `nothing under ${host} is cached (unless a more specific policy arms it)` : `${host} is never cached, even under an armed wildcard`;
      if (!window.confirm(`Turn caching off for ${host}? Both tiers go off: ${scope}. Objects already cached stay until they expire; purge first if something wrong was cached.`)) return;
      return this.runSCAction("Turn off", async () => {
        await this.postJSON("v1/site-cache/set", offPatch(host));
        if (this.scEditHost === host) this.resetSCForm();
        return `${host} is opted out. Each edge worker applies it within about 60 s.`;
      });
    },
    purgeSC(host) {
      const scope = isWildcard(host) ? `everything cached under ${host}` : `everything cached for ${host}`;
      if (!window.confirm(`Purge ${scope}? The next requests go to the origin.`)) return;
      return this.runSCAction("Purge", async () => {
        await this.postJSON(`v1/site-cache/purge?host=${encodeURIComponent(host)}`, {});
        return `Purged ${host}. Each edge worker stops serving the old objects at its next poll, within about 60 s.`;
      });
    },
    removeSC(host) {
      const after = isWildcard(host) ? "Its sub-hosts are then cached only by their own policies." : "The host then follows a covering wildcard again, if one is armed.";
      if (!window.confirm(`Delete the policy for ${host}? ${after} A purge is no longer possible after this, so purge first if something wrong was cached.`)) return;
      return this.runSCAction("Remove", async () => {
        await this.postJSON(`v1/site-cache/remove?host=${encodeURIComponent(host)}`, {});
        if (this.scEditHost === host) this.resetSCForm();
        return `Deleted the policy for ${host}.`;
      });
    },
    purgeAllSC() {
      if (!this.isAdmin) return;
      if (!window.confirm("Purge EVERY vhost's cache on this node? All cached objects stop being served; the next requests go to the origins.")) return;
      return this.runSCAction("Purge all", async () => {
        const res = await this.postJSON("v1/site-cache/purge?all=1", {});
        const n = Number((res && res.purged) || 0);
        return `Purged ${n} ${n === 1 ? "policy" : "policies"}. Each edge worker stops serving the old objects within about 60 s.`;
      });
    },
    checkSC(host) {
      this.scCheckHost = host;
      this.scMode = "editor";
      try { window.scrollTo({ top: 0, behavior: "smooth" }); } catch (e) { /* non-fatal */ }
    },
    async copySCCurl() {
      try {
        await navigator.clipboard.writeText(this.scCheckCurl);
        this.scCopied = true;
        setTimeout(() => { this.scCopied = false; }, 1500);
      } catch (e) {
        this.actionMsg = "Copy failed: select the command and copy it by hand.";
      }
    },

    // ── Recipes ──────────────────────────────────────────────────────────
    selectSCRecipe(key) {
      this.scRecipeKey = key;
      const seed = this.scVhostFilter || (this.isScoped ? this.allowedVhosts.filter((h) => !h.includes("*") || isWildcard(h)).join(", ") : "");
      this.scRecipeVars = scRecipeVarsDefaults(scRecipe(key), { vhosts: seed });
    },
    async createSCRecipe() {
      const rows = this.scRecipePreview;
      if (!rows.length) return;
      if (!this.confirmSCRecipeMicro(rows)) return;
      this.scBusy = true;
      const done = [];
      try {
        for (const { patch } of rows) {
          await this.postJSON("v1/site-cache/set", patch);
          done.push(patch.host);
        }
        this.actionMsg = `Applied "${this.scSelectedRecipe.title}" to ${done.join(", ")}. Each edge worker applies it within about 60 s.`;
        this.scRecipeKey = "";
        this.scMode = "editor";
      } catch (err) {
        const partial = done.length ? ` (applied to ${done.join(", ")} before the failure)` : "";
        this.actionMsg = `Recipe failed: ${this.formatApiError(err)}${partial}`;
        console.error("[cfm-admin] site-cache recipe failed", err);
      } finally {
        this.scBusy = false;
        await this.refreshSiteCache();
      }
    },
    confirmSCRecipeMicro(rows) {
      const micro = rows.some(({ patch }) => patch.micro && patch.micro.enabled);
      if (!micro || !this.scSwitches || !this.scSwitches.microEnforce) return true;
      return window.confirm("This node enforces the micro tier: the anonymous pages of these vhosts will be served from cache at once. Continue?");
    },
    scPatchSummary(p) {
      const parts = [];
      if (p.static) parts.push(p.static.enabled ? `static on (${recipeLabel(p.static.recipe)})` : "static off");
      if (p.micro) parts.push(p.micro.enabled ? `micro ${microBucketSeconds(p.micro.ttl || "")} s (${recipeLabel(p.micro.recipe)})` : "micro off");
      return parts.join(", ");
    },
  },

  watch: {
    allowedVhosts() { this.applySCScopedDefault(); },
  },

  mounted() {
    // ?vhost=<host> / ?host=<host> deep link: filter the list to the policies
    // that apply to that vhost (its own, or a wildcard covering it).
    try {
      const q = new URLSearchParams(window.location.search);
      const v = (q.get("vhost") || q.get("host") || "").trim().toLowerCase();
      if (v) {
        this.scVhostFilter = v;
        this.scCheckHost = v;
      }
    } catch (e) { /* non-fatal */ }
    this.applySCScopedDefault();
  },
};
