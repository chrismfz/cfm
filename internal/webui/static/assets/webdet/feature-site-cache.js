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
  coveringWildcard,
  patchChanges,
  isOptOut,
  hostError,
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
      // Bumped whenever the editor loads another form (reset / edit), so an
      // in-flight save never overwrites a form the operator moved on to.
      scFormEpoch: 0,
      // Refresh sequence: a list read that resolves after a newer one started
      // (an auto-refresh overlapping a save) is dropped.
      scRefreshSeq: 0,
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
        inScope: (h) => this.scInScope(h),
        existing: this.scEntries,
        unloadable: this.scUnloadable,
      });
    },
    // What a save would send: only what the operator decided (buildPatch).
    scPatch() {
      return buildPatch(this.scForm, this.scOriginal);
    },
    scHasChanges() {
      return patchChanges(this.scPatch) > 0;
    },
    // Any difference from the form as loaded, raw text included (a cookie list
    // still being typed can parse to the stored one): what the resync must not
    // throw away.
    scFormDirty() {
      if (!this.scOriginal) return false;
      return JSON.stringify(this.scForm) !== JSON.stringify(formFromEntry(this.scOriginal));
    },
    // The policy being edited changed ("changed") or went ("gone") since the
    // form loaded it. A save still sends only the fields changed here, but a
    // deleted policy must not be silently recreated.
    scEditStale() {
      if (!this.scEditHost || !this.scLoaded) return "";
      const row = this.scRows.find((r) => r.host === this.scEditHost);
      if (!row) return "gone";
      const was = (this.scOriginal && this.scOriginal.updated_at) || "";
      return row.entry && row.entry.updated_at !== was ? "changed" : "";
    },
    // The stored policy a NEW-policy form's host already has (the editor then
    // offers to open it instead: saving the new form would replace it).
    scExistingForNew() {
      if (this.scEditHost) return null;
      const h = canonHost(this.scForm.host);
      return h ? this.scRows.find((r) => r.host === h) || null : null;
    },
    canSaveSC() {
      if (this.scBusy || this.scValidation.errors.length) return false;
      // An edit needs a change, and a policy that still exists. A new policy
      // needs a loaded list: without it the page cannot tell that the host
      // already has one.
      if (this.scEditHost) return this.scHasChanges && this.scEditStale !== "gone";
      return this.scLoaded && !this.scLoadError;
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
      const where = isWildcard(host) ? `every sub-host of ${host.slice(2)} without a policy of its own (or a narrower wildcard)` : host;
      if (!f.staticOn && !f.microOn) return `${where}: never cached (opt-out).`;
      const parts = [];
      if (f.staticOn) parts.push(`static assets cached by the origin's headers, 1 h fallback (${recipeLabel(f.staticRecipe)})`);
      if (f.microOn) parts.push(`anonymous pages micro-cached for ${microBucketSeconds(String(f.microTTL || ""))} s (${recipeLabel(f.microRecipe)})`);
      return `${where}: ${parts.join("; ")}.`;
    },
    // "enforced" / "dryrun" from this node's MICRO_CACHE_ENFORCE, or "unknown":
    // a scoped page cannot read it, and an admin's read can fail. Unknown is
    // treated as possibly live, never as a dry run.
    scMicroMode() {
      if (!this.scSwitches) return "unknown";
      return this.scSwitches.microEnforce ? "enforced" : "dryrun";
    },
    scSelectedRecipe() {
      return scRecipe(this.scRecipeKey);
    },
    scRecipeVarErrors() {
      return scRecipeErrors(this.scSelectedRecipe, this.scRecipeVars, { inScope: (h) => this.scInScope(h) });
    },
    // The patches a recipe would send, with what each does to an existing
    // policy: "new", "updates", and whether it starts the cache over.
    scRecipePreview() {
      const patches = scRecipeBuild(this.scSelectedRecipe, this.scRecipeVars, { inScope: (h) => this.scInScope(h) });
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
      return debugCurl(this.scCheckHost || this.scForm.host, this.scCheckPath, this.scEntries.map((e) => e.host));
    },
  },

  methods: {
    // Wired into core.js refreshAll via the generic refreshLists hook.
    async refreshLists() {
      await this.refreshSiteCache();
    },
    async refreshSiteCache() {
      const seq = ++this.scRefreshSeq;
      const statsP = this.fetchJSON("v1/site-cache/stats").then((p) => this.extractRows(p, "rows"), (err) => {
        console.error("[cfm-admin] site-cache stats fetch failed", err);
        return null; // keep the last counts
      });
      try {
        const payload = await this.fetchJSON("v1/site-cache/list");
        if (seq !== this.scRefreshSeq) return; // a newer read is on its way
        this.scEntries = this.extractRows(payload, "rows");
        this.scUnloadable = Array.isArray(payload && payload.unloadable) ? payload.unloadable : [];
        this.scLoadError = "";
        this.scLoaded = true;
      } catch (err) {
        // Keep the last list rather than showing "no policies" on a failed read.
        this.scLoadError = `Could not load the policies: ${this.formatApiError(err)}`;
      }
      const stats = await statsP;
      if (stats) this.scStats = stats;
      if (!this.scLoadError) this.resyncSCEdit();
      this.adoptSCScopedPolicy();
      await this.refreshSiteCacheSwitches();
    },
    // SITE_CACHE / MICRO_CACHE_ENFORCE from the merged detectors.conf. The
    // endpoint is admin-only, so a scoped page never asks.
    async refreshSiteCacheSwitches(force = false) {
      if (!this.isAdmin) return;
      if (!force && this.scSwitchesAt && Date.now() - this.scSwitchesAt < SWITCHES_TTL_MS) return;
      this.scSwitchesAt = Date.now();
      const payload = await this.fetchJSONSafe("v1/detectors/config?view=merged", null);
      // A failed read keeps the last known state (a first failure leaves it
      // unknown); it is retried after the same interval.
      const sw = nodeSwitches(payload);
      if (sw) this.scSwitches = sw;
    },
    // The site-cache API matches a scoped token's vhosts literally (a scope
    // entry "*.example.com" allows that policy key, not a.example.com), and an
    // empty scope allows nothing: the same check here, so the page refuses what
    // the server would 403.
    scInScope(host) {
      if (!this.isScoped) return true;
      const h = canonHost(host);
      return this.allowedVhosts.some((v) => canonHost(v) === h);
    },

    scRecipeLabel: recipeLabel,
    // The set API refuses a host this version no longer accepts, so such an
    // unloadable row can only be deleted.
    scHostValid(host) {
      return !hostError(host);
    },
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
      this.scFormEpoch += 1;
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
        this.adoptSCScopedPolicy();
      }
    },
    // ...and when that vhost already has a policy, the editor opens it rather
    // than a blank new-policy form (whose both-off tiers would replace it).
    // Only while the form is untouched, so it never discards an edit.
    adoptSCScopedPolicy() {
      if (!this.isScoped || this.allowedVhosts.length !== 1 || this.scEditHost) return;
      const pristine = JSON.stringify({ ...this.scForm, host: "" }) === JSON.stringify(emptyForm());
      if (!pristine || canonHost(this.scForm.host) !== canonHost(this.allowedVhosts[0])) return;
      const row = this.scExistingForNew;
      if (row) this.editSC(row, { scroll: false });
    },
    editSC(row, { scroll = true, check = true, mode = true } = {}) {
      this.scFormEpoch += 1;
      this.scForm = formFromEntry(row.entry);
      this.scEditHost = row.host;
      this.scOriginal = row.entry;
      if (check) this.scCheckHost = row.host;
      if (mode) this.scMode = "editor";
      if (!scroll) return;
      try { window.scrollTo({ top: 0, behavior: "smooth" }); } catch (e) { /* non-fatal */ }
    },
    // After a fresh list: an editor with no unsaved change follows the stored
    // policy — reloaded when it changed (Turn off from the table, a recipe,
    // another operator), a blank form when it is gone — so a later Save never
    // re-sends the state from before. With unsaved changes it is left alone,
    // and the editor says the policy changed or went.
    resyncSCEdit() {
      if (!this.scEditHost || this.scFormDirty) return;
      const row = this.scRows.find((r) => r.host === this.scEditHost);
      if (!row) this.resetSCForm();
      else if (this.scEditStale === "changed") this.editSC(row, { scroll: false, check: false, mode: false });
    },
    reloadSCEdit() {
      const row = this.scRows.find((r) => r.host === this.scEditHost);
      if (row) this.editSC(row, { scroll: false });
    },
    // Turning the micro tier on where this node enforces it — or may: the
    // page cannot always tell — serves anonymous pages from cache at once.
    // Confirm, unless the node is known to be in a dry run.
    confirmSCMicroEnforced(patch) {
      if (!patch.micro || !patch.micro.enabled || this.scMicroMode === "dryrun") return true;
      const wasOn = Boolean(this.scOriginal && this.scOriginal.micro && this.scOriginal.micro.enabled);
      if (wasOn) return true;
      const node = this.scMicroMode === "enforced"
        ? "This node enforces the micro tier"
        : "This page cannot tell whether this node enforces the micro tier; if it does";
      return window.confirm(
        `${node}: anonymous pages of ${patch.host} will be served from cache for ` +
        `${microBucketSeconds(patch.micro.ttl || "")} s. Checked the debug stamp on its logged-in and cart pages first?`);
    },
    async saveSC() {
      if (!this.canSaveSC) return;
      const patch = this.scPatch;
      if (!this.confirmSCMicroEnforced(patch)) return;
      const epoch = this.scFormEpoch;
      this.scBusy = true;
      try {
        const res = await this.postJSON("v1/site-cache/set", patch);
        const entry = (res && res.entry) || null;
        this.actionMsg = `Saved the policy for ${patch.host}. Each edge worker applies it within about 60 s.`;
        // Load the stored result into the editor, unless the operator moved on
        // (another row, Clear) while the save was in flight.
        if (entry && this.scFormEpoch === epoch) {
          this.scFormEpoch += 1;
          this.scForm = formFromEntry(entry);
          this.scEditHost = entry.host;
          this.scOriginal = entry;
        }
        await this.refreshSiteCache();
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
      const scope = isWildcard(host)
        ? `the sub-hosts it covers are not cached, unless a policy of their own arms them`
        : `${host} is not cached, even under an armed wildcard`;
      if (!window.confirm(`Turn caching off for ${host}? Both tiers go off and the policy stays, as an opt-out: ${scope}. Nothing is served from its cache while it is off, and turning it on again starts from an empty cache.`)) return;
      return this.runSCAction("Turn off", async () => {
        await this.postJSON("v1/site-cache/set", offPatch(host));
        return `${host} is opted out. Each edge worker applies it within about 60 s.`;
      });
    },
    // An unloadable row belongs to a policy this build cannot read (maybe
    // written by a newer CFM): turning it off replaces it, dropping its settings.
    offUnloadableSC(host) {
      if (!window.confirm(`Replace the stored policy for ${host} with an opt-out? This version cannot read it (it may come from a newer CFM), so its settings are discarded; the host stays uncached, as it is now.`)) return;
      return this.runSCAction("Turn off", async () => {
        await this.postJSON("v1/site-cache/set", offPatch(host));
        return `${host} now has an opt-out policy.`;
      });
    },
    purgeSC(host) {
      const scope = isWildcard(host)
        ? `the cache of ${host} (the sub-hosts it covers; a sub-host with a policy of its own has its own cache)`
        : `the cache of ${host}`;
      if (!window.confirm(`Purge ${scope}? The next requests go to the origin.`)) return;
      return this.runSCAction("Purge", async () => {
        await this.postJSON(`v1/site-cache/purge?host=${encodeURIComponent(host)}`, {});
        return `Purged ${host}. Each edge worker stops serving the old objects at its next poll, within about 60 s.`;
      });
    },
    removeSC(host) {
      const others = this.scEntries.filter((e) => e.host !== host);
      const cover = coveringWildcard(host, others);
      const coverEntry = others.find((e) => e.host === cover);
      const who = isWildcard(host) ? "The sub-hosts it covered (those without a policy of their own)" : host;
      const verb = isWildcard(host) ? "follow" : "follows";
      let after;
      if (!cover && this.isScoped) {
        // A scoped list shows only the token's own policies: an operator's
        // wildcard covering this host would be invisible here.
        after = `${who} ${isWildcard(host) ? "are" : "is"} then not cached, unless a wildcard policy of the server operator (not shown here) covers ${isWildcard(host) ? "them" : "it"}. Turn off keeps ${isWildcard(host) ? "them" : "it"} uncached either way.`;
      } else if (!cover) after = isWildcard(host) ? `${who} are then not cached.` : `${host} is then not cached.`;
      else if (isOptOut(coverEntry)) after = `${who} then ${verb} ${cover}, an opt-out: not cached.`;
      else after = `${who} then ${verb} ${cover} and ${isWildcard(host) ? "are" : "is"} served from that wildcard's cache (purge ${cover} if that holds something wrong).`;
      if (!window.confirm(`Delete the policy for ${host}? ${after} Adding a policy for it again starts from an empty cache.`)) return;
      return this.runSCAction("Remove", async () => {
        await this.postJSON(`v1/site-cache/remove?host=${encodeURIComponent(host)}`, {});
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
      if (!micro || this.scMicroMode === "dryrun") return true;
      const node = this.scMicroMode === "enforced"
        ? "This node enforces the micro tier"
        : "This page cannot tell whether this node enforces the micro tier; if it does";
      return window.confirm(`${node}: the anonymous pages of these vhosts will be served from cache at once. Checked their session cookies are on the auth list? Continue?`);
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
