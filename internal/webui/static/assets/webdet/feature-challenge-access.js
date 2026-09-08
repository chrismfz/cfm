// Challenge Access-Control page: a per-vhost/global allow-list that EXEMPTS
// matching requests from the interactive challenge (challenge→allow only). The
// surgical companion to the coarse challenge on/off toggle on Vhost controls.
// Talks to the scope-filtered /api/v1/challenge/access/* API.

import {
  emptyCAForm,
  buildCAPayload,
  caFormFromEntry,
  dimensionsPresent,
  describeCAMatch,
  validateCAForm,
  caScopeLabel,
  BOT_GROUPS,
  VERIFIED_BOT_LABEL,
  CA_METHODS,
} from "./challenge-access-model.js";
import { hostPatternMatch } from "./rules-model.js";
import {
  CA_RECIPES,
  caRecipe,
  caRecipeVarsDefaults,
  caRecipeErrors,
  caRecipeBuild,
} from "./challenge-access-recipes.js";

export const challengeAccessMixin = {
  data() {
    return {
      caEntries: [],
      caForm: emptyCAForm(),
      caEditID: "",
      caChips: { paths: false, uas: false, countries: false, ips: false, asns: false, methods: false, vbot: false },
      caVhostFilter: "",
      caSearch: "",
      caBusy: false,
      caBotGroups: BOT_GROUPS,
      caVerifiedBotLabel: VERIFIED_BOT_LABEL,
      caKnownMethods: CA_METHODS,
      // Editor vs recipes pane.
      caEditorMode: "editor",
      caRecipes: CA_RECIPES,
      caRecipeKey: "",
      caRecipeVars: {},
    };
  },

  computed: {
    // Vhost dropdown options, derived from the loaded entries.
    caVhostOptions() {
      const set = new Set();
      for (const e of this.caEntries) for (const h of (e.scope?.vhosts || [])) set.add(h);
      // Keep the active filter selectable even when it only matches Global /
      // wildcard entries (a ?vhost= deep-link host is not a literal scope
      // value), so the dropdown never disagrees with the applied filter.
      if (this.caVhostFilter) set.add(this.caVhostFilter);
      return Array.from(set).sort();
    },
    caFiltered() {
      const vf = this.caVhostFilter;
      const q = this.caSearch.toLowerCase();
      return this.caEntries.filter((e) => {
        // Match the filter host against each scope PATTERN, so a Global ("*") or
        // wildcard ("*.shop.gr") entry that actually applies to the chosen vhost
        // is shown — not hidden by a literal-equality check.
        if (vf && !(e.scope?.vhosts || []).some((pat) => pat === vf || hostPatternMatch(pat, vf))) return false;
        if (!q) return true;
        const hay = [
          e.id,
          (e.scope?.vhosts || []).join(","),
          e.note || "",
          describeCAMatch(e.match),
        ].join(" ").toLowerCase();
        return hay.includes(q);
      });
    },
    caValidation() {
      return validateCAForm(this.caForm);
    },
    canSaveCA() {
      return !this.caBusy && this.caValidation.errors.length === 0;
    },
    caReviewSentence() {
      const vhosts = this.caForm.vhosts.trim() || "(no vhost)";
      const what = describeCAMatch(buildCAPayload(this.caForm).match);
      return `On ${vhosts}, exempt from the challenge: ${what}. WAF and IP blocking stay active.`;
    },
    caSelectedRecipe() {
      return caRecipe(this.caRecipeKey);
    },
    caRecipeVarErrors() {
      return caRecipeErrors(this.caSelectedRecipe, this.caRecipeVars);
    },
    caRecipePreview() {
      return caRecipeBuild(this.caSelectedRecipe, this.caRecipeVars);
    },
  },

  methods: {
    // Wired into core.js refreshAll via the generic refreshLists hook.
    async refreshLists() {
      await this.refreshChallengeAccess();
    },
    async refreshChallengeAccess() {
      const payload = await this.fetchJSONSafe("v1/challenge/access", { rows: [] });
      this.caEntries = this.extractRows(payload, "rows");
    },

    caScopeLabel,
    caMatchSummary(entry) {
      return describeCAMatch(entry?.match);
    },

    // ── Recipes ───────────────────────────────────────────────────────────
    setCAEditorMode(mode) {
      this.caEditorMode = mode;
    },
    selectCARecipe(key) {
      this.caRecipeKey = key;
      const seedVhost = this.caVhostFilter || (this.isScoped ? this.allowedVhosts.join(", ") : "");
      this.caRecipeVars = caRecipeVarsDefaults(caRecipe(key), { vhosts: seedVhost });
    },
    caRecipePreviewSummary(entry) {
      return describeCAMatch(entry?.match);
    },
    async createCARecipe() {
      const entries = this.caRecipePreview;
      if (!entries.length) return;
      this.caBusy = true;
      try {
        for (const body of entries) {
          await this.postJSON("v1/challenge/access/add", body);
        }
        this.actionMsg = `Created ${entries.length} exemption(s) from recipe ${this.caRecipeKey}.`;
        this.caSearch = "recipe:" + this.caRecipeKey; // group the new entries in the list
        this.caRecipeKey = "";
        this.caEditorMode = "editor";
        await this.refreshChallengeAccess();
      } catch (err) {
        this.actionMsg = `Recipe failed: ${this.formatApiError(err)}`;
        console.error("[cfm-admin] challenge-access recipe failed", err);
      } finally {
        this.caBusy = false;
      }
    },
    // Load a single-entry recipe into the editor to tweak before saving.
    loadCARecipeIntoEditor() {
      const entries = this.caRecipePreview;
      if (entries.length !== 1) return;
      this.loadCAIntoForm(entries[0]); // no id on a recipe entry → opens as a new draft
      this.caEditorMode = "editor";
      this.caRecipeKey = "";
    },

    toggleCAChip(name) {
      this.caChips[name] = !this.caChips[name];
    },
    caMethodOn(m) {
      return this.caForm.methods.split(",").map((x) => x.trim().toUpperCase()).includes(m);
    },
    toggleCAMethod(m) {
      const cur = this.caForm.methods.split(",").map((x) => x.trim().toUpperCase()).filter(Boolean);
      const i = cur.indexOf(m);
      if (i >= 0) cur.splice(i, 1);
      else cur.push(m);
      this.caForm.methods = cur.join(", ");
    },
    addCABotGroup(key) {
      const g = this.caBotGroups.find((x) => x.key === key);
      if (!g) return;
      const cur = this.caForm.uas.split(",").map((x) => x.trim()).filter(Boolean);
      for (const p of g.patterns) if (!cur.includes(p)) cur.push(p);
      this.caForm.uas = cur.join(", ");
    },

    resetCAForm() {
      this.caForm = emptyCAForm();
      this.caEditID = "";
      this.caChips = { paths: false, uas: false, countries: false, ips: false, asns: false, methods: false, vbot: false };
      this.applyCAScopedDefault();
    },
    // Scoped tokens: prefill the vhost field with their own vhosts so a new
    // exemption is in-scope by default (the server enforces this regardless).
    applyCAScopedDefault() {
      if (this.isScoped && this.allowedVhosts.length && !this.caForm.vhosts.trim()) {
        this.caForm.vhosts = this.allowedVhosts.join(", ");
      }
    },
    loadCAIntoForm(entry, { duplicate = false } = {}) {
      this.caForm = caFormFromEntry(entry);
      this.caChips = { ...this.caChips, ...dimensionsPresent(entry) };
      this.caEditID = duplicate ? "" : (entry.id || "");
      if (duplicate) this.caForm.note = (this.caForm.note ? this.caForm.note + " " : "") + "(copy)";
      try { window.scrollTo({ top: 0, behavior: "smooth" }); } catch (e) { /* non-fatal */ }
    },
    duplicateCA(entry) {
      this.loadCAIntoForm(entry, { duplicate: true });
    },

    // A no-condition exemption downgrades the challenge for EVERY request on the
    // vhost (equivalent to turning the challenge off there). Confirm before
    // committing such a security-loosening entry as enabled — same guard the
    // rules page uses for a match-everything enabled rule.
    confirmWholeVhostExempt(body) {
      if (!body.enabled || Object.keys(body.match).length > 0) return true;
      const hosts = (body.scope?.vhosts || []).join(", ") || "the selected vhosts";
      return window.confirm(`This exemption has no conditions — it turns the challenge OFF for EVERY request on ${hosts}. Continue?`);
    },

    async saveCA() {
      if (!this.canSaveCA) return;
      const body = buildCAPayload(this.caForm);
      if (!this.confirmWholeVhostExempt(body)) return;
      this.caBusy = true;
      try {
        const path = this.caEditID
          ? `v1/challenge/access/update?id=${encodeURIComponent(this.caEditID)}`
          : "v1/challenge/access/add";
        await this.postJSON(path, body);
        this.actionMsg = this.caEditID ? "Exemption updated." : "Exemption added.";
        this.resetCAForm();
        await this.refreshChallengeAccess();
      } catch (err) {
        this.actionMsg = `Save failed: ${this.formatApiError(err)}`;
        console.error("[cfm-admin] challenge-access save failed", err);
      } finally {
        this.caBusy = false;
      }
    },
    async toggleCAEnabled(entry) {
      const body = buildCAPayload(caFormFromEntry(entry));
      body.enabled = !entry.enabled;
      if (!this.confirmWholeVhostExempt(body)) return;
      this.caBusy = true;
      try {
        await this.postJSON(`v1/challenge/access/update?id=${encodeURIComponent(entry.id)}`, body);
        await this.refreshChallengeAccess();
      } catch (err) {
        this.actionMsg = `Toggle failed: ${this.formatApiError(err)}`;
        console.error("[cfm-admin] challenge-access toggle failed", err);
      } finally {
        this.caBusy = false;
      }
    },
    async removeCA(entry) {
      if (!entry?.id) return;
      const hosts = (entry.scope?.vhosts || []).join(", ") || entry.id;
      if (!window.confirm(`Delete this challenge exemption for ${hosts}?`)) return;
      this.caBusy = true;
      try {
        await this.postJSON(`v1/challenge/access/remove?id=${encodeURIComponent(entry.id)}`, {});
        this.actionMsg = "Exemption removed.";
        if (this.caEditID === entry.id) this.resetCAForm();
        await this.refreshChallengeAccess();
      } catch (err) {
        this.actionMsg = `Remove failed: ${this.formatApiError(err)}`;
        console.error("[cfm-admin] challenge-access remove failed", err);
      } finally {
        this.caBusy = false;
      }
    },
  },

  watch: {
    allowedVhosts() { this.applyCAScopedDefault(); },
  },

  mounted() {
    // ?vhost=<host> deep-link (from the command palette / other pages) filters
    // the list to one vhost.
    try {
      const q = new URLSearchParams(window.location.search);
      const v = (q.get("vhost") || q.get("host") || "").trim().toLowerCase();
      if (v) this.caVhostFilter = v;
    } catch (e) { /* non-fatal */ }
    this.applyCAScopedDefault();
  },
};
