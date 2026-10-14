// Traffic Rules page: Cloudflare-style per-vhost rules (allow / block /
// challenge / throttle) built through a guided editor ("what should happen →
// which requests → where"), multi-rule recipes, and a simulator that shows
// the live verdict plus any DISABLED rule that would match if enabled.
//
// All rule semantics (validation mirroring the daemon, plain-language
// descriptions, priority bands, bot groups, recipes) live in rules-model.js —
// pure and unit-tested. This mixin only wires them to Vue and to the
// scope-filtered /api/v1/webdet/rules/* API, which is unchanged: it works for
// admins and (own vhosts only) scoped users alike.
//
// Facts this page must keep telling the operator (see
// docs/traffic-rules-ux-proposal.md §1): `allow` only ends rule evaluation —
// it does not bypass WAF/challenge/IP blocks; clearance-cookie holders skip
// the rules entirely; rules run only on the in-path edge (OpenResty/Angie),
// never in DNAT mode.

import {
  ACTIONS,
  BOT_GROUPS,
  KNOWN_METHODS,
  RECIPES,
  THROTTLE_PROFILES,
  VERIFIED_BOT_LABEL,
  actionInfo,
  buildRulePayload,
  csvSplit,
  describeMatch,
  describeRule,
  emptyForm,
  formFromRule,
  hasAnyMatch,
  positionText,
  priorityTie,
  recipe as recipeByKey,
  recipeOf,
  recipeVarsDefaults,
  shadowingRules,
  simulateInputFromRule,
  suggestPriority,
  validateRecipeVars,
  validateRuleForm,
} from "./rules-model.js";
import {
  docVhosts,
  exportFileName,
  exportPath,
  importPath,
  itemTone,
  parseExportFile,
  planSummary,
} from "./rules-transfer.js";

const CHIP_KEYS = ["paths", "uas", "countries", "ips", "vbot", "methods", "qs"];

function chipsFromForm(form) {
  return {
    paths: Boolean(form.paths),
    uas: Boolean(form.uas),
    countries: Boolean(form.countries),
    ips: Boolean(form.ips),
    vbot: Boolean(form.verifiedBot),
    methods: Boolean(form.methods),
    qs: Boolean(form.hasQS || form.qsNotRx),
  };
}

export const rulesMixin = {
  data() {
    return {
      rules: [],
      rulesSearch: "",
      rulesVhostFilter: "",
      rulesBusy: false,

      // Static model tables exposed to the template (frozen → not made reactive).
      ruleActions: ACTIONS,
      botGroups: BOT_GROUPS,
      throttleProfiles: THROTTLE_PROFILES,
      knownMethods: KNOWN_METHODS,
      recipes: RECIPES,

      // Editor
      editorMode: "editor", // "editor" | "recipes"
      ruleEditID: "",
      ruleForm: emptyForm(),
      ruleChips: chipsFromForm(emptyForm()),
      priorityAuto: true,

      // Recipes
      recipeKey: "",
      recipeVars: {},

      // Simulator
      simulateForm: { host: "", ip: "", ua: "", path: "/", method: "GET", country: "", qs: "", verifiedBot: "" },
      verifiedBotLabel: VERIFIED_BOT_LABEL,
      simulateResult: null,
      simulateRequest: null, // the request that produced simulateResult (not the live form)
      simulateNote: "",

      // Export / import (moving a site's rules between nodes)
      transferDoc: null, // the parsed export file
      transferFileName: "",
      transferDisabled: false,
      transferPlan: null, // the daemon's import plan (dry run or result)
      transferDone: false, // transferPlan is the result of a real import
      transferError: "",
    };
  },

  computed: {
    rulesFiltered() {
      const q = String(this.rulesSearch || "").trim().toLowerCase();
      const vh = String(this.rulesVhostFilter || "").trim().toLowerCase();
      return this.rules.filter((row) => {
        const hosts = Array.isArray(row?.scope?.vhosts) ? row.scope.vhosts.map((h) => String(h).toLowerCase()) : [];
        if (vh && !hosts.includes(vh)) return false;
        if (!q) return true;
        const hostStr = hosts.join(",");
        const note = String(row?.note || "").toLowerCase();
        return String(row?.id || "").toLowerCase().includes(q)
          || hostStr.includes(q)
          || note.includes(q)
          || String(row?.action?.type || "").toLowerCase().includes(q)
          || this.ruleMatchSummary(row).toLowerCase().includes(q);
      });
    },
    ruleVhostOptions() {
      const set = new Set();
      for (const r of this.rules) for (const h of r?.scope?.vhosts || []) set.add(String(h).toLowerCase());
      return [...set].sort();
    },
    rulePayload() {
      return buildRulePayload(this.ruleForm);
    },
    ruleValidation() {
      return validateRuleForm(this.ruleForm, { rules: this.rules, editId: this.ruleEditID });
    },
    ruleSentence() {
      const p = this.rulePayload;
      if (!p.action.type) return "";
      return describeRule(p, { max: 4 });
    },
    rulePositionText() {
      const p = this.rulePayload;
      if (!p.priority) return "";
      return positionText(p.priority, this.rules, { excludeId: this.ruleEditID, vhosts: p.scope.vhosts });
    },
    chosenAction() {
      return actionInfo(this.ruleForm.actionType);
    },
    ruleHasNoMatch() {
      return !hasAnyMatch(this.rulePayload.match);
    },
    canSaveRule() {
      return !this.rulesBusy && this.ruleValidation.errors.length === 0;
    },
    // Recipes
    selectedRecipe() {
      return recipeByKey(this.recipeKey);
    },
    recipeVarErrors() {
      return this.selectedRecipe ? validateRecipeVars(this.selectedRecipe, this.recipeVars) : [];
    },
    recipePreview() {
      const rcp = this.selectedRecipe;
      if (!rcp || rcp.kind === "link" || this.recipeVarErrors.length) return [];
      try {
        return rcp.build(this.recipeVars);
      } catch (err) {
        console.error("[cfm-admin] recipe build failed", err);
        return [];
      }
    },
    // Ties/duplicates the recipe's fixed priorities would create against the
    // rules already stored for these vhosts (the editor path warns about the
    // same thing through validateRuleForm; recipes must not look cleaner).
    recipePreviewWarnings() {
      const rcp = this.selectedRecipe;
      const rows = this.recipePreview;
      if (!rcp || !rows.length) return [];
      const out = [];
      // Union of every row's scope: a recipe may scope its rules to different
      // vhost sets (lock_panel_subdomains), so rows[0] alone would miss a re-apply.
      const vhosts = [...new Set(rows.flatMap((p) => (p.scope?.vhosts || []).map((h) => String(h).toLowerCase())))];
      const already = this.rules.filter((r) => recipeOf(r) === rcp.key && (r.scope?.vhosts || []).some((h) => vhosts.includes(String(h).toLowerCase())));
      if (already.length) out.push(`This recipe was already applied to ${vhosts.join(", ")} (${already.map((r) => r.id).join(", ")}). Creating it again duplicates those rules.`);
      for (const p of rows) {
        const tie = priorityTie(p.priority, p.scope.vhosts, this.rules);
        if (tie) out.push(`Rule #${p.priority} ties with existing ${tie.id} (${tie.action?.type || "?"}) — ties are resolved by id order, which is not predictable.`);
        const shadow = shadowingRules(p, this.rules);
        if (shadow.length) out.push(`Rule #${p.priority} (${p.action?.type}) is shadowed by existing ${shadow.map((r) => `${r.id} (#${r.priority} ${r.action?.type})`).join(", ")}: first match wins, so the crawlers those rules cover (verified / listed User-Agents) never reach it. Disable or narrow them on this vhost, or accept that those crawlers only get that earlier verdict.`);
      }
      return [...new Set(out)];
    },
    // Simulator
    simulateVerdict() {
      const r = this.simulateResult;
      if (!r) return null;
      if (r.matched) {
        return {
          tone: this.actionTone(r.action),
          text: `${r.action}${r.profile ? ` (${r.profile})` : ""} — rule ${r.rule?.id || "?"} · ${describeRule(r.rule || {}, { max: 3 })}`,
        };
      }
      return { tone: "", text: "No enabled rule matches — the request proceeds to the normal challenge / WAF decision." };
    },
    transferSummary() {
      return planSummary(this.transferPlan);
    },
    transferVhosts() {
      return docVhosts(this.transferDoc);
    },
    simulateDisabledText() {
      const d = this.simulateResult?.disabled_match;
      if (!d) return "";
      return `Disabled rule ${d.id} would ${d.action?.type || "match"} this request if enabled — ${describeRule(d, { max: 3 })}`;
    },
    // What the evaluation assumed about the client being a verified crawler.
    // Shown whenever a rule in the set uses verified_bot, so a "did not match"
    // on such a rule is explained by the verdict rather than left to guesswork.
    simulateVerifiedBotText() {
      const r = this.simulateResult;
      if (!r) return "";
      const anyRule = this.rules.some((x) => x?.match?.verified_bot);
      if (!anyRule && !r.verified_bot) return "";
      const req = this.simulateRequest || {};
      if (r.verified_bot) {
        if (req.verified_bot) return `Treated as a verified crawler (${r.verified_bot}) because the override was ticked for this run.`;
        if (r.verified_bot_inconclusive) return `Cached (stale) verdict "${r.verified_bot}" was used: the inline re-verify did not complete (${r.verified_bot_inconclusive}). Live traffic from this IP is still treated as a crawler until the verdict ages out.`;
        return `IP verified as crawler "${r.verified_bot}" (reverse DNS forward-confirmed).`;
      }
      if (r.verified_bot_inconclusive === "not_checked") return "";
      if (r.verified_bot_excluded) {
        return `Reverse DNS forward-confirmed as "${r.verified_bot_excluded}", which is deliberately NOT a crawler for rules (Google's user-driven fetchers: Translate / AMP proxies). verified_bot rules do not match it — by design, not a DNS problem.`;
      }
      if (r.verified_bot_inconclusive) {
        const why = {
          timeout: "all crawler-verification slots were busy for the whole wait",
          transient: "the DNS resolver failed mid-check",
          no_resolver: "IP enrichment is OFF on this daemon (ENRICH), so nothing can be verified — verified_bot rules cannot match live traffic here either",
          no_bridge: "the in-path edge bridge is not running on this daemon",
        }[r.verified_bot_inconclusive] || r.verified_bot_inconclusive;
        return `Crawler verification was NOT completed (${why}). This is not a negative: the rule set was evaluated with the IP treated as unverified. Retry, or tick the override to test the crawler path.`;
      }
      if (!String(req.ip || "").trim()) {
        return "No IP in the sample, so crawler verification was not attempted: verified_bot rules cannot match it. Add the crawler's IP, or tick the override.";
      }
      return "Not a verified crawler: the IP's reverse DNS did not forward-confirm to a known good bot, so verified_bot rules do not match. Tick the override to test the crawler path.";
    },
  },

  watch: {
    "ruleForm.actionType"() { this.maybeAutoPriority(); },
    "ruleForm.vhosts"() { this.maybeAutoPriority(); },
  },

  methods: {
    // ── Presentation helpers ────────────────────────────────────────────
    actionTone(type) {
      return actionInfo(type)?.tone || "";
    },
    ruleMatchSummary(row) {
      return describeMatch(row?.match || {}, { max: 3 });
    },
    ruleRecipe(row) {
      return recipeOf(row);
    },
    ruleNoteText(row) {
      // Strip the "recipe:<key> — " tag: it is shown as a pill instead.
      return String(row?.note || "").replace(/^recipe:[a-z0-9_]+\s*[—-]\s*/i, "");
    },
    throttleProfileLabel(key) {
      return THROTTLE_PROFILES.find((p) => p.key === key)?.label || key;
    },

    // ── Editor state ─────────────────────────────────────────────────────
    setEditorMode(mode) {
      this.editorMode = ["recipes", "transfer"].includes(mode) ? mode : "editor";
    },
    setAction(key) {
      const act = actionInfo(key);
      if (!act) return;
      this.ruleForm.actionType = act.key;
      // Enforcing actions start disabled unless we are editing a saved rule:
      // "save disabled → simulate → enable" is the intended path.
      if (!this.ruleEditID) this.ruleForm.enabled = act.key === "allow" || act.key === "throttle";
    },
    toggleChip(key) {
      if (!CHIP_KEYS.includes(key)) return;
      const on = !this.ruleChips[key];
      this.ruleChips[key] = on;
      // Verified crawler is a boolean condition: the chip IS the switch.
      if (key === "vbot") { this.ruleForm.verifiedBot = on; return; }
      if (on) return;
      // Turning a chip off clears its condition so the review sentence and
      // the saved rule never carry a hidden field.
      if (key === "qs") { this.ruleForm.hasQS = false; this.ruleForm.qsNotRx = ""; }
      else if (key === "countries") { this.ruleForm.countries = ""; this.ruleForm.countriesMode = "in"; }
      else this.ruleForm[key] = "";
    },
    addBotGroup(key) {
      const g = BOT_GROUPS.find((x) => x.key === key);
      if (!g) return;
      const cur = csvSplit(this.ruleForm.uas);
      const merged = [...cur];
      for (const p of g.patterns) if (!merged.includes(p)) merged.push(p);
      this.ruleForm.uas = merged.join(", ");
      this.ruleChips.uas = true;
    },
    toggleMethod(m) {
      const cur = csvSplit(this.ruleForm.methods).map((x) => x.toUpperCase());
      const i = cur.indexOf(m);
      if (i >= 0) cur.splice(i, 1); else cur.push(m);
      this.ruleForm.methods = cur.join(", ");
    },
    methodOn(m) {
      return csvSplit(this.ruleForm.methods).map((x) => x.toUpperCase()).includes(m);
    },
    onPriorityInput() {
      this.priorityAuto = false;
    },
    maybeAutoPriority() {
      if (!this.priorityAuto || this.ruleEditID) return;
      const p = this.rulePayload;
      if (!p.action.type) return;
      this.ruleForm.priority = suggestPriority(p.action.type, this.rules, p.scope.vhosts);
    },
    resetRuleForm() {
      this.ruleEditID = "";
      this.ruleForm = emptyForm();
      this.ruleChips = chipsFromForm(this.ruleForm);
      this.priorityAuto = true;
    },
    loadRuleIntoForm(row) {
      if (!row) return;
      this.editorMode = "editor";
      this.ruleEditID = String(row.id || "");
      this.ruleForm = formFromRule(row);
      this.ruleChips = chipsFromForm(this.ruleForm);
      this.priorityAuto = false;
    },
    duplicateRule(row) {
      if (!row) return;
      this.editorMode = "editor";
      this.ruleEditID = "";
      this.ruleForm = formFromRule(row);
      this.ruleForm.enabled = false;
      this.ruleForm.priority = 0;
      this.ruleForm.note = this.ruleNoteText(row) ? `copy of ${this.ruleNoteText(row)}` : `copy of ${row.id}`;
      this.ruleChips = chipsFromForm(this.ruleForm);
      this.priorityAuto = true;
      this.maybeAutoPriority();
      this.actionMsg = `Duplicated ${row.id} into the editor (saved disabled, new priority).`;
    },
    loadPayloadIntoForm(payload) {
      this.editorMode = "editor";
      this.ruleEditID = "";
      this.ruleForm = formFromRule(payload);
      this.ruleChips = chipsFromForm(this.ruleForm);
      this.priorityAuto = false;
    },

    // ── API ──────────────────────────────────────────────────────────────
    async refreshRules() {
      if (!this.shouldShow("rules")) return;
      const payload = await this.fetchJSONSafe("v1/webdet/rules", { rows: [] });
      this.rules = this.extractRows(payload, "rows");
    },
    async saveRule() {
      const v = this.ruleValidation;
      if (v.errors.length) {
        this.actionMsg = `Rule not saved: ${v.errors[0]}`;
        return;
      }
      const payload = { ...v.payload };
      if (!payload.priority) payload.priority = suggestPriority(payload.action.type, this.rules, payload.scope.vhosts);
      this.rulesBusy = true;
      try {
        if (this.ruleEditID) {
          await this.postJSON(`v1/webdet/rules/update?id=${encodeURIComponent(this.ruleEditID)}`, payload);
          this.actionMsg = `Rule updated: ${this.ruleEditID}`;
        } else {
          const out = await this.postJSON("v1/webdet/rules/add", payload);
          const id = out?.rule?.id || "(new)";
          this.actionMsg = payload.enabled
            ? `Rule added and ENABLED: ${id}`
            : `Rule added (disabled): ${id} — run the simulator, then enable it from the table.`;
        }
        await this.refreshRules();
        this.resetRuleForm();
      } catch (err) {
        this.actionMsg = `Rule save failed: ${this.formatApiError(err)}`;
        console.error("[cfm-admin] rule save failed", err);
      } finally {
        this.rulesBusy = false;
      }
    },
    async toggleRuleEnabled(row) {
      const id = String(row?.id || "").trim();
      if (!id) return;
      const next = !row.enabled;
      if (next && !this.ruleMatchNarrows(row) && row?.action?.type !== "allow") {
        const ok = window.confirm(`Enable ${id}? It has NO conditions and its ${row.action?.type} action will apply to EVERY request on ${(row.scope?.vhosts || []).join(", ")}.`);
        if (!ok) return;
      }
      this.rulesBusy = true;
      try {
        await this.postJSON(`v1/webdet/rules/update?id=${encodeURIComponent(id)}`, { ...row, enabled: next });
        this.actionMsg = `Rule ${id} ${next ? "ENABLED" : "disabled"}.`;
        await this.refreshRules();
      } catch (err) {
        this.actionMsg = `Rule toggle failed: ${this.formatApiError(err)}`;
        console.error("[cfm-admin] rule toggle failed", err);
      } finally {
        this.rulesBusy = false;
      }
    },
    ruleMatchNarrows(row) {
      return hasAnyMatch(row?.match || {});
    },
    async removeRule(row) {
      const id = String(row?.id || "").trim();
      if (!id) return;
      if (!window.confirm(`Delete rule ${id}?\n${describeRule(row)}`)) return;
      this.rulesBusy = true;
      try {
        await this.postJSON(`v1/webdet/rules/remove?id=${encodeURIComponent(id)}`, {});
        this.actionMsg = `Rule removed: ${id}`;
        await this.refreshRules();
        if (this.ruleEditID === id) this.resetRuleForm();
      } catch (err) {
        this.actionMsg = `Rule remove failed: ${this.formatApiError(err)}`;
        console.error("[cfm-admin] rule remove failed", err);
      } finally {
        this.rulesBusy = false;
      }
    },

    // ── Recipes ─────────────────────────────────────────────────────────
    selectRecipe(key) {
      const rcp = recipeByKey(key);
      if (!rcp) return;
      this.recipeKey = rcp.key;
      const vh = this.rulesVhostFilter || this.rulePayload.scope.vhosts[0] || "";
      this.recipeVars = recipeVarsDefaults(rcp, { vhosts: vh });
    },
    recipeRuleSentence(payload) {
      return describeRule(payload, { max: 3 });
    },
    recipeRuleNote(payload) {
      return this.ruleNoteText(payload);
    },
    async createRecipeRules() {
      const rcp = this.selectedRecipe;
      const rows = this.recipePreview;
      if (!rcp || !rows.length || this.recipeVarErrors.length) return;
      const enabledCount = rows.filter((r) => r.enabled).length;
      const ok = window.confirm(
        `Create ${rows.length} rule(s) for ${rcp.title}?\n${enabledCount} will be enabled immediately, ${rows.length - enabledCount} saved disabled.`,
      );
      if (!ok) return;
      this.rulesBusy = true;
      const created = [];
      try {
        for (const payload of rows) {
          const out = await this.postJSON("v1/webdet/rules/add", payload);
          created.push(out?.rule?.id || "?");
        }
        this.actionMsg = `Recipe "${rcp.title}": created ${created.length} rule(s) (${created.join(", ")}). Search "recipe:${rcp.key}" to see them together.`;
        this.rulesSearch = `recipe:${rcp.key}`;
        await this.refreshRules();
      } catch (err) {
        this.actionMsg = `Recipe stopped after ${created.length}/${rows.length} rule(s): ${this.formatApiError(err)}. Created so far: ${created.join(", ") || "none"}.`;
        console.error("[cfm-admin] recipe create failed", err);
        await this.refreshRules();
      } finally {
        this.rulesBusy = false;
      }
    },
    loadRecipeIntoEditor() {
      const rows = this.recipePreview;
      if (!rows.length) return;
      this.loadPayloadIntoForm(rows[0]);
      this.actionMsg = `Loaded "${this.selectedRecipe?.title}" into the editor — review, then save.`;
    },

    // ── Export / import ─────────────────────────────────────────────────
    // The daemon validates, de-duplicates and scope-checks the import and
    // writes it all-or-nothing (traffic_rules_transfer.go); the page always
    // shows the dry-run plan first and imports exactly the previewed file.
    transferItemTone(status) {
      return itemTone(status);
    },
    async exportRules() {
      const vh = this.rulesVhostFilter;
      try {
        const doc = await this.fetchJSON(exportPath(vh));
        const n = (doc?.rules || []).length;
        if (!n) {
          this.actionMsg = `Export: no rules${vh ? ` scoped to ${vh}` : ""}.`;
          return;
        }
        const name = exportFileName(vh);
        const blob = new Blob([`${JSON.stringify(doc, null, 2)}\n`], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        const skipped = Number(doc?.skipped_unsupported) || 0;
        this.actionMsg = `Exported ${n} rule(s) to ${name}.${skipped ? ` ${skipped} rule(s) written by a newer cfm were left out.` : ""}`;
      } catch (err) {
        this.actionMsg = `Export failed: ${this.formatApiError(err)}`;
        console.error("[cfm-admin] rules export failed", err);
      }
    },
    resetTransfer() {
      this.transferDoc = null;
      this.transferFileName = "";
      this.transferPlan = null;
      this.transferDone = false;
      this.transferError = "";
      const input = this.$refs?.rulesImportFile;
      if (input) input.value = "";
    },
    async onImportFile(ev) {
      const file = ev?.target?.files?.[0];
      this.transferDoc = null;
      this.transferPlan = null;
      this.transferDone = false;
      this.transferError = "";
      this.transferFileName = file ? file.name : "";
      if (!file) return;
      if (file.size > 2 * 1024 * 1024) {
        this.transferError = "The file is larger than 2 MiB, more than this page can import. Split it, or import it with \"cfm webtop rules import\" in parts.";
        return;
      }
      let text = "";
      this.rulesBusy = true; // the file input stays disabled while it is read
      try {
        text = await file.text();
      } catch (err) {
        this.transferError = `Could not read the file: ${err?.message || err}`;
        return;
      } finally {
        this.rulesBusy = false;
      }
      const { doc, error } = parseExportFile(text);
      if (error) {
        this.transferError = error;
        return;
      }
      this.transferDoc = doc;
      await this.previewImport();
    },
    onTransferDisabledChange(ev) {
      this.transferDisabled = Boolean(ev?.target?.checked);
      // The plan shows enabled states, so a changed checkbox needs a new one.
      if (this.transferDoc && !this.transferDone) this.previewImport();
    },
    // postImport returns the daemon's plan: a 400 still carries one (which
    // rule is invalid and why), so it is read from the error too.
    async postImport(dryRun) {
      try {
        return await this.postJSON(importPath({ dryRun, disabled: this.transferDisabled }), this.transferDoc);
      } catch (err) {
        if (err?.data && Array.isArray(err.data.items)) return err.data;
        throw err;
      }
    },
    async previewImport() {
      if (!this.transferDoc) return;
      this.rulesBusy = true;
      this.transferError = "";
      try {
        this.transferPlan = await this.postImport(true);
        this.transferDone = false;
      } catch (err) {
        this.transferPlan = null;
        this.transferError = `Preview failed: ${this.formatApiError(err)}`;
        console.error("[cfm-admin] rules import preview failed", err);
      } finally {
        this.rulesBusy = false;
      }
    },
    async runImport() {
      if (!this.transferDoc || !this.transferSummary.canImport) return;
      const add = Number(this.transferPlan?.add) || 0;
      const enabled = (this.transferPlan?.items || []).filter((it) => it.status === "add" && it.rule?.enabled).length;
      const ok = window.confirm(
        `Import ${add} rule(s) from ${this.transferFileName}?\n${enabled} will be enforced immediately, ${add - enabled} saved disabled.`,
      );
      if (!ok) return;
      this.rulesBusy = true;
      this.transferError = "";
      try {
        const plan = await this.postImport(false);
        this.transferPlan = plan;
        if (plan?.error) {
          // Nothing was written. Show what changed (e.g. another import added
          // the same rules meanwhile) with a fresh preview.
          this.rulesBusy = false;
          await this.previewImport();
          this.transferError = `Import failed, nothing was written: ${plan.error}. The preview below is up to date.`;
          return;
        }
        this.transferDone = true;
        const ids = plan?.added || [];
        this.actionMsg = `Imported ${ids.length} rule(s) from ${this.transferFileName}${ids.length ? ` (${ids.join(", ")})` : ""}.`;
        await this.refreshRules();
      } catch (err) {
        this.transferError = `Import failed: ${this.formatApiError(err)}`;
        console.error("[cfm-admin] rules import failed", err);
      } finally {
        this.rulesBusy = false;
      }
    },

    // ── Simulator ───────────────────────────────────────────────────────
    async prefillSimulatorFromDraft() {
      const p = this.rulePayload;
      this.simulateForm = simulateInputFromRule(p);
      this.simulateNote = this.ruleEditID
        ? ""
        : "This draft is not saved yet, so the verdict reflects saved rules only. Save it disabled and the simulator will report it as \"would match if enabled\".";
      this.simulateResult = null;
      if (!this.simulateForm.host) {
        this.actionMsg = "Add a vhost to the draft first.";
        return;
      }
      await this.runRuleSimulation();
      if (!this.ruleEditID) return;
      // Editing: the daemon evaluated the SAVED rule, not this draft. Only
      // attribute the outcome to the rule when the draft is unchanged.
      const saved = this.rules.find((r) => String(r?.id) === this.ruleEditID);
      const unchanged = saved && JSON.stringify(buildRulePayload(formFromRule(saved))) === JSON.stringify(p);
      this.simulateNote = unchanged
        ? this.explainTestOutcome(saved)
        : `This draft has unsaved changes, so the verdict reflects the SAVED version of ${this.ruleEditID} (and the other saved rules). Update the rule, then test again.`;
    },
    async testRule(row) {
      this.simulateForm = simulateInputFromRule(row);
      this.simulateNote = "";
      await this.runRuleSimulation();
      this.simulateNote = this.explainTestOutcome(row);
    },
    // explainTestOutcome says, for the rule the operator clicked Test on,
    // whether the sample request actually REACHED it. Only assert "shadowed"
    // when a rule demonstrably ran first — lower priority, or equal priority
    // with a lower id (the daemon's tie-break) — otherwise the honest answer is
    // that the sample did not match this rule. The simulator reports only the
    // FIRST disabled match, so for a disabled rule an earlier disabled match
    // hides it regardless of whether an enabled rule won later.
    explainTestOutcome(row) {
      const id = String(row?.id || "");
      const prio = Number(row?.priority);
      const r = this.simulateResult;
      if (!id || !r) return "";
      const runsBefore = (other) => Number.isFinite(prio) && other &&
        (Number(other.priority) < prio || (Number(other.priority) === prio && String(other.id) < id));
      if (r.matched && r.rule?.id === id) return `Rule ${id} is the verdict for this request.`;
      if (r.disabled_match?.id === id) return `Rule ${id} is disabled: it would be the verdict if enabled.`;
      const winner = r.matched ? r.rule : null;
      if (winner && runsBefore(winner)) {
        const tie = Number(winner.priority) === prio ? " (same priority — ties are resolved by id order)" : "";
        return `Rule ${id} was NOT reached: enabled rule ${winner.id} (priority ${winner.priority})${tie} wins first for requests shaped like this one, so enabling or editing ${id} changes nothing for them.`;
      }
      if (row?.enabled === false && r.disabled_match && runsBefore(r.disabled_match)) {
        return `Rule ${id} is hidden here: disabled rule ${r.disabled_match.id} (priority ${r.disabled_match.priority}) precedes it and the simulator reports only the first disabled match. Enable ${id}, or test with a request the earlier rule does not match, to see whether ${id} matches.`;
      }
      return `The sample request did not match rule ${id}'s conditions (${winner ? `rule ${winner.id} matched instead` : "no rule matched"}). Adjust the simulator fields to a request the rule should catch and run again.`;
    },
    async runRuleSimulation() {
      const req = {
        host: String(this.simulateForm.host || "").trim(),
        ip: String(this.simulateForm.ip || "").trim(),
        ua: String(this.simulateForm.ua || "").trim(),
        path: String(this.simulateForm.path || "/").trim(),
        method: String(this.simulateForm.method || "GET").trim().toUpperCase(),
        country: String(this.simulateForm.country || "").trim().toUpperCase(),
        qs: String(this.simulateForm.qs || "").trim(),
      };
      // Override: "test as a verified crawler". Left empty, the daemon
      // resolves the real FCrDNS verdict for the IP (inline, simulate only).
      if (this.simulateForm.verifiedBot) req.verified_bot = String(this.simulateForm.verifiedBot);
      if (!req.host) {
        this.actionMsg = "Simulation host is required.";
        return;
      }
      try {
        this.simulateResult = await this.postJSON("v1/webdet/rules/simulate", req);
        this.simulateRequest = req;
        this.actionMsg = this.simulateResult?.matched
          ? `Simulation: ${this.simulateResult.action} by rule ${this.simulateResult?.rule?.id || ""}`
          : (this.simulateResult?.disabled_match
            ? `Simulation: no enabled rule matches; disabled rule ${this.simulateResult.disabled_match.id} would.`
            : "Simulation: no matching rule.");
      } catch (err) {
        this.simulateResult = null;
        this.actionMsg = `Simulation failed: ${this.formatApiError(err)}`;
        console.error("[cfm-admin] rule simulation failed", err);
      }
    },
  },
};
