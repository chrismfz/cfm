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
  simulateInputFromRule,
  suggestPriority,
  validateRecipeVars,
  validateRuleForm,
} from "./rules-model.js";

const CHIP_KEYS = ["paths", "uas", "countries", "ips", "methods", "qs"];

function chipsFromForm(form) {
  return {
    paths: Boolean(form.paths),
    uas: Boolean(form.uas),
    countries: Boolean(form.countries),
    ips: Boolean(form.ips),
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
      simulateForm: { host: "", ip: "", ua: "", path: "/", method: "GET", country: "", qs: "" },
      simulateResult: null,
      simulateNote: "",
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
      const vhosts = rows[0].scope.vhosts.map((h) => h.toLowerCase());
      const already = this.rules.filter((r) => recipeOf(r) === rcp.key && (r.scope?.vhosts || []).some((h) => vhosts.includes(String(h).toLowerCase())));
      if (already.length) out.push(`This recipe was already applied to ${vhosts.join(", ")} (${already.map((r) => r.id).join(", ")}). Creating it again duplicates those rules.`);
      for (const p of rows) {
        const tie = priorityTie(p.priority, p.scope.vhosts, this.rules);
        if (tie) out.push(`Rule #${p.priority} ties with existing ${tie.id} (${tie.action?.type || "?"}) — ties are resolved by id order, which is not predictable.`);
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
    simulateDisabledText() {
      const d = this.simulateResult?.disabled_match;
      if (!d) return "";
      return `Disabled rule ${d.id} would ${d.action?.type || "match"} this request if enabled — ${describeRule(d, { max: 3 })}`;
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
      this.editorMode = mode === "recipes" ? "recipes" : "editor";
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
        const ok = window.confirm(`Enable ${id}? It has NO conditions and will ${row.action?.type} EVERY request on ${(row.scope?.vhosts || []).join(", ")}.`);
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
      if (!req.host) {
        this.actionMsg = "Simulation host is required.";
        return;
      }
      try {
        this.simulateResult = await this.postJSON("v1/webdet/rules/simulate", req);
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
