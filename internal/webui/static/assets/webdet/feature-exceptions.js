// Exceptions page: everything let through on purpose, in one place. Three
// tabs over state the page's other mixins already hold:
//
//   WAF, Challenge    feature-excludes.js (lists, add / remove, scoped guardrails)
//   Trusted clients   feature-challenge-access.js (the Challenge access editor)
//
// This mixin only adds the tabs, a text filter and the wording
// (excludes-model.js, tested). It was three places before: the same excludes
// card on the WAF engine, Forensics and WebDetector pages, and Challenge
// access on a page of its own.

import {
  EXCEPTION_TABS, exceptionTab, wafExcludeSkips, excludeWhere, filterExcludes, sortExcludes, excludeWhen,
} from "./excludes-model.js";

export const exceptionsMixin = {
  data() {
    let t = "waf", q = "";
    try {
      const u = new URL(window.location.href);
      t = exceptionTab(u.searchParams.get("tab") || "");
      q = String(u.searchParams.get("host") || "").trim().toLowerCase();
    } catch { /* no URL */ }
    return { exTab: t, exFilter: q };
  },
  computed: {
    exTabs() {
      const n = { waf: this.wafExcludes.length, challenge: this.challengeExcludes.length, trusted: Array.isArray(this.caEntries) ? this.caEntries.length : 0 };
      return EXCEPTION_TABS.map((t) => ({ ...t, count: n[t.key] }));
    },
    exWAFRows() { return sortExcludes(filterExcludes(this.wafExcludes, this.exFilter)); },
    exChallengeRows() { return sortExcludes(filterExcludes(this.challengeExcludes, this.exFilter)); },
    // A scoped session without exclude management sees the lists' tab bar
    // but not the excludes themselves (core.js shouldShow).
    exExcludesShown() { return this.shouldShow("excludes"); },
  },
  watch: {
    // A session that cannot manage excludes opens on the tab it can use.
    exExcludesShown: {
      immediate: true,
      handler(shown) { if (!shown && this.exTab !== "trusted") this.exTab = "trusted"; },
    },
  },
  methods: {
    exSkips: wafExcludeSkips,
    exWhere: excludeWhere,
    exWhen: excludeWhen,
    exSetTab(key) {
      this.exTab = exceptionTab(key);
      try {
        const u = new URL(window.location.href);
        u.searchParams.set("tab", this.exTab);
        window.history.replaceState(null, "", u.pathname + u.search);
      } catch { /* no history */ }
    },
  },
};
