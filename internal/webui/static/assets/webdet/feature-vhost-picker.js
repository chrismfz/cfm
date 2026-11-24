// Vhost page: the host picker. The host field opens a list of every host the
// caller may see, each with chips for what is going on there (challenged,
// suspicious, excludes, cache, rules…), the ones that need attention first.
// Typing filters it; arrows and Enter pick.
//
// Admins and scoped (cPanel) callers alike: v1/webdet/vhosts and
// v1/webdet/suspicious are scope-filtered by the daemon, and the challenged
// hosts are the page's own activeChallengeVhosts (feature-challenge.js), which
// is scope-filtered too. Wording and order: vhost-picker-model.js (tested).

import { hostSet, entries, attentionCount } from "./vhost-picker-model.js";

const PICKER_STALE_MS = 60_000;

export const vhostPickerMixin = {
  data() {
    return {
      vpkOpen: false,
      vpkQuery: "",
      vpkIndex: 0,
      vpkMoved: false,
      vpkRows: [],
      vpkSuspicious: [],
      vpkLoadedAt: 0,
      vpkLoading: false,
    };
  },

  computed: {
    vpkCtx() {
      return { challenged: hostSet(this.activeChallengeVhosts), suspicious: hostSet(this.vpkSuspicious) };
    },
    vpkList() { return entries(this.vpkRows, this.vpkCtx, this.vpkQuery, 200); },
    vpkAttention() { return attentionCount(this.vpkRows, this.vpkCtx); },
  },

  methods: {
    async vpkLoad(force = false) {
      if (this.vpkLoading) return;
      if (!force && this.vpkRows.length && Date.now() - this.vpkLoadedAt < PICKER_STALE_MS) return;
      this.vpkLoading = true;
      try {
        const [vhosts, suspicious] = await Promise.all([
          this.fetchJSONSafe("v1/webdet/vhosts", { rows: [] }),
          this.fetchJSONSafe("v1/webdet/suspicious?limit=500", []),
        ]);
        this.vpkRows = this.extractRows(vhosts, "rows");
        this.vpkSuspicious = this.extractRows(suspicious, "rows");
        this.vpkLoadedAt = Date.now();
      } finally {
        this.vpkLoading = false;
      }
    },
    vpkShow() {
      this.vpkOpen = true;
      this.vpkLoad();
    },
    vpkFocus() {
      // Show the whole list on focus, not just the host already in the field.
      this.vpkQuery = "";
      this.vpkIndex = 0;
      this.vpkMoved = false;
      this.vpkShow();
    },
    vpkTyped() {
      this.vpkQuery = this.vhostFocusHost;
      this.vpkIndex = 0;
      this.vpkMoved = false;
      this.vpkShow();
    },
    vpkMove(step) {
      if (!this.vpkOpen) { this.vpkShow(); return; }
      const n = this.vpkList.items.length;
      if (!n) return;
      this.vpkIndex = (this.vpkIndex + step + n) % n;
      this.vpkMoved = true;
      this.$nextTick(() => {
        const el = document.getElementById(`vpk-opt-${this.vpkIndex}`);
        if (el) el.scrollIntoView({ block: "nearest" });
      });
    },
    // Enter opens the highlighted host once the user typed or moved through
    // the list; otherwise it opens what the field holds (an unknown host too).
    vpkEnter() {
      const item = this.vpkOpen ? this.vpkList.items[this.vpkIndex] : null;
      if (item && (this.vpkQuery || this.vpkMoved)) this.vpkPick(item.host);
      else { this.vpkOpen = false; this.applyVhostFocus(); }
    },
    vpkPick(host) {
      this.vhostFocusHost = host;
      this.vpkOpen = false;
      this.vpkQuery = "";
      this.applyVhostFocus();
    },
    vpkBlur() {
      // A click on an option lands after the blur: close a moment later.
      setTimeout(() => { this.vpkOpen = false; }, 150);
    },
  },
};
