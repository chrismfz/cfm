// Webdetector page factory: shared boot (auth/token/scoped identity), the
// refresh loop, formatting helpers and cross-page navigation. Feature state
// and methods live in the feature-*.js mixins; each page entry passes only
// the mixins its sections actually use, so a page never fetches or carries
// logic for cards it doesn't render.
//
// Extracted from the old assets/app.js monolith - the logic is moved, not
// rewritten; refreshAll() calls feature hooks via optional chaining in the
// same order the monolith ran them.

import { expandPartials } from "./partials.js";

export function createWebdetApp(config) {
  const pageMode = String(config.pageMode || "overview");
  const sections = new Set(config.sections || []);
  const mixins = config.mixins || [];
  const autoRefreshByDefault = config.autoRefresh !== false;

  const { createApp } = window.Vue;
  let _appVm = null;
  const controller = window.CFMControllerBootstrap.initSharedController({
    onDeferredScopedToken: () => {
      if (!_appVm || typeof _appVm.onLateScopedToken !== "function") return;
      _appVm.onLateScopedToken().catch((err) => {
        console.error("[cfm-webui] late token re-init failed", err);
      });
    },
  });

  function waitForScopedToken(timeoutMs = 1200) {
    return controller.waitForToken(timeoutMs);
  }
  let _adminApiClient = null;
  function getAdminApiClient() {
    if (!_adminApiClient) {
      _adminApiClient = controller.createApiClient({
        basePath: "/cfm-admin/api",
        isScoped: () => Boolean(_appVm && _appVm.isScopedMode),
      });
    }
    return _adminApiClient;
  }

  const coreMixin = {
    data() {
      return {
        loading: false,
        autoRefresh: autoRefreshByDefault,
        refreshIntervalSec: 5,
        timer: null,
        refreshInProgress: false,
        actionMsg: "",
        pageMode,
        // Token / identity state
        isAdmin: false,
        isScopedMode: false,
        tokenRole: "viewer",
        allowedVhosts: [],
        scopedExcludeManagementAllowed: true,
        scopedPathExcludeAllowed: false,
        meLoaded: false,
        // Known vhost names for the host-input datalists (vhost live,
        // forensics, controls). Loaded lazily by pages that render one.
        knownVhosts: [],
        scopedSkipInfoLogged: false,
        tokenBootLogged: false,
        modeChangeLogged: false,
        authReady: false,
        authFailed: false,
        authUnknown: true,
      };
    },

    computed: {
      isScoped() { return this.isScopedMode; },
      canWrite() { return this.isAdmin || this.tokenRole !== "viewer"; },
      hasScopedVhosts() { return this.isScoped && this.allowedVhosts.length > 0; },
      isOverviewPage() { return this.pageMode === "overview"; },
      isVhostPage() { return this.pageMode === "vhost"; },
      isForensicsPage() { return this.pageMode === "forensics"; },
      isWAFPage() { return this.pageMode === "waf"; },
      isControlsPage() { return this.pageMode === "controls"; },
      pageTitle() {
        if (this.isVhostPage) return "WebDetector / vhost live";
        if (this.isForensicsPage) return "WebDetector / forensics";
        if (this.isWAFPage) return "WebDetector / WAF engine";
        if (this.isControlsPage) return "WebDetector / vhost controls";
        return "WebDetector / overview";
      },
    },

    methods: {
      shouldShow(section) {
        if (this.isScoped) {
          const hiddenForScoped = new Set(["globalips", "tokens"]);
          if (!this.scopedExcludeManagementAllowed) hiddenForScoped.add("excludes");
          if (hiddenForScoped.has(section)) return false;
        }
        return sections.has(section);
      },
      // Fills knownVhosts once (fire-and-forget) so host inputs offer
      // type-ahead instead of blind typing. Scoped tokens get their own list.
      async refreshKnownVhosts() {
        if (this.knownVhosts.length) return;
        const payload = await this.fetchJSONSafe("v1/webdet/vhosts", { rows: [] });
        const hosts = this.extractRows(payload, "rows")
          .map((r) => String(r?.host || "").trim())
          .filter(Boolean)
          .sort();
        this.knownVhosts = hosts;
      },
      logScopedAdminSkipsOnce(paths) {
        if (!this.isScoped || this.scopedSkipInfoLogged) return;
        const list = Array.isArray(paths) ? paths.filter(Boolean) : [];
        if (!list.length) return;
        console.info("[cfm-admin] scoped mode: skipped admin/global endpoints:", list.join(", "));
        this.scopedSkipInfoLogged = true;
      },

      // ── Cross-page navigation ─────────────────────────────────────────
      vhostLiveURL(host) {
        const h = String(host || "").trim();
        if (!h) return "/cfm-admin/webdetector/vhost/";
        return `/cfm-admin/webdetector/vhost/?host=${encodeURIComponent(h)}`;
      },
      forensicsURL(host) {
        const h = String(host || "").trim();
        if (!h) return "/cfm-admin/webdetector/forensics/";
        return `/cfm-admin/webdetector/forensics/?host=${encodeURIComponent(h)}`;
      },
      openVhostLive(host, newTab = true) {
        const h = String(host || "").trim();
        if (!h) return;
        const url = this.vhostLiveURL(h);
        if (newTab) window.open(url, "_blank", "noopener");
        else window.location.href = url;
      },
      openForensics(host, newTab = true) {
        const h = String(host || "").trim();
        if (!h) return;
        const url = this.forensicsURL(h);
        if (newTab) window.open(url, "_blank", "noopener");
        else window.location.href = url;
      },
      openHistoryPage(host = "", ip = "") {
        const url = new URL("/cfm-admin/webdetector/forensics/", window.location.origin);
        const h = String(host || "").trim();
        const i = String(ip || "").trim();
        if (h) url.searchParams.set("host", h);
        if (i) url.searchParams.set("ip", i);
        url.hash = "history-card";
        window.location.href = `${url.pathname}${url.search}${url.hash}`;
      },
      jumpToHistory() {
        const el = document.getElementById("history-card");
        if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
      },
      async historyForHost(host) {
        if (!host) return;
        if (!this.shouldShow("history")) {
          this.openHistoryPage(host, "");
          return;
        }
        this.historyHost = host;
        this.historyIP = "";
        await this.refreshHistory?.();
        this.jumpToHistory();
      },
      async historyForIP(ip) {
        if (!ip) return;
        if (!this.shouldShow("history")) {
          this.openHistoryPage(this.activeHost || "", ip);
          return;
        }
        this.historyIP = ip;
        if (!this.historyHost) this.historyHost = this.activeHost || "";
        await this.refreshHistory?.();
        this.jumpToHistory();
      },

      // ── Formatting ────────────────────────────────────────────────────
      extractRows(payload, key = "rows") {
        if (Array.isArray(payload)) return payload;
        if (payload && Array.isArray(payload[key])) return payload[key];
        return [];
      },
      num(v) {
        if (v === null || v === undefined || Number.isNaN(Number(v))) return "-";
        return Number(v).toFixed(2).replace(/\.00$/, "");
      },
      pct(v) {
        if (v === null || v === undefined || Number.isNaN(Number(v))) return "-";
        return `${(Number(v) * 100).toFixed(1).replace(/\.0$/, "")}%`;
      },
      fmtTs(unix) {
        const v = Number(unix || 0);
        if (!v) return "-";
        const d = new Date(v * 1000);
        if (Number.isNaN(d.getTime())) return "-";
        return d.toISOString().replace("T", " ").slice(0, 19);
      },
      formatTs(tsUnix) {
        if (!tsUnix) return "-";
        const d = new Date(Number(tsUnix) * 1000);
        if (isNaN(d.getTime())) return String(tsUnix);
        return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
      },
      formatBytes(bytes) {
        const n = Number(bytes || 0);
        if (!Number.isFinite(n) || n <= 0) return "0 B";
        const units = ["B", "KB", "MB", "GB"];
        let v = n;
        let i = 0;
        while (v >= 1024 && i < units.length - 1) {
          v /= 1024;
          i += 1;
        }
        return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
      },
      reasonText(row) {
        if (Array.isArray(row?.reasons)) return row.reasons.join(", ");
        return row?.reasons || row?.reason || "-";
      },
      csvSplit(v) {
        return String(v || "")
          .split(",")
          .map((x) => x.trim())
          .filter(Boolean);
      },
      formatApiError(err) {
        const parts = [];
        const apiErr = err?.data?.error || err?.data?.message || err?.message;
        if (apiErr) parts.push(String(apiErr));
        if (Number(err?.status) > 0) parts.push(`HTTP ${Number(err.status)}`);
        return parts.length ? parts.join(" · ") : String(err || "unknown error");
      },
      wildcardMatch(pattern, value) {
        const rx = new RegExp(`^${String(pattern).replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`, "i");
        return rx.test(String(value || ""));
      },
      isHostAllowedByScope(host) {
        if (!this.hasScopedVhosts) return true;
        const target = String(host || "").trim().toLowerCase();
        if (!target) return false;
        return this.allowedVhosts.some((allowed) => {
          const scoped = String(allowed || "").trim().toLowerCase();
          if (!scoped) return false;
          if (scoped.includes("*") || scoped.includes("?")) return this.wildcardMatch(scoped, target);
          return scoped === target;
        });
      },

      // ── API access ────────────────────────────────────────────────────
      async fetchJSON(path) {
        return getAdminApiClient()(path, {
          headers: { Accept: "application/json" },
        });
      },
      async fetchJSONSafe(path, fallback) {
        try {
          return await this.fetchJSON(path);
        } catch (err) {
          console.error("[cfm-admin] fetch failed", path, err);
          return fallback;
        }
      },
      // Self-service writes a scoped (e.g. cPanel) token may perform on its OWN
      // vhost(s). The daemon scope-checks every one of these endpoints
      // server-side (403 "host not in scope" / "exclude value outside token
      // scope"), so allowing them client-side is safe — the token's vhost
      // allowlist stays the real boundary. Admin-only writes (global firewall,
      // WAF rule edits, token/auth/history management) are NOT listed here and
      // stay blocked for viewers.
      isScopedSelfServiceWrite(path) {
        if (!this.isScoped) return false;
        const p = String(path);
        const vhostSelfService = ["v1/challenge/vhost/", "v1/http3/", "v1/webdet/rules/"];
        if (vhostSelfService.some((prefix) => p.startsWith(prefix))) return true;
        const excludeSelfService = ["v1/challenge/exclude/", "v1/waf/exclude/"];
        if (this.scopedExcludeManagementAllowed && excludeSelfService.some((prefix) => p.startsWith(prefix))) return true;
        return false;
      },
      async postJSON(path, body) {
        if (!this.canWrite) {
          const writePrefixes = ["v1/challenge/", "v1/waf/", "v1/http3/", "v1/firewall/", "v1/webdet/rules/", "v1/tokens/revoke", "v1/auth/token", "v1/webdet/history/prune", "v1/webdet/history/truncate"];
          if (writePrefixes.some((prefix) => String(path).startsWith(prefix)) && !this.isScopedSelfServiceWrite(path)) {
            throw new Error("read-only scoped viewer token");
          }
        }
        return getAdminApiClient()(path, {
          method: "POST",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
          },
          body: JSON.stringify(body),
        });
      },

      // ── Refresh loop ──────────────────────────────────────────────────
      startAutoRefresh() {
        if (this.timer) clearInterval(this.timer);
        const sec = Math.max(1, Math.min(300, Number(this.refreshIntervalSec) || 5));
        this.refreshIntervalSec = sec;
        this.autoRefresh = true;
        this.timer = setInterval(() => this.refreshAll(), sec * 1000);
      },
      applyRefreshInterval() {
        const sec = Math.max(1, Math.min(300, Number(this.refreshIntervalSec) || 5));
        this.refreshIntervalSec = sec;
        if (this.autoRefresh) this.startAutoRefresh();
      },
      stopAutoRefresh() {
        this.autoRefresh = false;
        if (this.timer) {
          clearInterval(this.timer);
          this.timer = null;
        }
      },
      async logout() {
        this.stopAutoRefresh();
        await fetch("/cfm-admin/logout", {
          method: "POST",
          credentials: "same-origin",
          redirect: "manual",
        }).catch(() => {});
        window.location.href = "/cfm-admin/login";
      },

      // refreshAll orchestrates the same sequence the monolith ran; feature
      // hooks are optional so a page only does the work its mixins define.
      async refreshAll() {
        if (this.authUnknown || this.authFailed) return;
        if (this.refreshInProgress) return;
        this.refreshInProgress = true;
        this.loading = true;
        try {
          // Type-ahead host list: only pages that render a datalist need it.
          if (document.getElementById("cfm-vhost-list")) this.refreshKnownVhosts();
          await this.refreshLists?.();
          if (this.shouldShow("excludes")) await this.refreshExcludeLists?.();
          if (this.shouldShow("history")) await this.refreshHistory?.();
          if (this.shouldShow("wafengine")) await this.refreshWAFEngine?.();
          if (this.shouldShow("controls")) {
            await this.refreshVhostControls?.();
            await this.refreshRules?.();
          }
          if (this.shouldShow("tokens")) await this.refreshTokens?.();
          if (this.shouldShow("vhost_overview") && this.vhostOverviewHost) await this.refreshVhostOverview?.();
          await this.afterListsRefreshed?.();
        } catch (err) {
          console.error("[cfm-admin] refresh failed", err);
          this.actionMsg = `Refresh failed: ${err}`;
        } finally {
          this.loading = false;
          this.refreshInProgress = false;
        }
      },

      // ── Identity / auth boot ──────────────────────────────────────────
      isScopedPathExcludeAllowedFromIdentity(me = {}) {
        const direct = me?.allow_scoped_path_excludes ?? me?.allowScopedPathExcludes ?? me?.scoped_path_excludes_allowed ?? me?.scopedPathExcludesAllowed;
        if (typeof direct === "boolean") return direct;
        const perms = me?.permissions || me?.caps || me?.capabilities;
        if (perms && typeof perms === "object") {
          const nested = perms.allow_scoped_path_excludes ?? perms.allowScopedPathExcludes ?? perms.scoped_path_excludes_allowed ?? perms.scopedPathExcludesAllowed;
          if (typeof nested === "boolean") return nested;
        }
        return false;
      },
      isScopedExcludeManagementAllowedFromIdentity(me = {}) {
        const direct = me?.allow_scoped_exclude_management ?? me?.allowScopedExcludeManagement ?? me?.scoped_exclude_management_allowed ?? me?.scopedExcludeManagementAllowed;
        if (typeof direct === "boolean") return direct;
        const perms = me?.permissions || me?.caps || me?.capabilities;
        if (perms && typeof perms === "object") {
          const nested = perms.allow_scoped_exclude_management ?? perms.allowScopedExcludeManagement ?? perms.scoped_exclude_management_allowed ?? perms.scopedExcludeManagementAllowed;
          if (typeof nested === "boolean") return nested;
        }
        return true;
      },
      // Scoped identities land with per-feature defaults (first allowed vhost
      // pre-filled). Feature fields are guarded with `in $data` so a page
      // without that mixin skips them.
      applyScopedDefaults() {
        if (!this.hasScopedVhosts) return;
        const firstHost = this.allowedVhosts[0];
        if ("vhostFocusHost" in this.$data && !this.vhostFocusHost) this.vhostFocusHost = firstHost;
        if ("vhostOverviewHost" in this.$data && !this.vhostOverviewHost) this.vhostOverviewHost = firstHost;
        if ("historyHost" in this.$data && !this.historyHost) this.historyHost = firstHost;
        if ("ruleForm" in this.$data) this.ruleForm.vhosts = this.allowedVhosts.join(", ");
        if ("simulateForm" in this.$data && !this.simulateForm.host) this.simulateForm.host = firstHost;
      },
      applyScopedChrome() {
        controller.applyScopedChrome({ scoped: this.isScoped });
      },
      setAuthState(nextState) {
        this.authReady = nextState === "ready";
        this.authFailed = nextState === "failed";
        this.authUnknown = nextState !== "ready" && nextState !== "failed";
      },
      isHttpStatusError(err, statusCode) {
        const msg = String(err?.message || err || "");
        return Number(err?.status) === statusCode || msg.includes(`HTTP ${statusCode}`) || msg.includes(`status ${statusCode}`);
      },
      isAuthStatusError(err) {
        return this.isHttpStatusError(err, 401) || this.isHttpStatusError(err, 403);
      },
      async waitForCookieScopedIdentity(maxMs = 3200) {
        const deadline = Date.now() + Math.max(0, Number(maxMs) || 0);
        while (Date.now() < deadline) {
          try {
            await controller.loadMe({ preferScopedToken: false, waitForTokenMs: 0 });
            return true;
          } catch (_) {}
          await new Promise((resolve) => setTimeout(resolve, 320));
        }
        return false;
      },
      async checkAdminStatus(opts = {}) {
        const hadTokenAtStart = Boolean(controller.getToken());
        if (!hadTokenAtStart) {
          await waitForScopedToken(1500);
          controller.refreshToken();
        }
        const tokenBeforeLoadMe = controller.getToken();
        const me = await controller.loadMe({ preferScopedToken: true });
        let latestToken = controller.refreshToken();
        const isIdentityScoped = Boolean(me && (me.isScopedMode ?? me.is_scoped_mode ?? me.scoped));
        const computedInitialMode = window.CFMAuthMode?.computeInitialScopeMode?.({
          identity: me,
          token: latestToken,
        }) || "global";
        let resolvedMe = me;
        if (opts.resolveInitialMode && computedInitialMode === "scoped" && !isIdentityScoped) {
          resolvedMe = await controller.loadMe({ preferScopedToken: true, waitForTokenMs: 0 });
          latestToken = controller.refreshToken();
        }
        const prevMode = this.isScopedMode ? "scoped" : "global";
        this.isScopedMode = Boolean(resolvedMe?.scoped);
        this.isAdmin = !this.isScopedMode;
        this.tokenRole = String(resolvedMe?.role || (this.isAdmin ? "admin" : "viewer")).toLowerCase();
        this.allowedVhosts = Array.isArray(resolvedMe?.vhosts) ? resolvedMe.vhosts.map((v) => String(v || "").trim().toLowerCase()).filter(Boolean) : [];
        this.scopedExcludeManagementAllowed = !this.isScopedMode || this.isScopedExcludeManagementAllowedFromIdentity(resolvedMe);
        this.scopedPathExcludeAllowed = !this.isScopedMode || this.isScopedPathExcludeAllowedFromIdentity(resolvedMe);
        this.applyScopedDefaults();
        this.enforceScopedExcludeControls?.();
        this.meLoaded = true;
        this.applyScopedChrome();
        const newMode = this.isScopedMode ? "scoped" : "global";
        if (!this.modeChangeLogged && prevMode !== newMode) {
          console.info("[cfm-webui] mode_changed", { from: prevMode, to: newMode });
          this.modeChangeLogged = true;
        }
        return {
          modeChanged: prevMode !== newMode,
          tokenBeforeLoadMe,
          tokenAfterLoadMe: latestToken,
        };
      },
      async onLateScopedToken() {
        const result = await this.checkAdminStatus();
        this.setAuthState("ready");
        if (result?.modeChanged || this.pageNeedsInitialRefresh?.() !== false) {
          await this.refreshAll();
        }
      },
    },

    mounted() {
      _appVm = this;
      const currentURL = new URL(window.location.href);
      const qHost = currentURL.searchParams.get("host");
      const qIP = currentURL.searchParams.get("ip");

      if (this.isVhostPage && qHost && "vhostFocusHost" in this.$data) {
        this.vhostFocusHost = qHost.trim();
        this.activeHost = this.vhostFocusHost;
      }
      if ((this.isForensicsPage || this.isWAFPage) && qHost && "historyHost" in this.$data) {
        this.historyHost = qHost.trim();
      }
      if ((this.isForensicsPage || this.isWAFPage) && qIP && "historyIP" in this.$data) {
        this.historyIP = qIP.trim();
      }

      if (!this.tokenBootLogged) {
        console.info("[cfm-webui] token_present_at_boot", { present: Boolean(controller.getToken()) });
        this.tokenBootLogged = true;
      }
      const firstCheckDelayMs = 260;
      setTimeout(() => {
        this.setAuthState("unknown");
        this.checkAdminStatus({ resolveInitialMode: true })
          .then(async () => {
            this.setAuthState("ready");
            controller.noteInitialModeResolved({ isScopedMode: this.isScopedMode });
            await this.refreshAll();
          })
          .catch(async (err) => {
            console.warn("[cfm-webui] checkAdminStatus failed", err);
            if (this.isAuthStatusError(err)) {
              try {
                await waitForScopedToken(10000);
                if (controller.refreshToken()) {
                  await this.checkAdminStatus({ resolveInitialMode: true });
                  this.setAuthState("ready");
                  controller.noteInitialModeResolved({ isScopedMode: this.isScopedMode });
                  await this.refreshAll();
                  return;
                }
                const cookieIdentityReady = await this.waitForCookieScopedIdentity(3200);
                if (cookieIdentityReady) {
                  await this.checkAdminStatus({ resolveInitialMode: true });
                  this.setAuthState("ready");
                  controller.noteInitialModeResolved({ isScopedMode: this.isScopedMode });
                  await this.refreshAll();
                  return;
                }
              } catch (retryErr) {
                console.warn("[cfm-webui] deferred checkAdminStatus retry failed", retryErr);
              }
              this.setAuthState("failed");
              controller.noteInitialModeResolved({ isScopedMode: this.isScopedMode });
              return;
            }
            const fallbackScoped = Boolean(controller.getToken());
            this.isScopedMode = fallbackScoped;
            this.isAdmin = !fallbackScoped;
            // Identity never resolved here, so we couldn't confirm scoped
            // capabilities. Fail closed: keep scope-gated self-service
            // excludes disabled until a real identity loads. Admin fallback
            // (no token) is unaffected — canWrite is already true via isAdmin.
            this.scopedExcludeManagementAllowed = !fallbackScoped;
            this.scopedPathExcludeAllowed = false;
            this.applyScopedChrome();
            this.setAuthState("ready");
            controller.noteInitialModeResolved({ isScopedMode: this.isScopedMode });
            await this.refreshAll();
          });
      }, firstCheckDelayMs);

      if (this.autoRefresh) this.startAutoRefresh();

      if (this.isForensicsPage && currentURL.hash === "#history-card") {
        setTimeout(() => this.jumpToHistory(), 120);
      }
    },

    beforeUnmount() {
      if (_appVm === this) _appVm = null;
      if (this.timer) clearInterval(this.timer);
    },
  };

  expandPartials();
  const app = createApp({ mixins: [coreMixin, ...mixins] });
  const vm = app.mount("#app");
  // Debug/test handle (also used by the template-reference checker).
  window.__cfmVm = vm;
  return app;
}
