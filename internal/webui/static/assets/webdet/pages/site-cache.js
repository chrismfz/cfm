// Site Cache: per-vhost edge caching — arm a vhost's static / micro tier, opt a
// host out, purge, and read the live hit counts. Scope-filtered
// /api/v1/site-cache/* API (docs/site-cache-runbook.md).
import "../../shared/constants.js";
import "../../shared/auth-context.js";
import "../../shared/auth-mode.js";
import "../../shared/api-client.js";
import "../../shared/controller-bootstrap.js";
import "../../shared/ui-scope.js";
import { createWebdetApp } from "../core.js";
import { siteCacheMixin } from "../feature-site-cache.js";

createWebdetApp({
  pageMode: "site-cache",
  sections: ["site_cache"],
  mixins: [siteCacheMixin],
});
