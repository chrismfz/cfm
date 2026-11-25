// WebDetector / Protection: what the edge stopped and why. The WAF log
// (grouped), the event history (paged) and the edge outcomes in one page;
// it replaces the WAF engine and Forensics pages' reading views.
import "../../shared/constants.js";
import "../../shared/auth-context.js";
import "../../shared/auth-mode.js";
import "../../shared/api-client.js";
import "../../shared/controller-bootstrap.js";
import "../../shared/ui-scope.js";
import { createWebdetApp } from "../core.js";
import { protectionMixin } from "../feature-protection.js";

createWebdetApp({
  pageMode: "protection",
  sections: ["protection"],
  mixins: [protectionMixin],
  // Each view is a history query: refreshed on demand and on a change, not
  // every few seconds.
  autoRefresh: false,
  minRefreshSec: 60,
});
