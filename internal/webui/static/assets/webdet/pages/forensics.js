// WebDetector / forensics: history investigation, IP drilldown and the
// offline analyze tools. No auto-refresh — investigation stays still.
import "../../shared/constants.js";
import "../../shared/auth-context.js";
import "../../shared/auth-mode.js";
import "../../shared/api-client.js";
import "../../shared/controller-bootstrap.js";
import "../../shared/ui-scope.js";
import { createWebdetApp } from "../core.js";
import { forensicsMixin, analyzeMixin, ipDrilldownMixin } from "../feature-forensics.js";
import { excludesMixin } from "../feature-excludes.js";

createWebdetApp({
  pageMode: "forensics",
  sections: ["history", "ipdrilldown", "analyze", "excludes"],
  autoRefresh: false,
  mixins: [forensicsMixin, analyzeMixin, ipDrilldownMixin, excludesMixin],
});
