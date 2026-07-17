// WebDetector / overview: live lists (WebTop, suspicious, long-window,
// global IPs), excludes management and the click-through vhost drilldown.
import "../../shared/constants.js";
import "../../shared/auth-context.js";
import "../../shared/auth-mode.js";
import "../../shared/api-client.js";
import "../../shared/controller-bootstrap.js";
import "../../shared/ui-scope.js";
import { createWebdetApp } from "../core.js";
import { liveMixin } from "../feature-live.js";
import { challengeMixin } from "../feature-challenge.js";
import { firewallMixin } from "../feature-firewall.js";
import { excludesMixin } from "../feature-excludes.js";
import { analyzeMixin } from "../feature-forensics.js";

createWebdetApp({
  pageMode: "overview",
  sections: ["webtop", "suspicious", "longtop", "globalips", "excludes", "vhost"],
  mixins: [liveMixin, challengeMixin, firewallMixin, excludesMixin, analyzeMixin],
});
