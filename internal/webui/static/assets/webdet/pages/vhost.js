// WebDetector / vhost: one vhost in focus. Admins get the profile tabs
// (what applies, bots and traffic, WAF and challenges); everyone gets the
// Live tab: live KPIs, ECharts series and the drilldown with bulk IP actions.
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
import { vhostProfileMixin } from "../feature-vhost-profile.js";

createWebdetApp({
  pageMode: "vhost",
  sections: ["vhost"],
  mixins: [liveMixin, challengeMixin, firewallMixin, vhostProfileMixin],
});
