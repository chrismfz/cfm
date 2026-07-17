// WebDetector / vhost live: one vhost in focus — live KPIs, ECharts series
// and the rich drilldown with bulk IP actions.
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

createWebdetApp({
  pageMode: "vhost",
  sections: ["vhost"],
  mixins: [liveMixin, challengeMixin, firewallMixin],
});
