// WebDetector / vhost controls: per-vhost protection toggles, traffic rules
// with presets + simulation, scoped tokens and the security overview.
import "../../shared/constants.js";
import "../../shared/auth-context.js";
import "../../shared/auth-mode.js";
import "../../shared/api-client.js";
import "../../shared/controller-bootstrap.js";
import "../../shared/ui-scope.js";
import { createWebdetApp } from "../core.js";
import { controlsMixin } from "../feature-controls.js";

createWebdetApp({
  pageMode: "controls",
  sections: ["controls", "tokens", "vhost_overview"],
  mixins: [controlsMixin],
});
