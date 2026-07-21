// ClamAV insights: scanner status/health (admin) + per-vhost scan coverage
// (scoped). Reuses the vhost-controls scoped data + the admin clam/health API.
import "../../shared/constants.js";
import "../../shared/auth-context.js";
import "../../shared/auth-mode.js";
import "../../shared/api-client.js";
import "../../shared/controller-bootstrap.js";
import "../../shared/ui-scope.js";
import { createWebdetApp } from "../core.js";
import { clamMixin } from "../feature-clam.js";

createWebdetApp({
  pageMode: "clam",
  sections: ["clam"],
  mixins: [clamMixin],
});
