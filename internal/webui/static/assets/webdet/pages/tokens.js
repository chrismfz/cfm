// API tokens (admin-only): scoped-token issuance/revocation for panel
// plugins. Split out of the vhost-controls page.
import "../../shared/constants.js";
import "../../shared/auth-context.js";
import "../../shared/auth-mode.js";
import "../../shared/api-client.js";
import "../../shared/controller-bootstrap.js";
import "../../shared/ui-scope.js";
import { createWebdetApp } from "../core.js";
import { tokensMixin } from "../feature-tokens.js";

createWebdetApp({
  pageMode: "tokens",
  sections: ["tokens"],
  mixins: [tokensMixin],
});
