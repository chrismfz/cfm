// WebDetector / Exceptions: WAF excludes, challenge excludes and trusted
// clients (Challenge access) in one page.
import "../../shared/constants.js";
import "../../shared/auth-context.js";
import "../../shared/auth-mode.js";
import "../../shared/api-client.js";
import "../../shared/controller-bootstrap.js";
import "../../shared/ui-scope.js";
import { createWebdetApp } from "../core.js";
import { excludesMixin } from "../feature-excludes.js";
import { challengeAccessMixin } from "../feature-challenge-access.js";
import { exceptionsMixin } from "../feature-exceptions.js";

createWebdetApp({
  pageMode: "exceptions",
  sections: ["exceptions", "excludes", "challenge_access"],
  mixins: [excludesMixin, challengeAccessMixin, exceptionsMixin],
  autoRefresh: false,
  minRefreshSec: 30,
});
