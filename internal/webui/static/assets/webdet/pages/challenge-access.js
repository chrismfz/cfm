// Challenge Access-Control: a per-vhost/global allow-list that exempts matching
// requests from the interactive challenge (challenge→allow only; never softens
// the WAF or an IP block). Scope-filtered /api/v1/challenge/access/* API.
import "../../shared/constants.js";
import "../../shared/auth-context.js";
import "../../shared/auth-mode.js";
import "../../shared/api-client.js";
import "../../shared/controller-bootstrap.js";
import "../../shared/ui-scope.js";
import { createWebdetApp } from "../core.js";
import { challengeAccessMixin } from "../feature-challenge-access.js";

createWebdetApp({
  pageMode: "challenge-access",
  sections: ["challenge_access"],
  mixins: [challengeAccessMixin],
});
