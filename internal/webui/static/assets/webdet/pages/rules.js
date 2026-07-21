// Traffic Rules: Cloudflare-style per-vhost allow/block/challenge/throttle
// rules with presets, editor and pre-enforcement simulation. Split out of the
// vhost-controls page — same scope-filtered /api/v1/webdet/rules/* API.
import "../../shared/constants.js";
import "../../shared/auth-context.js";
import "../../shared/auth-mode.js";
import "../../shared/api-client.js";
import "../../shared/controller-bootstrap.js";
import "../../shared/ui-scope.js";
import { createWebdetApp } from "../core.js";
import { rulesMixin } from "../feature-rules.js";

createWebdetApp({
  pageMode: "rules",
  sections: ["rules"],
  mixins: [rulesMixin],
});
