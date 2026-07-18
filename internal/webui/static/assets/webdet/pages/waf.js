// WebDetector / WAF engine: structured WAF analytics + excludes management.
import "../../shared/constants.js";
import "../../shared/auth-context.js";
import "../../shared/auth-mode.js";
import "../../shared/api-client.js";
import "../../shared/controller-bootstrap.js";
import "../../shared/ui-scope.js";
import { createWebdetApp } from "../core.js";
import { wafEngineMixin } from "../feature-wafengine.js";
import { excludesMixin } from "../feature-excludes.js";

createWebdetApp({
  pageMode: "waf",
  sections: ["wafengine", "excludes"],
  mixins: [wafEngineMixin, excludesMixin],
});
