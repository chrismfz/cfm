<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= htmlspecialchars($pageTitle, ENT_QUOTES, 'UTF-8') ?></title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: system-ui, -apple-system, sans-serif;
  background: #0b1020;
  color: #e6edf3;
  height: 100vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.bar {
  padding: .55rem 1rem;
  background: #121a2b;
  border-bottom: 1px solid #263449;
  font-size: .85rem;
  display: flex;
  gap: .75rem;
  align-items: center;
  flex-shrink: 0;
}
.bar strong { color: #4da3ff; font-size: .95rem; }
.bar .domains { color: #9fb0c3; }
.err {
  margin: 1.5rem;
  padding: .9rem 1.1rem;
  background: #2a0f17;
  border: 1px solid #7a2a3a;
  border-radius: 10px;
  color: #ffc9d3;
  line-height: 1.6;
}
.err strong { display: block; margin-bottom: .35rem; }
.err small { color: #9fb0c3; font-size: .82rem; }
iframe {
  flex: 1;
  border: none;
  width: 100%;
  display: block;
  min-height: 0;
}
</style>
</head>
<body>

<?php if ($error !== ''): ?>

<div class="bar">
  <strong>CFM Security</strong>
  <?php if (!empty($currentUser)): ?>
    <span class="domains">User: <?= htmlspecialchars($currentUser, ENT_QUOTES, 'UTF-8') ?></span>
  <?php endif; ?>
</div>
<div class="err">
  <strong>CFM is not available</strong>
  <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?><br>
  <small>
    Ensure the CFM service is running and <code>AUTH_TOKEN</code> is set in
    <code>/etc/cfm/cfm.conf</code>. If the UI is on a non-standard port, set
    <code>CPANEL_PLUGIN_BASE_URL = https://hostname:port</code> in cfm.conf.
  </small>
</div>

<?php else: ?>

<div class="bar">
  <strong>CFM Security</strong>
  <span class="domains"><?= htmlspecialchars(implode('  ·  ', $domains), ENT_QUOTES, 'UTF-8') ?></span>
</div>
<iframe
  id="cfm-frame"
  src="<?= htmlspecialchars($iframeUrl, ENT_QUOTES, 'UTF-8') ?>"
  title="CFM Security Controls"
></iframe>
<script>
(function () {
  var token  = <?= json_encode($token, JSON_UNESCAPED_SLASHES) ?>;
  var origin = <?= json_encode($iframeOrigin, JSON_UNESCAPED_SLASHES) ?>;
  var frame  = document.getElementById('cfm-frame');
  if (!token || !frame) return;
  frame.addEventListener('load', function () {
    try {
      frame.contentWindow.postMessage({ cfmToken: token }, origin);
    } catch (e) {
      console.error('[cfm-plugin] postMessage failed:', e);
    }
  });
})();
</script>

<?php endif; ?>
</body>
</html>
