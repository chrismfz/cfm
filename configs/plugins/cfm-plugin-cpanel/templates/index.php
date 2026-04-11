<!-- Authoritative metadata source: /api/v1/cpanel/user-info -->
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
    See <code>/usr/local/cpanel/logs/error_log</code> and CFM daemon logs for details.
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
  var state = 'loaded';
  var fallbackAttempted = false;
  var ackTimeoutMs = 1200;
  var isPluginContext = window.location.pathname.indexOf('/frontend/') !== -1 ||
    window.location.pathname.indexOf('/cpanelplugin/') !== -1;
  if (!token || !frame) return;

  console.debug('[cfm-plugin] startup context: isPluginContext=%s', isPluginContext);

  function buildFallbackUrl(rawUrl, scopedToken) {
    try {
      var url = new URL(rawUrl, window.location.href);
      url.searchParams.set('token', scopedToken);
      return url.toString();
    } catch (e) {
      console.error('[cfm-plugin] could not build fallback iframe URL:', e);
      return rawUrl;
    }
  }

  function sendTokenViaPostMessage(reason) {
    try {
      state = 'token_posted';
      console.debug('[cfm-plugin] posting scoped token to iframe (%s)', reason);
      frame.contentWindow.postMessage({ cfmToken: token }, origin);
    } catch (e) {
      console.error('[cfm-plugin] postMessage failed:', e);
    }
  }

  function getFrameOriginForLog() {
    try {
      return frame.contentWindow && frame.contentWindow.location ? frame.contentWindow.location.origin : 'unavailable';
    } catch (e) {
      return 'cross-origin-unavailable';
    }
  }

  window.addEventListener('message', function (evt) {
    if (evt.origin !== origin) return;
    var data = evt && evt.data ? evt.data : {};
    if (data.cfmTokenAck === true) {
      state = 'acked';
      console.debug('[cfm-plugin] iframe ACK received via postMessage (%s)', data.path || 'unknown path');
    }
  });

  frame.addEventListener('load', function () {
    if (fallbackAttempted && state === 'fallback_attempted') return;
    state = 'loaded';
    sendTokenViaPostMessage('iframe load');
    window.setTimeout(function () {
      if (state === 'acked' || state === 'fallback_attempted') return;
      state = 'timeout';
      console.warn(
        '[cfm-plugin] no iframe ACK after %dms (state=%s, frameUrl=%s, frameOrigin=%s, expectedOrigin=%s)',
        ackTimeoutMs,
        state,
        frame.src || 'unknown',
        getFrameOriginForLog(),
        origin
      );
      if (!isPluginContext) {
        console.error('[cfm-plugin] fallback reload is disabled outside plugin context; no reload attempted');
        return;
      }
      if (fallbackAttempted) return;
      fallbackAttempted = true;
      state = 'fallback_attempted';
      var fallbackUrl = buildFallbackUrl(frame.src, token);
      console.warn('[cfm-plugin] no iframe ACK after %dms, forcing one fallback reload with token query parameter', ackTimeoutMs);
      frame.src = fallbackUrl;
    }, ackTimeoutMs);
  });

  // cPanel plugin compatibility path only: append ?token=... when fallback reload is needed.
  if (isPluginContext) {
    console.debug('[cfm-plugin] cPanel plugin context detected; URL token fallback is enabled for compatibility only');
  } else {
    // Safety: if template is ever reused outside plugin context, avoid accidental fallback URL transport.
    buildFallbackUrl = function (rawUrl) {
      console.debug('[cfm-plugin] URL token fallback disabled outside plugin context');
      return rawUrl;
    };
  }
})();
</script>

<script>
// Compatibility warning: URL token transport is fallback-only and should remain disabled
// unless iframe postMessage delivery is unreliable in the hosting environment.
</script>

<?php endif; ?>
</body>
</html>
