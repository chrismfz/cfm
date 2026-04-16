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
.warn-banner {
  display: none;
  margin: .75rem 1rem;
  padding: .7rem .95rem;
  background: #3a2b10;
  border: 1px solid #946c1e;
  border-radius: 8px;
  color: #ffe3a6;
  font-size: .85rem;
  line-height: 1.45;
  flex-shrink: 0;
}
.warn-banner strong { color: #ffd27a; }
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
<div id="cfm-ack-warning" class="warn-banner" role="alert" aria-live="polite">
  <strong>Secure session handshake delayed.</strong>
  We could not confirm token delivery to the embedded app. Refresh this page if loading stalls, and contact your administrator if the issue continues.
</div>
<iframe
  id="cfm-frame"
  src="<?= htmlspecialchars($iframeUrl, ENT_QUOTES, 'UTF-8') ?>"
  title="CFM Security Controls"
></iframe>
<script>
(function () {
  var token   = <?= json_encode($token, JSON_UNESCAPED_SLASHES) ?>;
  var origin  = <?= json_encode($iframeOrigin, JSON_UNESCAPED_SLASHES) ?>;
  var frame   = document.getElementById('cfm-frame');
  var ackWarningBanner = document.getElementById('cfm-ack-warning');
  var expectedParentOriginParam = 'cfmExpectedOrigin'; // canonical transport for expected parent origin
  var state = 'loaded';
  var ackTimeoutMs = 1200;
  var loadSeq = 0;
  var latestAckSeq = 0;
  var currentLoadSeq = 0;
  var explicitNavigationSeq = 0;
  var ackSucceededInLifecycle = false;
  var ackTimersBySeq = Object.create(null);
  var pluginContext = (function detectPluginContext() {
    var reasons = [];
    var path = window.location.pathname || '';
    var cpanelCgiPathRe = /^\/cpsess[^/]+\/3rdparty\/cfm_cpanel\.cgi(?:\/|$)/;
    if (cpanelCgiPathRe.test(path)) reasons.push('cgi_path');
    if (typeof window.CPANEL !== 'undefined') reasons.push('global_cpanel');
    if (typeof window.CPANEL_THEME !== 'undefined') reasons.push('global_cpanel_theme');
    if (typeof window.LOCALE !== 'undefined') reasons.push('global_locale');
    return {
      isPluginContext: reasons.length > 0,
      reasonCode: reasons.length ? reasons.join('+') : 'no_stable_indicators'
    };
  })();
  var isPluginContext = pluginContext.isPluginContext;
  var pluginContextReason = pluginContext.reasonCode;
  if (!token || !frame) return;

  console.info(
    '[cfm-plugin] startup context: isPluginContext=%s url=%s reason=%s',
    isPluginContext,
    window.location.href,
    pluginContextReason
  );

  function markExplicitNavigation(reason) {
    explicitNavigationSeq = loadSeq + 1;
    console.debug('[cfm-plugin] explicit navigation armed (reason=%s, nextLoadSeq=%d)', reason, explicitNavigationSeq);
  }

  function injectExpectedParentOrigin(rawUrl) {
    try {
      var url = new URL(rawUrl, window.location.href);
      url.searchParams.set(expectedParentOriginParam, window.location.origin);
      return url.toString();
    } catch (e) {
      console.error('[cfm-plugin] could not inject expected parent origin into iframe URL:', e);
      return rawUrl;
    }
  }

  function clearAckTimer(seq, clearReason) {
    if (!ackTimersBySeq[seq]) return;
    window.clearTimeout(ackTimersBySeq[seq]);
    delete ackTimersBySeq[seq];
    console.debug('[cfm-plugin] cleared ACK timer (%s, loadSeq=%d, ackSeq=%d, timeoutSeq=%d)', clearReason, currentLoadSeq, latestAckSeq, seq);
  }

  function sendTokenViaPostMessage(reason, seq) {
    try {
      state = 'token_posted';
      if (ackWarningBanner) ackWarningBanner.style.display = 'none';
      console.debug('[cfm-plugin] posting scoped token to iframe (%s, loadSeq=%d)', reason, seq);
      frame.contentWindow.postMessage({ cfmToken: token, loadSeq: seq }, origin);
    } catch (e) {
      console.error('[cfm-plugin] postMessage failed (loadSeq=%d):', seq, e);
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
    if (evt.origin !== origin) {
      console.warn('[cfm-plugin] rejected iframe message origin=%s allowlist=%o', evt.origin, [origin]);
      return;
    }
    var data = evt && evt.data ? evt.data : {};
    var payloadShape = Object.prototype.toString.call(data);
    if (data && typeof data === 'object') {
      var keys = Object.keys(data).slice(0, 6);
      payloadShape = 'object keys=' + (keys.length ? keys.join(',') : 'none');
    }
    if (data.cfmTokenAck === true) {
      console.debug('[cfm-plugin] accepted iframe ACK origin=%s', evt.origin);
      var ackSeq = Number(data.ackSeq || data.loadSeq || currentLoadSeq || 0);
      if (!ackSeq || ackSeq < 0) ackSeq = currentLoadSeq;
      latestAckSeq = Math.max(latestAckSeq, ackSeq);
      ackSucceededInLifecycle = true;
      if (ackWarningBanner) ackWarningBanner.style.display = 'none';
      clearAckTimer(ackSeq, 'ack_received');
      if (ackSeq === currentLoadSeq) state = 'acked';
      console.debug('[cfm-plugin] iframe ACK received via postMessage (%s, loadSeq=%d, ackSeq=%d, timeoutSeq=%s)', data.path || 'unknown path', currentLoadSeq, ackSeq, 'none');
      return;
    }
    console.debug('[cfm-plugin] accepted non-ACK iframe message origin=%s (shape=%s, loadSeq=%d, ackSeq=%d, timeoutSeq=%s)', evt.origin, payloadShape, currentLoadSeq, latestAckSeq, 'active');
  });

  frame.src = injectExpectedParentOrigin(frame.getAttribute('src') || frame.src || '');
  markExplicitNavigation('initial iframe src');

  frame.addEventListener('load', function () {
    loadSeq += 1;
    currentLoadSeq = loadSeq;
    var timeoutSeq = currentLoadSeq;
    var explicitNavForThisLoad = timeoutSeq <= explicitNavigationSeq;

    state = 'loaded';
    clearAckTimer(timeoutSeq, 'load_restart');
    sendTokenViaPostMessage('iframe load', timeoutSeq);

    ackTimersBySeq[timeoutSeq] = window.setTimeout(function () {
      delete ackTimersBySeq[timeoutSeq];
      if (timeoutSeq !== currentLoadSeq) {
        console.debug('[cfm-plugin] ignoring stale ACK timeout (loadSeq=%d, ackSeq=%d, timeoutSeq=%d)', currentLoadSeq, latestAckSeq, timeoutSeq);
        return;
      }
      if (state === 'acked') {
        console.debug('[cfm-plugin] ACK timeout ignored due to state=%s (loadSeq=%d, ackSeq=%d, timeoutSeq=%d)', state, currentLoadSeq, latestAckSeq, timeoutSeq);
        return;
      }
      state = 'timeout';
      console.warn(
        '[cfm-plugin] no iframe ACK after %dms (state=%s, frameUrl=%s, frameOrigin=%s, expectedOrigin=%s, loadSeq=%d, ackSeq=%d, timeoutSeq=%d)',
        ackTimeoutMs,
        state,
        frame.src || 'unknown',
        getFrameOriginForLog(),
        origin,
        currentLoadSeq,
        latestAckSeq,
        timeoutSeq
      );

      if (ackSucceededInLifecycle && !explicitNavForThisLoad) {
        console.info('[cfm-plugin] ignoring delayed ACK timeout because ACK already succeeded in this lifecycle (loadSeq=%d, ackSeq=%d, timeoutSeq=%d)', currentLoadSeq, latestAckSeq, timeoutSeq);
        return;
      }
      if (ackWarningBanner) ackWarningBanner.style.display = 'block';
      console.warn('[cfm-plugin] URL token fallback is disabled; showing user-visible warning banner (loadSeq=%d, ackSeq=%d, timeoutSeq=%d)', currentLoadSeq, latestAckSeq, timeoutSeq);
    }, ackTimeoutMs);

    console.debug('[cfm-plugin] armed ACK timeout (loadSeq=%d, ackSeq=%d, timeoutSeq=%d, explicitNav=%s)', currentLoadSeq, latestAckSeq, timeoutSeq, explicitNavForThisLoad);
  });

  console.debug('[cfm-plugin] URL token fallback transport is disabled; postMessage ACK is required');
})();
</script>

<script>
// URL token transport is disabled and unsupported in production.
</script>

<?php endif; ?>
</body>
</html>
