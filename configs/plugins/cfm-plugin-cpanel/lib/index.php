<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= h($pageTitle) ?></title>
<link rel="stylesheet" href="?asset=style.css">
</head>
<body>
<header class="topbar">
  <div>
    <h1><?= h($pageTitle) ?></h1>
    <div class="top-nav">
      <span class="pill <?= $modeName === 'cpanel' ? 'ok' : '' ?>"><?= $modeName === 'cpanel' ? 'cPanel' : 'WHM' ?></span>
      <?php if ($modeName === 'cpanel'): ?><span class="pill">User: <?= h($currentUser) ?></span><?php endif; ?>
      <span class="pill">Vue-style merged dashboard</span>
    </div>
  </div>
  <div class="meta">
    <button id="refreshDashboard" class="btn-quiet">Refresh dashboard</button>
  </div>
</header>

<main class="layout">
  <section class="card wide">
    <h2>Quick overview</h2>
    <p class="section-sub">Borrowed layout/style direction from the old CFM admin, while keeping the working plugin list/toggles below intact.</p>
    <div id="msg" class="msg hidden"></div>
    <div id="healthGrid" class="kpi-grid"><div class="muted">Loading…</div></div>
  </section>

  <section class="card">
    <h2>System status</h2>
    <pre id="statusOut">Loading…</pre>
  </section>

  <section class="card">
    <h2>DNAT / SSL</h2>
    <h3>DNAT</h3>
    <pre id="dnatOut">Loading…</pre>
    <h3 style="margin-top:1rem">SSL</h3>
    <pre id="sslOut">Loading…</pre>
  </section>

  <section class="card">
    <h2>WebDetector top vhosts</h2>
    <p class="section-sub">Click a host to load live drilldown.</p>
    <div class="table-wrap tall"><table><thead><tr><th>Host</th><th>RPS</th><th>2xx</th><th>4xx</th><th>5xx</th><th>Unique IPs</th><th>Score</th></tr></thead><tbody id="webdetBody"><tr><td colspan="7" class="muted">Loading…</td></tr></tbody></table></div>
  </section>

  <section class="card">
    <h2>Suspicious / challenged</h2>
    <h3>Suspicious</h3>
    <div class="table-wrap"><table><thead><tr><th>Host</th><th>Score</th><th>RPS</th><th>Reasons</th></tr></thead><tbody id="suspiciousBody"><tr><td colspan="4" class="muted">Loading…</td></tr></tbody></table></div>
    <h3 style="margin-top:1rem">Active challenge</h3>
    <div class="table-wrap"><table><thead><tr><th>Host</th><th>Mode</th><th>IPs</th><th>Reasons</th></tr></thead><tbody id="challengeBody"><tr><td colspan="4" class="muted">Loading…</td></tr></tbody></table></div>
  </section>

  <section class="card wide">
    <h2>Vhost live</h2>
    <div class="toolbar">
      <input id="vhostHost" class="input input-wide" type="text" placeholder="example.com">
      <button id="loadVhostBtn" class="btn-quiet">Load live</button>
      <button id="challengeHostBtn">Challenge host</button>
      <button id="unchallengeHostBtn" class="btn-quiet">Remove challenge</button>
      <span id="vhostMeta" class="muted">Choose a host from above or type one manually.</span>
    </div>
    <div id="vhostMetrics" class="kpi-grid" style="margin-bottom:1rem"></div>
    <div class="split">
      <div class="card" style="padding:.8rem"><h3>Top IPs</h3><div id="vhostIPs" class="list"><div class="muted">No data yet.</div></div></div>
      <div class="card" style="padding:.8rem"><h3>Top paths</h3><div id="vhostPaths" class="list"><div class="muted">No data yet.</div></div></div>
    </div>
  </section>

  <section class="card">
    <h2>Governor / per-user</h2>
    <div class="table-wrap tall"><table><thead><tr><th>User</th><th>Total</th><th>Active</th><th>Sleep</th><th>Locked</th></tr></thead><tbody id="governorBody"><tr><td colspan="5" class="muted">Loading…</td></tr></tbody></table></div>
  </section>

  <section class="card">
    <h2>Governor / running queries</h2>
    <div class="table-wrap tall"><table><thead><tr><th>User</th><th>DB</th><th>Time</th><th>State</th><th>Query</th></tr></thead><tbody id="governorRunningBody"><tr><td colspan="5" class="muted">Loading…</td></tr></tbody></table></div>
  </section>

  <section class="card wide">
    <h2>WAF engine</h2>
    <pre id="wafOut">Loading…</pre>
  </section>

  <section class="card wide">
    <h2>Per-domain controls</h2>
    <p class="section-sub">The original working list remains here. Search/filter still works; button state wording is now clearer.</p>
    <div class="toolbar">
      <input type="text" id="search" class="input input-wide" placeholder="Filter by user or domain">
      <label><input type="checkbox" id="enabledOnly"> Show only enabled</label>
    </div>
    <div class="table-wrap" id="domainsWrap">
      <table id="domainsTable">
        <thead><tr><th>User</th><th>Domain</th><th>Challenge</th><th>WAF</th></tr></thead>
        <tbody id="domainsBody">
          <?php foreach ($rows as $row): ?>
            <?php $user=(string)$row['user']; $domain=normalize_host((string)$row['domain']); $chExcluded=!empty($challengeSet[$domain]); $wafExcluded=!empty($wafSet[$domain]); ?>
            <tr data-user="<?= h(strtolower($user)) ?>" data-domain="<?= h(strtolower($domain)) ?>">
              <td><?= h($user) ?></td>
              <td><?= h($domain) ?></td>
              <td><button class="toggle <?= $chExcluded ? 'is-disabled' : 'is-enabled' ?>" data-kind="challenge" data-domain="<?= h($domain) ?>" data-state="<?= $chExcluded ? '1' : '0' ?>"><?= $chExcluded ? 'CHALLENGE OFF / DISABLED' : 'CHALLENGE ON / ENABLED' ?></button></td>
              <td><button class="toggle <?= $wafExcluded ? 'is-disabled' : 'is-enabled' ?>" data-kind="waf" data-domain="<?= h($domain) ?>" data-state="<?= $wafExcluded ? '1' : '0' ?>"><?= $wafExcluded ? 'WAF OFF / DISABLED' : 'WAF ON / ENABLED' ?></button></td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </section>
</main>
<script>
window.CFM_TOKEN = <?= json_encode($csrfToken) ?>;
window.CFM_MODE = <?= json_encode($modeName) ?>;
window.CFM_CURRENT_USER = <?= json_encode($currentUser ?? '') ?>;
window.CFM_CHALLENGE_SET = <?= json_encode($challengeSet, JSON_UNESCAPED_SLASHES) ?>;
window.CFM_WAF_SET = <?= json_encode($wafSet, JSON_UNESCAPED_SLASHES) ?>;
</script>
<script src="?asset=app.js" defer></script>
</body>
</html>
