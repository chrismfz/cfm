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
      <span class="pill">CFM dashboard</span>
    </div>
  </div>
  <div class="meta">
    <button id="refreshDashboard" class="btn-quiet">Refresh dashboard</button>
  </div>
</header>

<main class="layout">
  <div id="msg" class="msg hidden"></div>
  <?php if ($modeName === 'whm'): ?>
  <section class="card">
    <h2>WebDetector top vhosts</h2>
    <p class="section-sub">Top server vhosts by short-window activity.</p>
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
    <h2>WAF engine</h2>
    <pre id="wafOut">Loading…</pre>
  </section>
  <?php endif; ?>

  <?php if ($modeName !== 'whm'): ?>
  <section class="card wide">
    <h2>Vhost live</h2>
    <div class="toolbar">
      <select id="vhostHost" class="input input-wide">
        <option value="">Select one of your domains…</option>
        <?php foreach ($rows as $row): $domain = normalize_host((string)$row['domain']); if ($domain === '') continue; ?>
          <option value="<?= h($domain) ?>"><?= h($domain) ?></option>
        <?php endforeach; ?>
      </select>
      <button id="loadVhostBtn" class="btn-quiet">Load live</button>
      <span id="vhostMeta" class="muted">Only your own domains can be loaded here.</span>
    </div>
    <div id="vhostMetrics" class="kpi-grid" style="margin-bottom:1rem"></div>
    <div class="split">
      <div class="card" style="padding:.8rem"><h3>Top IPs</h3><div id="vhostIPs" class="list"><div class="muted">No data yet.</div></div></div>
      <div class="card" style="padding:.8rem"><h3>Top paths</h3><div id="vhostPaths" class="list"><div class="muted">No data yet.</div></div></div>
    </div>
  </section>
  <?php endif; ?>

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
          <?php if (empty($rows)): ?>
            <tr><td colspan="4" class="muted">No domains detected for this account yet.</td></tr>
          <?php endif; ?>
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
window.CFM_OWNED_DOMAINS = <?= json_encode(array_values(array_unique(array_map(static function ($row) { return normalize_host((string)$row['domain']); }, $rows))), JSON_UNESCAPED_SLASHES) ?>;
</script>
<script src="?asset=app.js" defer></script>
</body>
</html>
