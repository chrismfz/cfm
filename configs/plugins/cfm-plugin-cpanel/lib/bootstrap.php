<?php
require_once __DIR__ . '/cfm_api.php';
require_once __DIR__ . '/domain_provider.php';

function cgi_send_headers(string $contentType = 'text/html; charset=utf-8', array $extra = []): void
{
    echo "Content-Type: {$contentType}\r\n";
    foreach ($extra as $h) echo $h . "\r\n";
    echo "\r\n";
}

function cfm_bootstrap(string $mode): void
{
    if (!in_array($mode, ['whm', 'cpanel'], true)) {
        cgi_send_headers();
        echo '<p>Invalid mode</p>';
        exit;
    }

    // WHM / root — redirect straight to the full admin UI.
    // Root has goauth session auth; no scoped token needed.
    if ($mode === 'whm') {
        $adminUrl = cfm_iframe_base_url() . '/cfm-admin/';
        cgi_send_headers();
        echo '<!doctype html><html><head><meta charset=utf-8>'
            . '<meta http-equiv="refresh" content="0;url=' . htmlspecialchars($adminUrl, ENT_QUOTES, 'UTF-8') . '">'
            . '<title>CFM Admin</title></head><body>'
            . '<p>Redirecting to <a href="' . htmlspecialchars($adminUrl, ENT_QUOTES, 'UTF-8') . '">CFM Admin</a>…</p>'
            . '</body></html>';
        exit;
    }

    // cPanel mode — issue a scoped token for the user's domains.
    $currentUser = get_current_cpanel_user();
    $domains     = [];
    $error       = '';
    $token       = '';
    $pageTitle   = 'CFM Security';

    if ($currentUser === '') {
        $error = 'Could not determine cPanel username.';
    } else {
        $domains = get_domains_for_user($currentUser);
        if (empty($domains)) {
            $error = 'No domains found for user "' . $currentUser . '".';
        } else {
            try {
                $label = 'cpanel:' . $currentUser;
                $token = cfm_issue_scoped_token($domains, $label, '4h');
            } catch (Throwable $e) {
                $error = $e->getMessage();
            }
        }
    }

    $iframeBase   = cfm_iframe_base_url();
    $iframeUrl    = $iframeBase . '/cfm-admin/webdetector/controls/';

    // Compute postMessage target origin (scheme + host + optional port).
    $parsed       = parse_url($iframeBase);
    $iframeOrigin = ($parsed['scheme'] ?? 'https') . '://' . ($parsed['host'] ?? '');
    if (!empty($parsed['port'])) {
        $iframeOrigin .= ':' . $parsed['port'];
    }

    cgi_send_headers();
    include __DIR__ . '/../templates/index.php';
    exit;
}
