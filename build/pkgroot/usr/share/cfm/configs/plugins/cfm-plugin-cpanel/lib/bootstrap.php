<?php
require_once __DIR__ . '/cfm_api.php';

function cgi_send_headers(string $contentType = 'text/html; charset=utf-8', array $extra = []): void
{
    echo "Content-Type: {$contentType}\r\n";
    foreach ($extra as $h) echo $h . "\r\n";
    echo "\r\n";
}

function get_current_cpanel_user(): string
{
    foreach (['REMOTE_USER', 'CPANEL_USER', 'REMOTE_LOGNAME', 'USER'] as $key) {
        $v = $_SERVER[$key] ?? getenv($key);
        if (is_string($v) && trim($v) !== '') {
            return strtolower(trim(preg_replace('/\s+/', '', $v)));
        }
    }
    return '';
}

function cfm_bootstrap(string $mode): void
{
    if (!in_array($mode, ['whm', 'cpanel'], true)) {
        cgi_send_headers();
        echo '<p>Invalid mode</p>';
        exit;
    }

    // WHM / root — redirect straight to the full admin UI.
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

    // cPanel mode.
    $currentUser = get_current_cpanel_user();
    $domains     = [];
    $dbUsers     = [];
    $databases   = [];
    $error       = '';
    $token       = '';
    $pageTitle   = 'CFM Security';
    $socketUIBase = '';

    if ($currentUser === '') {
        $error = 'Could not determine cPanel username.';
    } else {
        // Ask CFM (running as root) for the user's domains and DB info.
        $userInfoResult = cfm_get_user_info($currentUser);

        if (!($userInfoResult['ok'] ?? false)) {
            $httpCode = (int)($userInfoResult['http_code'] ?? 0);
            $apiError = trim((string)($userInfoResult['error'] ?? ''));
            $apiReason = trim((string)($userInfoResult['reason'] ?? ''));
            $hints    = $userInfoResult['hints'] ?? [];
            if (!is_array($hints)) $hints = [];

            if ($httpCode === 401 || $httpCode === 403) {
                $error = 'CFM API auth failed.';
            } else {
                $error = 'CFM API unreachable.';
            }

            $diagHints = [];
            foreach ($hints as $hint) {
                if (is_string($hint) && trim($hint) !== '') {
                    $diagHints[] = trim($hint);
                }
            }

            if ($apiError !== '') {
                $lowerError = strtolower($apiError);
                if (strpos($lowerError, 'timed out') !== false || strpos($lowerError, 'timeout') !== false) {
                    $diagHints[] = 'Request timed out before CFM API responded';
                }
                if (strpos($lowerError, 'failed to connect') !== false || strpos($lowerError, 'couldn\'t connect') !== false) {
                    $diagHints[] = 'Service may not be listening on configured local API port';
                }
            }

            if (!empty($diagHints)) {
                $error .= ' Hints: ' . implode('; ', array_values(array_unique($diagHints))) . '.';
            }
            if ($apiReason !== '' && cfm_debug_enabled()) {
                $error .= ' Reason: ' . $apiReason . '.';
            }
        } else {
            $userInfo = $userInfoResult['data'] ?? [];
            if (!is_array($userInfo)) $userInfo = [];

            // Authoritative plugin metadata source:
            // /api/v1/cpanel/user-info (via cfm_get_user_info). Do not add
            // filesystem/UAPI fallbacks in plugin runtime.
            // Troubleshooting note: in jailed plugin runtime, debug logs may show
            // auth_token_missing_in_plugin_runtime when /etc/cfm/cfm.conf is not
            // readable. This is expected/non-fatal as long as socket scoped-token
            // mint logs success immediately afterward.
            $domains   = $userInfo['domains'] ?? [];
            $dbUsers   = $userInfo['db_users'] ?? [];
            $databases = $userInfo['databases'] ?? [];

            if (!is_array($domains)) $domains = [];
            if (!is_array($dbUsers)) $dbUsers = [];
            if (!is_array($databases)) $databases = [];

            if (empty($domains)) {
                $error = 'No domains found for user "' . $currentUser . '".';
            }
        }

        if ($error === '' && !empty($domains)) {
            $token = trim((string)($userInfoResult['scoped_token'] ?? ''));
            $socketUIBase = trim((string)($userInfoResult['ui_base_url'] ?? ''));
            if ($token === '') {
                $error = 'CFM auth did not return a scoped token.';
            }
        }
    }

    $iframeBase   = cfm_iframe_base_url($socketUIBase);
    $iframeNext   = '/cfm-admin/webdetector/controls/';
    $iframeUrl    = $iframeBase . '/api/v1/embed/bootstrap?token=' . rawurlencode($token)
        . '&next=' . rawurlencode($iframeNext);
    $parsed       = parse_url($iframeBase);
    $iframeOrigin = ($parsed['scheme'] ?? 'https') . '://' . ($parsed['host'] ?? '');
    if (!empty($parsed['port'])) {
        $iframeOrigin .= ':' . $parsed['port'];
    }

    cgi_send_headers();
    include __DIR__ . '/../templates/index.php';
    exit;
}
