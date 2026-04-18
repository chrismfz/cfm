<?php
// cfm_api.php — CFM API client for the cPanel plugin.
// Reads PORT, TLS_PORT from /etc/cfm/cfm.conf.

function cfm_parse_conf(string $path = '/etc/cfm/cfm.conf'): array
{
    $cfg = [];
    if (!is_readable($path)) return $cfg;
    $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) return $cfg;
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#' || $line[0] === ';') continue;
        if (strpos($line, '=') === false) continue;
        [$k, $v] = explode('=', $line, 2);
        $k = trim($k);
        $v = trim(trim($v), '"\'');
        // strip inline comments
        foreach ([' #', ' //', ' ;'] as $marker) {
            if (($pos = strpos($v, $marker)) !== false) {
                $v = trim(substr($v, 0, $pos));
            }
        }
        if ($k !== '') $cfg[$k] = $v;
    }
    return $cfg;
}

function cfm_conf(): array
{
    static $cfg = null;
    if ($cfg === null) $cfg = cfm_parse_conf();
    return $cfg;
}

function cfm_debug_enabled(): bool
{
    static $enabled = null;
    if ($enabled !== null) return $enabled;

    $on  = ['1', 'true', 'yes', 'on'];
    $off = ['0', 'false', 'no', 'off'];

    // Runtime trigger (no config file access required):
    // ?cfm_debug=0 to disable, ?cfm_debug=1 to re-enable.
    $queryToggle = strtolower(trim((string)($_GET['cfm_debug'] ?? '')));
    if ($queryToggle !== '') {
        if (in_array($queryToggle, $off, true)) {
            @setcookie('CFM_PLUGIN_DEBUG', '0', time() + 86400, '/');
            $enabled = false;
            return $enabled;
        }
        if (in_array($queryToggle, $on, true)) {
            @setcookie('CFM_PLUGIN_DEBUG', '1', time() + 86400, '/');
            $enabled = true;
            return $enabled;
        }
    }

    // Cookie override for operators during live debugging.
    $cookieToggle = strtolower(trim((string)($_COOKIE['CFM_PLUGIN_DEBUG'] ?? '')));
    if (in_array($cookieToggle, $off, true)) {
        $enabled = false;
        return $enabled;
    }
    if (in_array($cookieToggle, $on, true)) {
        $enabled = true;
        return $enabled;
    }

    // Backward-compatible config/env toggles if readable.
    $cfg = cfm_conf();
    foreach (['CPANEL_PLUGIN_DEBUG', 'CFM_PLUGIN_DEBUG', 'DEBUG'] as $k) {
        $v = strtolower(trim((string)($cfg[$k] ?? getenv($k) ?? '')));
        if (in_array($v, $off, true)) {
            $enabled = false;
            return $enabled;
        }
        if (in_array($v, $on, true)) {
            $enabled = true;
            return $enabled;
        }
    }

    // Default on while investigating auth failures.
    $enabled = true;
    return $enabled;
}

function cfm_debug_log(string $message, array $context = []): void
{
    if (!cfm_debug_enabled()) return;
    if (!empty($context)) {
        $safe = json_encode($context, JSON_UNESCAPED_SLASHES);
        if (!is_string($safe)) $safe = '{}';
        error_log('[cfm][debug] ' . $message . ' ' . $safe);
        return;
    }
    error_log('[cfm][debug] ' . $message);
}

// Local API base URL — always loopback, used for server-side calls (token issuance).
function cfm_local_base_url(): string
{
    $cfg = cfm_conf();
    $port = (int)($cfg['PORT'] ?? 6060);
    if ($port <= 0) $port = 6060;
    return 'http://127.0.0.1:' . $port;
}

function cfm_request_host(): string
{
    $rawHost = trim((string)(getenv('HTTP_HOST') ?: ($_SERVER['HTTP_HOST'] ?? '')));
    if ($rawHost === '') return '';
    if (strpos($rawHost, ':') !== false) {
        $rawHost = preg_replace('/:\d+$/', '', $rawHost);
    }
    return strtolower(trim((string)$rawHost, '[]'));
}

function cfm_forwarded_or_request_host(): string
{
    $rawForwarded = trim((string)(getenv('HTTP_X_FORWARDED_HOST') ?: ($_SERVER['HTTP_X_FORWARDED_HOST'] ?? '')));
    if ($rawForwarded !== '') {
        // X-Forwarded-Host may contain a comma-separated chain.
        $first = trim((string)explode(',', $rawForwarded, 2)[0]);
        if ($first !== '') {
            if (strpos($first, ':') !== false) {
                $first = preg_replace('/:\d+$/', '', $first);
            }
            $first = strtolower(trim((string)$first, '[]'));
            if ($first !== '') return $first;
        }
    }
    return cfm_request_host();
}

function cfm_canonical_host(array $cfg): string
{
    foreach (['CPANEL_PLUGIN_CANONICAL_HOST', 'PLUGIN_CANONICAL_HOST', 'CANONICAL_HOST', 'HOSTNAME'] as $key) {
        $value = strtolower(trim((string)($cfg[$key] ?? '')));
        if ($value !== '') return trim($value, '[]');
    }

    $apiUrl = trim((string)($cfg['API_URL'] ?? ''));
    if ($apiUrl !== '') {
        $host = parse_url($apiUrl, PHP_URL_HOST);
        if (is_string($host) && $host !== '') return strtolower(trim($host, '[]'));
    }

    $host = trim((string)shell_exec('hostname -f 2>/dev/null'));
    if ($host === '') $host = (string)gethostname();
    return strtolower(trim($host, '[]'));
}

// Browser-facing base URL for the iframe.
// Priority: CPANEL_PLUGIN_BASE_URL override -> socket-provided UI base -> legacy config fallback.
function cfm_iframe_base_url(string $socketUiBaseUrl = ''): string
{
    $cfg = cfm_conf();

    // Explicit override — deterministic/admin-controlled endpoint.
    $override = trim($cfg['CPANEL_PLUGIN_BASE_URL'] ?? '');
    if ($override !== '') {
        $selected = rtrim($override, '/');
        cfm_debug_log('iframe_base_url_selected', [
            'ui_base_source' => 'override',
            'ui_base_url' => $selected,
        ]);
        return $selected;
    }

    $socketBase = trim($socketUiBaseUrl);
    if ($socketBase !== '') {
        $parsedSocket = parse_url($socketBase);
        $socketPort = (int)($parsedSocket['port'] ?? 0);
        $legacyPorts = array_filter([
            (int)($cfg['PORT'] ?? 6060),
            (int)($cfg['TLS_PORT'] ?? 0),
        ], static fn(int $p): bool => $p > 0);

        if ($socketPort > 0 && in_array($socketPort, $legacyPorts, true)) {
            cfm_debug_log('iframe_base_url_socket_ignored_legacy_port', [
                'socket_ui_base_url' => $socketBase,
                'socket_port' => $socketPort,
                'legacy_ports' => array_values($legacyPorts),
            ]);
        } else {
            $selected = rtrim($socketBase, '/');
            cfm_debug_log('iframe_base_url_selected', [
                'ui_base_source' => 'socket',
                'ui_base_url' => $selected,
            ]);
            return $selected;
        }
    }

    $requestHost   = cfm_request_host();
    $canonicalHost = cfm_canonical_host($cfg);

    $hostMismatch = ($requestHost !== '' && $canonicalHost !== '' && strcasecmp($requestHost, $canonicalHost) !== 0);
    $effectiveHost = $requestHost !== '' ? $requestHost : $canonicalHost;

    if ($hostMismatch) {
        // Mixed-hostname access detected (e.g., account domain in cPanel frame).
        // Keep traffic on OpenResty /cfm-admin path, but force canonical host.
        cfm_debug_log('iframe_base_url_host_mismatch_canonical_fallback', [
            'http_host'      => $requestHost,
            'canonical_host' => $canonicalHost,
        ]);
        $selected = 'https://' . $canonicalHost;
        cfm_debug_log('iframe_base_url_selected', [
            'ui_base_source' => 'legacy_fallback',
            'ui_base_url' => $selected,
        ]);
        return $selected;
    }

    // /cfm-admin/ is handled by OpenResty location proxy on standard HTTPS.
    $selected = 'https://' . $effectiveHost;
    cfm_debug_log('iframe_base_url_selected', [
        'ui_base_source' => 'legacy_fallback',
        'ui_base_url' => $selected,
    ]);
    return $selected;
}

// WHM-facing base URL for root/admin entrypoint redirects.
// Prefer canonical server hostname so WHM launches the plugin on the server
// hostname instead of an account domain/frame host.
function cfm_whm_base_url(string $socketUiBaseUrl = ''): string
{
    $cfg = cfm_conf();

    // Preserve explicit admin override behavior.
    $override = trim($cfg['CPANEL_PLUGIN_BASE_URL'] ?? '');
    if ($override !== '') {
        $selected = rtrim($override, '/');
        cfm_debug_log('whm_base_url_selected', [
            'ui_base_source' => 'override',
            'ui_base_url' => $selected,
        ]);
        return $selected;
    }

    // In WHM, prefer the hostname used to open WHM itself.
    // This avoids stale socket metadata (e.g. old :6061 direct listeners).
    $requestHost = cfm_forwarded_or_request_host();
    $canonicalHost = cfm_canonical_host($cfg);
    $effectiveHost = $requestHost !== '' ? $requestHost : $canonicalHost;

    $selected = 'https://' . $effectiveHost;
    cfm_debug_log('whm_base_url_selected', [
        'ui_base_source' => $requestHost !== '' ? 'whm_request_host' : 'canonical_https',
        'ui_base_url' => $selected,
        'request_host' => $requestHost,
        'canonical_host' => $canonicalHost,
    ]);
    return $selected;
}

// Generic CFM API call (server-side, loopback).
function cfm_api_request(string $path, string $method = 'GET', ?array $payload = null, array $extraHeaders = []): array
{
    $url = rtrim(cfm_local_base_url(), '/') . $path;
    $ch  = curl_init($url);
    if ($ch === false) throw new RuntimeException('curl_init failed');

    $headers = ['Accept: application/json'];
    foreach ($extraHeaders as $h) {
        if (is_string($h) && trim($h) !== '') {
            $headers[] = trim($h);
        }
    }
    if (cfm_debug_enabled()) {
        $headers[] = 'X-CFM-Debug: 1';
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_FAILONERROR    => false,
        CURLOPT_HTTPHEADER     => $headers,
    ]);

    if ($payload !== null) {
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if ($json === false) throw new RuntimeException('json_encode failed');
        $headers[] = 'Content-Type: application/json';
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
    }

    $body = curl_exec($ch);
    if ($body === false) {
        $err = curl_error($ch);
        curl_close($ch);
        throw new RuntimeException('CFM API request failed: ' . $err);
    }
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    cfm_debug_log('api_request', [
        'method'         => strtoupper($method),
        'path'           => $path,
        'url'            => $url,
        'http_code'      => $code,
        'extra_headers'  => count($extraHeaders),
        'payload_present'=> $payload !== null,
    ]);

    $decoded = json_decode($body, true);
    if (!is_array($decoded)) $decoded = ['raw' => $body];
    if ($code >= 400) {
        $bodyPreview = trim(substr(preg_replace('/\s+/', ' ', (string)$body), 0, 300));
        throw new RuntimeException(
            ($decoded['error'] ?? $decoded['message'] ?? ('HTTP ' . $code)) .
            ($bodyPreview !== '' ? ('; response=' . $bodyPreview) : ''),
            $code
        );
    }
    return $decoded;
}

function cfm_socket_auth_path(): string
{
    return '/var/run/cfm-auth.sock';
}

function cfm_admin_token(): string
{
    $cfg = cfm_conf();
    return trim((string)($cfg['AUTH_TOKEN'] ?? $cfg['TOKEN'] ?? ''));
}

function cfm_should_log_auth_token_missing_once(): bool
{
    static $alreadyLogged = false;
    if ($alreadyLogged) return false;
    $alreadyLogged = true;
    return true;
}

function cfm_issue_actor_assertion(string $user): array
{
    $sock = cfm_socket_auth_path();
    $confPath = '/etc/cfm/cfm.conf';
    $confReadable = is_readable($confPath);
    $cfg = cfm_conf();
    $authTokenKeyExists = array_key_exists('AUTH_TOKEN', $cfg) || array_key_exists('TOKEN', $cfg);
    $adminToken = cfm_admin_token();
    $adminTokenMissing = ($adminToken === '');
    if ($adminTokenMissing && cfm_should_log_auth_token_missing_once()) {
        // In jailed cPanel plugin runtime, /etc/cfm/cfm.conf (and AUTH_TOKEN inside it)
        // may be intentionally unreadable. This is expected and non-fatal because the
        // plugin prefers the unix-socket auth flow and scoped-token mint path.
        cfm_debug_log('auth_token_missing_in_plugin_runtime', [
            'note' => 'non-fatal in jailed plugin runtime; socket auth path preferred',
            'conf_path' => $confPath,
            'conf_readable' => $confReadable,
            'auth_token_key_exists' => $authTokenKeyExists,
        ]);
    }

    $nonce = bin2hex(random_bytes(12));
    $ts = time();
    $source = 'env_upper';
    $secTok = trim((string)($_SERVER['CP_SECURITY_TOKEN'] ?? getenv('CP_SECURITY_TOKEN') ?? ''));
    if ($secTok === '') {
        $source = 'env_lower';
        $secTok = trim((string)($_SERVER['cp_security_token'] ?? getenv('cp_security_token') ?? ''));
    }
    if ($secTok === '') {
        $source = 'request_uri';
        $uri = (string)($_SERVER['REQUEST_URI'] ?? getenv('REQUEST_URI') ?? '');
        if (preg_match('~(/cpsess[0-9A-Za-z]{8,128})/~', $uri, $m)) {
            $secTok = trim((string)$m[1]);
        }
    }
    if ($secTok === '') {
        cfm_debug_log('auth_socket_assertion_issue_failed', ['user' => $user, 'reason' => 'token_missing', 'source' => $source, 'sock' => $sock]);
        cfm_debug_log('auth_socket_scoped_token_mint_failed', ['user' => $user, 'reason' => 'assertion_issue_failed', 'source' => $source, 'sock' => $sock]);
        return ['ok' => false, 'reason' => 'token_missing', 'error' => 'Missing cPanel security token'];
    }

    $req = [
        'panel' => 'cpanel',
        'user' => strtolower(trim($user)),
        'cpsess' => $secTok,
        'ts' => $ts,
        'nonce' => $nonce,
        'request_host' => cfm_request_host(),
    ];
    $json = json_encode($req, JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) {
        return ['ok' => false, 'reason' => 'bad_json', 'error' => 'Failed to encode auth request'];
    }

    $fp = @stream_socket_client('unix://' . $sock, $errno, $errstr, 1.5);
    if (!is_resource($fp)) {
        cfm_debug_log('auth_socket_assertion_issue_failed', ['user' => $user, 'reason' => 'socket_connect_failed', 'source' => $source, 'sock' => $sock]);
        cfm_debug_log('auth_socket_scoped_token_mint_failed', ['user' => $user, 'reason' => 'assertion_issue_failed', 'source' => $source, 'sock' => $sock]);
        return ['ok' => false, 'reason' => 'socket_connect_failed', 'error' => 'Auth socket unavailable (' . $sock . ')'];
    }
    stream_set_timeout($fp, 2);
    $http = "POST /auth/issue HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Content-Type: application/json\r\n" .
        "Content-Length: " . strlen($json) . "\r\n" .
        "Connection: close\r\n\r\n" .
        $json;
    fwrite($fp, $http);
    $raw = stream_get_contents($fp);
    fclose($fp);
    if (!is_string($raw) || $raw === '') {
        cfm_debug_log('auth_socket_assertion_issue_failed', ['user' => $user, 'reason' => 'socket_empty_response', 'source' => $source, 'sock' => $sock]);
        cfm_debug_log('auth_socket_scoped_token_mint_failed', ['user' => $user, 'reason' => 'assertion_issue_failed', 'source' => $source, 'sock' => $sock]);
        return ['ok' => false, 'reason' => 'socket_empty_response', 'error' => 'Empty auth socket response'];
    }
    $parts = preg_split("/\r\n\r\n/", $raw, 2);
    $body = is_array($parts) && isset($parts[1]) ? $parts[1] : '';
    $statusLine = is_array($parts) && isset($parts[0]) ? strtok($parts[0], "\r\n") : '';
    $status = 0;
    if (is_string($statusLine) && preg_match('/\s(\d{3})\s/', $statusLine, $m)) {
        $status = (int)$m[1];
    }
    $decoded = json_decode((string)$body, true);
    if (!is_array($decoded)) $decoded = [];
    $assertion = trim((string)($decoded['assertion'] ?? ''));
    if ($status >= 200 && $status < 300 && $assertion !== '') {
        $scopedToken = trim((string)($decoded['scoped_token'] ?? ''));
        $uiBaseUrl = rtrim(trim((string)($decoded['ui_base_url'] ?? '')), '/');
        if ($scopedToken === '') {
            cfm_debug_log('auth_socket_scoped_token_mint_failed', ['user' => $user, 'source' => $source, 'sock' => $sock, 'reason' => 'scoped_token_missing']);
            return ['ok' => false, 'reason' => 'scoped_token_missing', 'error' => 'No scoped token returned from auth service'];
        }
        cfm_debug_log('auth_socket_assertion_issue_ok', ['user' => $user, 'source' => $source, 'sock' => $sock]);
        cfm_debug_log('auth_socket_scoped_token_mint_ok', [
            'user' => $user,
            'source' => $source,
            'sock' => $sock,
            'ui_base_source' => $uiBaseUrl !== '' ? 'socket' : 'missing',
            'ui_base_url' => $uiBaseUrl,
        ]);
        if ($adminTokenMissing) {
            cfm_debug_log('auth_socket_scoped_token_mint_ok_after_admin_token_missing', [
                'user' => $user,
                'source' => $source,
                'sock' => $sock,
                'note' => 'socket scoped token mint succeeded; missing /etc/cfm/cfm.conf AUTH_TOKEN did not block authentication',
            ]);
        }
        $userInfo = $decoded['user_info'] ?? null;
        if (!is_array($userInfo)) $userInfo = null;
        return ['ok' => true, 'assertion' => $assertion, 'scoped_token' => $scopedToken, 'user_info' => $userInfo, 'ui_base_url' => $uiBaseUrl];
    }
    cfm_debug_log('auth_socket_assertion_issue_failed', [
        'user' => $user,
        'reason' => trim((string)($decoded['reason'] ?? 'auth_failed')),
        'source' => $source,
        'sock' => $sock,
        'http_status' => $status,
    ]);
    cfm_debug_log('auth_socket_scoped_token_mint_failed', [
        'user' => $user,
        'reason' => trim((string)($decoded['reason'] ?? 'auth_failed')),
        'source' => $source,
        'sock' => $sock,
        'http_status' => $status,
        'admin_token_missing_in_plugin_runtime' => $adminTokenMissing,
        'conf_readable' => $confReadable,
        'auth_token_key_exists' => $authTokenKeyExists,
    ]);
    $uiError = trim((string)($decoded['error'] ?? ''));
    if ($adminTokenMissing) {
        $uiError = 'Scoped token mint unavailable: plugin cannot access daemon admin token.';
    }
    if ($uiError === '') $uiError = 'authorization required';
    return [
        'ok' => false,
        'reason' => trim((string)($decoded['reason'] ?? 'auth_failed')),
        'error' => $uiError,
    ];
}

// Get user info (domains, db_users, databases) from CFM's local API.
// CFM runs as root and has full access to cPanel metadata files.
function cfm_get_user_info(string $user): array
{
    if ($user === '') {
        return [
            'ok'        => false,
            'error'     => 'Missing cPanel username',
            'http_code' => 400,
            'hints'     => [],
        ];
    }

    $hints = [];
    $localBase = cfm_local_base_url();

    try {
        $issued = cfm_issue_actor_assertion($user);
        if (!($issued['ok'] ?? false)) {
            $reason = trim((string)($issued['reason'] ?? 'auth_failed'));
            $error = trim((string)($issued['error'] ?? 'authorization required'));
            if ($reason === 'session_not_found') {
                $hints[] = 'cPanel session not found or expired; open CFM from cPanel again to refresh session context';
            } elseif ($reason === 'secret_missing') {
                $hints[] = 'CFM daemon assertion secret is not configured';
            } elseif ($reason === 'token_malformed') {
                $hints[] = 'Invalid cPanel session token format from request context';
            } elseif ($reason === 'token_replay') {
                $hints[] = 'Actor assertion nonce replay detected; ensure each API call uses a fresh assertion or avoid duplicate actor-auth calls.';
            }
            return [
                'ok'        => false,
                'error'     => $error,
                'http_code' => 401,
                'reason'    => $reason,
                'hints'     => array_values(array_unique($hints)),
            ];
        }
        $iframeBase = cfm_iframe_base_url((string)($issued['ui_base_url'] ?? ''));
        if ($iframeBase !== '' && strpos($iframeBase, '127.0.0.1') !== false) {
            $hints[] = 'Base URL may be loopback-only; verify CPANEL_PLUGIN_BASE_URL/TLS_PORT for browser access';
        }
        $mintedUserInfo = $issued['user_info'] ?? null;
        if (!is_array($mintedUserInfo)) $mintedUserInfo = null;
        $usedMintedUserInfo = $mintedUserInfo !== null;

        cfm_debug_log('user_info_request', [
            'user' => $user,
            'local_base' => $localBase,
            'call_graph' => 'cfm_get_user_info -> cfm_issue_actor_assertion -> auth_socket_scoped_token_mint_ok' . ($usedMintedUserInfo ? '' : ' -> /api/v1/cpanel/user-info'),
            'assertion_present' => trim((string)($issued['assertion'] ?? '')) !== '',
            'scoped_token_present' => trim((string)($issued['scoped_token'] ?? '')) !== '',
            'auth_header_count' => 0,
            'auth_headers' => [],
            'used_minted_user_info' => $usedMintedUserInfo,
            'assertion_nonce_reused' => false,
        ]);

        if ($usedMintedUserInfo) {
            $data = $mintedUserInfo;
        } else {
            $freshIssued = cfm_issue_actor_assertion($user);
            if (!($freshIssued['ok'] ?? false)) {
                $reason = trim((string)($freshIssued['reason'] ?? 'auth_failed'));
                $error = trim((string)($freshIssued['error'] ?? 'authorization required'));
                return [
                    'ok'        => false,
                    'error'     => $error,
                    'http_code' => 401,
                    'reason'    => $reason,
                    'hints'     => array_values(array_unique($hints)),
                ];
            }
            $assertion = trim((string)$freshIssued['assertion']);
            $headers = ['X-CFM-Actor-Assertion: ' . $assertion];
            cfm_debug_log('user_info_request_fallback', [
                'user' => $user,
                'local_base' => $localBase,
                'call_graph' => 'cfm_get_user_info -> cfm_issue_actor_assertion (mint scoped token) -> cfm_issue_actor_assertion (fresh) -> /api/v1/cpanel/user-info',
                'assertion_present' => $assertion !== '',
                'scoped_token_present' => trim((string)($freshIssued['scoped_token'] ?? '')) !== '',
                'auth_header_count' => count($headers),
                'auth_headers' => array_map(static function ($h) {
                    $p = strpos($h, ':');
                    return $p === false ? $h : substr($h, 0, $p);
                }, $headers),
                'used_minted_user_info' => false,
                'assertion_nonce_reused' => false,
            ]);
            $data = cfm_api_request('/api/v1/cpanel/user-info?' . http_build_query(['user' => $user]), 'GET', null, $headers);
        }
        return [
            'ok'        => true,
            'data'      => $data,
            'scoped_token' => trim((string)($issued['scoped_token'] ?? '')),
            'ui_base_url' => trim((string)($issued['ui_base_url'] ?? '')),
            'http_code' => 200,
            'reason'    => '',
            'hints'     => $hints,
        ];
    } catch (Throwable $e) {
        $errorMessage = trim((string)$e->getMessage());
        $httpCode = (int)$e->getCode();
        if ($httpCode < 0 || $httpCode > 599) $httpCode = 0;

        $lowerMessage = strtolower($errorMessage);
        if (strpos($lowerMessage, 'timed out') !== false || strpos($lowerMessage, 'timeout') !== false) {
            $hints[] = 'CFM API timeout; verify local service health and firewall rules';
        }
        if ($httpCode === 401 || $httpCode === 403) {
            $hints[] = 'Authentication rejected; verify actor assertion flow and shared assertion secret';
        }
        if (strpos($lowerMessage, 'failed to connect') !== false || strpos($lowerMessage, 'couldn\'t connect') !== false) {
            $hints[] = 'CFM API may be unreachable at ' . $localBase;
        }

        error_log('[cfm] user-info failed: ' . $errorMessage . ' (http=' . $httpCode . ')');
        return [
            'ok'        => false,
            'error'     => $errorMessage !== '' ? $errorMessage : 'CFM API request failed',
            'http_code' => $httpCode,
            'hints'     => array_values(array_unique($hints)),
        ];
    }
}
