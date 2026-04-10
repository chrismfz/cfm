<?php
// cfm_api.php — CFM API client for the cPanel plugin.
// Reads AUTH_TOKEN, PORT, TLS_PORT from /etc/cfm/cfm.conf.

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

// Admin bearer token from cfm.conf.
function cfm_admin_token(): string
{
    $cfg = cfm_conf();
    return trim($cfg['AUTH_TOKEN'] ?? '');
}

// Browser-facing base URL for the iframe.
// Priority: CPANEL_PLUGIN_BASE_URL override → TLS_PORT → PORT → bare hostname.
function cfm_iframe_base_url(): string
{
    $cfg = cfm_conf();

    // Explicit override — admin escape hatch for unusual setups.
    $override = trim($cfg['CPANEL_PLUGIN_BASE_URL'] ?? '');
    if ($override !== '') return rtrim($override, '/');

    // Derive hostname from the HTTP request (strip any port cPanel appends).
    $httpHost = preg_replace('/:\d+$/', '', (string)(getenv('HTTP_HOST') ?: ''));
    if ($httpHost === '') {
        $httpHost = trim((string)shell_exec('hostname -f 2>/dev/null'));
    }
    if ($httpHost === '') {
        $httpHost = (string)gethostname();
    }

    $tlsPort = (int)($cfg['TLS_PORT'] ?? 0);

    if ($tlsPort > 0) {
        // Direct TLS port — bypasses OpenResty, hits Go directly.
        return 'https://' . $httpHost . ':' . $tlsPort;
    }

    // No TLS_PORT → assume OpenResty is in front on standard 443.
    // /cfm-admin/ is already handled by the OpenResty location block.
    return 'https://' . $httpHost;
}

// Issue a scoped token for the given vhosts via the local API.
// Returns the token string.
function cfm_issue_scoped_token(array $vhosts, string $label = '', string $ttl = '4h'): string
{
    if (empty($vhosts)) {
        throw new RuntimeException('No vhosts to scope token to');
    }

    $result = cfm_api_request('/api/v1/auth/token', 'POST', [
        'vhosts' => array_values(array_unique($vhosts)),
        'role'   => 'viewer',
        'ttl'    => $ttl,
        'label'  => $label,
    ]);

    $token = $result['token'] ?? '';
    if ($token === '') {
        throw new RuntimeException('CFM returned no token — check AUTH_TOKEN in cfm.conf');
    }
    return $token;
}

// Generic CFM API call (server-side, loopback).
function cfm_api_request(string $path, string $method = 'GET', ?array $payload = null, array $extraHeaders = [], bool $includeAdminToken = true): array
{
    $url = rtrim(cfm_local_base_url(), '/') . $path;
    $ch  = curl_init($url);
    if ($ch === false) throw new RuntimeException('curl_init failed');

    $headers = ['Accept: application/json'];
    $tok = '';
    if ($includeAdminToken) {
        $tok = cfm_admin_token();
        if ($tok !== '') $headers[] = 'Authorization: Bearer ' . $tok;
    }
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
        'admin_auth'     => $tok !== '',
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
    $cfg = cfm_conf();
    $path = trim((string)($cfg['CPANEL_PLUGIN_AUTH_SOCK'] ?? ''));
    return $path !== '' ? $path : '/var/run/cfm-auth.sock';
}

function cfm_issue_actor_assertion(string $user): array
{
    $sock = cfm_socket_auth_path();
    $nonce = bin2hex(random_bytes(12));
    $ts = time();
    $secTok = trim((string)($_SERVER['CP_SECURITY_TOKEN'] ?? $_SERVER['cp_security_token'] ?? getenv('CP_SECURITY_TOKEN') ?? ''));
    if ($secTok === '') {
        return ['ok' => false, 'reason' => 'token_missing', 'error' => 'Missing cPanel security token'];
    }

    $req = [
        'panel' => 'cpanel',
        'user' => strtolower(trim($user)),
        'cpsess' => $secTok,
        'ts' => $ts,
        'nonce' => $nonce,
    ];
    $json = json_encode($req, JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) {
        return ['ok' => false, 'reason' => 'bad_json', 'error' => 'Failed to encode auth request'];
    }

    $fp = @stream_socket_client('unix://' . $sock, $errno, $errstr, 1.5);
    if (!is_resource($fp)) {
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
        return ['ok' => true, 'assertion' => $assertion];
    }
    return [
        'ok' => false,
        'reason' => trim((string)($decoded['reason'] ?? 'auth_failed')),
        'error' => trim((string)($decoded['error'] ?? 'authorization required')),
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
    $iframeBase = cfm_iframe_base_url();
    if ($iframeBase !== '' && strpos($iframeBase, '127.0.0.1') !== false) {
        $hints[] = 'Base URL may be loopback-only; verify CPANEL_PLUGIN_BASE_URL/TLS_PORT for browser access';
    }

    try {
        $issued = cfm_issue_actor_assertion($user);
        if (!($issued['ok'] ?? false)) {
            $reason = trim((string)($issued['reason'] ?? 'auth_failed'));
            $error = trim((string)($issued['error'] ?? 'authorization required'));
            cfm_debug_log('auth_socket_issue_failed', ['user' => $user, 'reason' => $reason]);
            return [
                'ok'        => false,
                'error'     => $error,
                'http_code' => 401,
                'reason'    => $reason,
                'hints'     => array_values(array_unique($hints)),
            ];
        }
        $assertion = trim((string)$issued['assertion']);
        $headers = ['X-CFM-Actor-Assertion: ' . $assertion];
        cfm_debug_log('user_info_request', [
            'user' => $user,
            'local_base' => $localBase,
            'assertion_present' => $assertion !== '',
            'auth_header_count' => count($headers),
            'auth_headers' => array_map(static function ($h) {
                $p = strpos($h, ':');
                return $p === false ? $h : substr($h, 0, $p);
            }, $headers),
        ]);
        $data = cfm_api_request('/api/v1/cpanel/user-info?' . http_build_query(['user' => $user]), 'GET', null, $headers, false);
        return [
            'ok'        => true,
            'data'      => $data,
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
