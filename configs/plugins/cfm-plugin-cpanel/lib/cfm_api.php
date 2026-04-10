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
function cfm_api_request(string $path, string $method = 'GET', ?array $payload = null): array
{
    $url = rtrim(cfm_local_base_url(), '/') . $path;
    $ch  = curl_init($url);
    if ($ch === false) throw new RuntimeException('curl_init failed');

    $headers = ['Accept: application/json'];
    $tok = cfm_admin_token();
    if ($tok !== '') $headers[] = 'Authorization: Bearer ' . $tok;

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

    $decoded = json_decode($body, true);
    if (!is_array($decoded)) $decoded = ['raw' => $body];
    if ($code >= 400) {
        throw new RuntimeException($decoded['error'] ?? $decoded['message'] ?? ('HTTP ' . $code));
    }
    return $decoded;
}

// Get user info (domains, db_users, databases) from CFM's local API.
// CFM runs as root and has full access to cPanel metadata files.
function cfm_get_user_info(string $user): array
{
    if ($user === '') return [];
    try {
        return cfm_api_request('/api/v1/cpanel/user-info?' . http_build_query(['user' => $user]), 'GET');
    } catch (Throwable $e) {
        error_log('[cfm] user-info failed: ' . $e->getMessage());
        return [];
    }
}
