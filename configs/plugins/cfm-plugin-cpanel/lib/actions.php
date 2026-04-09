<?php

function json_response(array $data, int $status = 200, array $extraHeaders = []): void
{
    echo "Status: {$status}\r\n";
    echo "Content-Type: application/json; charset=utf-8\r\n";
    foreach ($extraHeaders as $line) {
        echo $line . "\r\n";
    }
    echo "\r\n";
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}

function require_post(array $extraHeaders = []): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        json_response(['ok' => false, 'error' => 'Method not allowed'], 405, $extraHeaders);
    }
}

function cfm_request_identity(string $mode): string
{
    $parts = [$mode];

    foreach (['REMOTE_USER', 'CPANEL_USER', 'REMOTE_LOGNAME', 'USER'] as $key) {
        $v = getenv($key);
        if (is_string($v) && trim($v) !== '') {
            $parts[] = trim($v);
            break;
        }
    }

    $host = $_SERVER['HTTP_HOST'] ?? '';
    if (is_string($host) && $host !== '') {
        $parts[] = $host;
    }

    return implode('|', $parts);
}

function cfm_secret_material(): string
{
    $candidates = [
        '/var/cpanel/cpanel.config',
        '/etc/wwwacct.conf',
        '/usr/local/cpanel/version',
        __FILE__,
    ];

    $buf = '';
    foreach ($candidates as $file) {
        if (is_readable($file)) {
            $content = @file_get_contents($file);
            if (is_string($content) && $content !== '') {
                $buf .= $content;
            }
        }
    }

    if ($buf === '') {
        $buf = 'cfm-fallback-secret';
    }

    return hash('sha256', $buf);
}

function session_token(string $mode = 'global'): string
{
    $identity = cfm_request_identity($mode);
    $secret   = cfm_secret_material();

    return hash_hmac('sha256', $identity, $secret);
}

function verify_token(string $mode, string $token, array $extraHeaders = []): void
{
    $expected = session_token($mode);

    if ($token === '' || !hash_equals($expected, $token)) {
        json_response([
            'ok' => false,
            'error' => 'Invalid CSRF token',
        ], 403, $extraHeaders);
    }
}

function allowed_domains_for_mode(string $mode, array $requestData = []): array
{
    $allowed = [];

    if ($mode === 'whm') {
        foreach (get_all_user_domains() as $row) {
            $allowed[normalize_host((string)$row['domain'])] = true;
        }
        return $allowed;
    }

    // cPanel: trust the visible domain list sent by the authenticated page
    if (!empty($requestData['visible_domains']) && is_array($requestData['visible_domains'])) {
        foreach ($requestData['visible_domains'] as $domain) {
            if (is_string($domain)) {
                $domain = normalize_host($domain);
                if ($domain !== '') {
                    $allowed[$domain] = true;
                }
            }
        }
        if (!empty($allowed)) {
            return $allowed;
        }
    }

    // fallback
    $user = get_current_cpanel_user();
    if ($user === '') {
        return [];
    }

    foreach (get_domains_for_user($user) as $domain) {
        $allowed[normalize_host((string)$domain)] = true;
    }

    return $allowed;
}

function handle_ajax_action(string $mode, array $extraHeaders = []): void
{
    if (($_GET['ajax'] ?? '') !== '1') {
        return;
    }

    require_post($extraHeaders);

    $raw = file_get_contents('php://stdin');
    if (!is_string($raw) || trim($raw) === '') {
        $raw = file_get_contents('php://input');
    }

    if (!is_string($raw) || trim($raw) === '') {
        json_response(['ok' => false, 'error' => 'Empty request body'], 400, $extraHeaders);
    }

    $data = json_decode($raw, true);
    if (!is_array($data)) {
        json_response([
            'ok' => false,
            'error' => 'Invalid JSON body',
            'raw' => substr($raw, 0, 200),
        ], 400, $extraHeaders);
    }

    verify_token($mode, (string)($data['token'] ?? ''), $extraHeaders);

    $op = (string)($data['op'] ?? 'toggle');
    if ($op === 'proxy_get' || $op === 'proxy_post') {
        $path = ltrim((string)($data['path'] ?? ''), '/');
        if ($path === '' || !cfm_is_allowed_proxy_path($path, $mode, $data)) {
            json_response(['ok' => false, 'error' => 'Proxy path not allowed'], 403, $extraHeaders);
        }

        try {
            $apiPath = '/api/' . ltrim($path, '/');
            $result = ($op === 'proxy_post')
                ? cfm_api_request($apiPath, 'POST', is_array($data['payload'] ?? null) ? $data['payload'] : [])
                : cfm_api_request($apiPath, 'GET');
        } catch (Throwable $e) {
            json_response(['ok' => false, 'error' => $e->getMessage()], 500, $extraHeaders);
        }

        if (!is_array($result)) {
            $result = ['data' => $result];
        }
        $result['ok'] = true;
        json_response($result, 200, $extraHeaders);
    }

    $kind   = (string)($data['kind'] ?? '');
    $domain = normalize_host((string)($data['domain'] ?? ''));
    $state  = !empty($data['state']);

    if (!in_array($kind, ['challenge', 'waf'], true)) {
        json_response(['ok' => false, 'error' => 'Invalid kind'], 400, $extraHeaders);
    }

    if ($domain === '') {
        json_response(['ok' => false, 'error' => 'Invalid domain'], 400, $extraHeaders);
    }

    $allowed = allowed_domains_for_mode($mode, $data);
    if (empty($allowed[$domain])) {
        json_response(['ok' => false, 'error' => 'Domain not allowed'], 403, $extraHeaders);
    }

    try {
        if ($state) {
            cfm_add_exclude($kind, 'host', $domain);
        } else {
            cfm_remove_exclude($kind, 'host', $domain);
        }
    } catch (Throwable $e) {
        json_response(['ok' => false, 'error' => $e->getMessage()], 500, $extraHeaders);
    }

    json_response([
        'ok'     => true,
        'kind'   => $kind,
        'domain' => $domain,
        'state'  => $state,
    ], 200, $extraHeaders);
}

function handle_asset_request(string $mode, array $extraHeaders = []): void
{
    $asset = (string)($_GET["asset"] ?? "");
    if ($asset === "") {
        return;
    }

    $map = [
        "style.css" => [__DIR__ . "/assets/style.css", "text/css; charset=utf-8"],
        "app.js"    => [__DIR__ . "/assets/app.js", "application/javascript; charset=utf-8"],
    ];

    if (empty($map[$asset]) || !is_readable($map[$asset][0])) {
        echo "Status: 404\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nNot found";
        exit;
    }

    [$file, $type] = $map[$asset];
    echo "Content-Type: {$type}\r\n";
    foreach ($extraHeaders as $line) {
        echo $line . "\r\n";
    }
    echo "\r\n";
    readfile($file);
    exit;
}

function cfm_extract_proxy_host(string $path): string
{
    $qs = parse_url($path, PHP_URL_QUERY);
    if (!is_string($qs) || $qs === '') {
        return '';
    }
    parse_str($qs, $params);
    $host = normalize_host((string)($params['host'] ?? ''));
    return $host;
}

function cfm_is_allowed_proxy_path(string $path, string $mode, array $requestData = []): bool
{
    $path = ltrim($path, '/');

    if ($mode === 'cpanel') {
        if (strpos($path, 'v1/webdet/drilldown') !== 0) {
            return false;
        }

        $host = cfm_extract_proxy_host($path);
        if ($host === '') {
            return false;
        }

        $allowed = allowed_domains_for_mode($mode, $requestData);
        return !empty($allowed[$host]);
    }

    $allowedPrefixes = [
        'v1/system/status',
        'v1/system/dnat',
        'v1/system/ssl/stats',
        'v1/webdet/top-short',
        'v1/webdet/suspicious',
        'v1/webdet/long-top',
        'v1/webdet/drilldown',
        'v1/challenge/vhosts',
        'v1/challenge/vhost/add',
        'v1/challenge/vhost/remove',
        'v1/mysql/state',
        'v1/mysql/processlist',
        'v1/mysql/locks',
        'v1/mysql/cpu',
        'v1/mysql/history',
        'v1/mysql/history/summary',
        'v1/waf/engine/summary',
    ];

    foreach ($allowedPrefixes as $prefix) {
        if (strpos($path, $prefix) === 0) {
            return true;
        }
    }

    return false;
}
