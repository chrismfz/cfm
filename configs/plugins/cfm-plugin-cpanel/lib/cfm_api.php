<?php

function cfm_api_base_url(): string
{
    foreach (['CFM_API_BASE_URL', 'API_BASE_URL'] as $key) {
        $v = getenv($key);
        if (is_string($v) && trim($v) !== '') {
            return rtrim(trim($v), '/');
        }
    }

    return 'http://127.0.0.1:6060';
}

function cfm_api_token(): string
{
    return '';
}

function cfm_api_request(string $path, string $method = 'GET', ?array $payload = null): array
{
    $url = rtrim(cfm_api_base_url(), '/') . $path;
    $ch = curl_init($url);

    if ($ch === false) {
        throw new RuntimeException('Failed to initialize curl');
    }

    $headers = [
        'Accept: application/json',
    ];

    $token = cfm_api_token();
    if ($token !== '') {
        $headers[] = 'Authorization: Bearer ' . $token;
    }

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
    curl_setopt($ch, CURLOPT_TIMEOUT, 20);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($ch, CURLOPT_FAILONERROR, false);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    if ($payload !== null) {
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new RuntimeException('Failed to encode request payload');
        }
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
    if (!is_array($decoded)) {
        $decoded = ['raw' => $body];
    }

    if ($code >= 400) {
        $msg = $decoded['error'] ?? $decoded['message'] ?? ('HTTP ' . $code);
        throw new RuntimeException('CFM API error: ' . $msg);
    }

    return $decoded;
}

function cfm_list_excludes(string $kind): array
{
    if (!in_array($kind, ['challenge', 'waf'], true)) {
        throw new InvalidArgumentException('Invalid exclude kind');
    }

    return cfm_api_request('/api/v1/' . $kind . '/exclude/list', 'GET');
}

function cfm_add_exclude(string $kind, string $type, string $value): array
{
    $qs = http_build_query(['type' => $type, 'value' => $value]);
    return cfm_api_request('/api/v1/' . $kind . '/exclude/add?' . $qs, 'POST');
}

function cfm_remove_exclude(string $kind, string $type, string $value): array
{
    $qs = http_build_query(['type' => $type, 'value' => $value]);
    return cfm_api_request('/api/v1/' . $kind . '/exclude/remove?' . $qs, 'POST');
}
