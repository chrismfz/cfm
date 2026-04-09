<?php

function normalize_host(string $host): string
{
    $host = strtolower(trim($host));
    $host = preg_replace('/\.+$/', '', $host);
    return $host;
}

function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function str_ends_with_compat(string $haystack, string $needle): bool
{
    if ($needle === '') {
        return true;
    }

    $len = strlen($needle);
    if ($len > strlen($haystack)) {
        return false;
    }

    return substr($haystack, -$len) === $needle;
}

function normalize_cpanel_user(string $user): string
{
    $user = trim($user);

    // Defensive cleanup for odd CGI/env values
    $user = preg_replace('/\s+/', '', $user);
    $user = strtolower($user);

    return $user;
}

function domain_looks_valid(string $domain): bool
{
    if ($domain === '' || strpos($domain, '.') === false) {
        return false;
    }

    return (bool) preg_match('/^[a-z0-9][a-z0-9\.\-\*]*[a-z0-9]$/i', $domain);
}

function should_skip_domain_name(string $domain): bool
{
    if ($domain === '') {
        return true;
    }

    if (str_ends_with_compat($domain, '_ssl')) {
        return true;
    }

    foreach (['.cache', '.yaml', '.json', '.tmp', '.bak'] as $suffix) {
        if (str_ends_with_compat($domain, $suffix)) {
            return true;
        }
    }

    return false;
}

function finalize_domains(array $domains): array
{
    $set = [];

    foreach ($domains as $domain) {
        if (!is_string($domain)) {
            continue;
        }

        $domain = normalize_host($domain);

        if ($domain === '' || should_skip_domain_name($domain) || !domain_looks_valid($domain)) {
            continue;
        }

        $set[$domain] = true;
    }

    $out = array_keys($set);
    sort($out, SORT_NATURAL | SORT_FLAG_CASE);

    return $out;
}


// ── MySQL database and user discovery ────────────────────────────────────────
//
// cPanel MySQL users and databases follow the naming convention:
//   DB user:  cpaneluser_username   (max 16 chars total on MySQL 5.x)
//   DB name:  cpaneluser_dbname
//
// Discovery priority:
//   1. UAPI Mysql::list_databases / Mysql::list_users  (most accurate)
//   2. Parse /var/cpanel/databases/users.yaml          (fast, file-based fallback)
//   3. Prefix scan of /var/lib/mysql/ dirs             (last resort)

function get_db_users_for_user(string $user): array
{
    $user = normalize_cpanel_user($user);
    if ($user === '') return [];

    // Method 1: UAPI
    $via_uapi = _db_users_via_uapi($user);
    if (!empty($via_uapi)) return $via_uapi;

    // Method 2: yaml file
    $via_yaml = _db_users_via_yaml($user);
    if (!empty($via_yaml)) return $via_yaml;

    // Method 3: prefix fallback
    return _db_users_via_prefix($user);
}

function get_databases_for_user(string $user): array
{
    $user = normalize_cpanel_user($user);
    if ($user === '') return [];

    // Method 1: UAPI
    $via_uapi = _databases_via_uapi($user);
    if (!empty($via_uapi)) return $via_uapi;

    // Method 2: yaml file
    $via_yaml = _databases_via_yaml($user);
    if (!empty($via_yaml)) return $via_yaml;

    // Method 3: prefix fallback from /var/lib/mysql
    return _databases_via_prefix($user);
}

// Returns both in one call to avoid double UAPI round-trips.
function get_db_info_for_user(string $user): array
{
    $user = normalize_cpanel_user($user);
    if ($user === '') return ['users' => [], 'databases' => []];

    // Try UAPI once for both
    $uapi = _db_info_via_uapi($user);
    if (!empty($uapi['users']) || !empty($uapi['databases'])) return $uapi;

    // Yaml fallback
    $yaml_users = _db_users_via_yaml($user);
    $yaml_dbs   = _databases_via_yaml($user);
    if (!empty($yaml_users) || !empty($yaml_dbs)) {
        return ['users' => $yaml_users, 'databases' => $yaml_dbs];
    }

    // Prefix fallback
    return [
        'users'     => _db_users_via_prefix($user),
        'databases' => _databases_via_prefix($user),
    ];
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function _db_info_via_uapi(string $user): array
{
    $users = _db_users_via_uapi($user);
    $dbs   = _databases_via_uapi($user);
    return ['users' => $users, 'databases' => $dbs];
}

function _db_users_via_uapi(string $user): array
{
    $cmd = '/usr/local/cpanel/bin/uapi --user=' . escapeshellarg($user)
         . ' Mysql list_users --output=json 2>/dev/null';
    $raw = shell_exec($cmd);
    if (!is_string($raw) || trim($raw) === '') return [];

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) return [];

    $items = $decoded['result']['data'] ?? [];
    if (!is_array($items)) return [];

    $out = [];
    foreach ($items as $item) {
        // UAPI returns either a string or array with 'user' key depending on version
        $u = is_string($item) ? $item : (string)($item['user'] ?? '');
        $u = trim($u);
        if ($u !== '') $out[] = $u;
    }
    sort($out, SORT_NATURAL | SORT_FLAG_CASE);
    return $out;
}

function _databases_via_uapi(string $user): array
{
    $cmd = '/usr/local/cpanel/bin/uapi --user=' . escapeshellarg($user)
         . ' Mysql list_databases --output=json 2>/dev/null';
    $raw = shell_exec($cmd);
    if (!is_string($raw) || trim($raw) === '') return [];

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) return [];

    $items = $decoded['result']['data'] ?? [];
    if (!is_array($items)) return [];

    $out = [];
    foreach ($items as $item) {
        $db = is_string($item) ? $item : (string)($item['database'] ?? '');
        $db = trim($db);
        if ($db !== '') $out[] = $db;
    }
    sort($out, SORT_NATURAL | SORT_FLAG_CASE);
    return $out;
}

function _db_users_via_yaml(string $user): array
{
    // /var/cpanel/databases/users.yaml maps cpanel user → list of mysql users
    $file = '/var/cpanel/databases/users.yaml';
    return _parse_cpanel_db_yaml($file, $user, 'users');
}

function _databases_via_yaml(string $user): array
{
    // /var/cpanel/databases/dbindex.yaml maps cpanel user → list of db names
    $file = '/var/cpanel/databases/dbindex.yaml';
    return _parse_cpanel_db_yaml($file, $user, 'databases');
}

function _parse_cpanel_db_yaml(string $file, string $cpanelUser, string $kind): array
{
    if (!is_readable($file)) return [];

    $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) return [];

    // Minimal YAML parser — cPanel's yaml files use a simple structure:
    //   username:
    //     - item1
    //     - item2
    // We don't load a full YAML library to avoid dependencies.

    $out         = [];
    $inUser      = false;
    $userIndent  = 0;

    foreach ($lines as $line) {
        if (trim($line) === '' || trim($line)[0] === '#') continue;

        $trimmed = ltrim($line);
        $indent  = strlen($line) - strlen($trimmed);

        // Top-level key: "username:"
        if ($indent === 0) {
            $key = rtrim($trimmed, ':');
            $inUser = (normalize_cpanel_user($key) === $cpanelUser);
            $userIndent = 0;
            continue;
        }

        if (!$inUser) continue;

        // List item under this user: "  - value"
        if (strpos($trimmed, '- ') === 0) {
            $val = trim(substr($trimmed, 2));
            // Strip YAML quotes if present
            $val = trim($val, '"\'');
            if ($val !== '') $out[] = $val;
        }
    }

    sort($out, SORT_NATURAL | SORT_FLAG_CASE);
    return $out;
}

function _db_users_via_prefix(string $user): array
{
    // MySQL users created by cPanel are prefixed with the cpanel username + '_'
    // We can't enumerate them without a DB connection, so return empty here.
    // The governor will need direct MySQL access for this fallback anyway.
    return [];
}

function _databases_via_prefix(string $user): array
{
    $prefix = $user . '_';
    $base   = '/var/lib/mysql';
    $out    = [];

    if (!is_dir($base)) return [];

    foreach (glob($base . '/' . $prefix . '*') ?: [] as $path) {
        if (!is_dir($path)) continue;
        $db = basename($path);
        // Skip system dirs that happen to match
        if (in_array($db, ['information_schema', 'mysql', 'performance_schema', 'sys'], true)) continue;
        $out[] = $db;
    }

    sort($out, SORT_NATURAL | SORT_FLAG_CASE);
    return $out;
}



function get_all_cpanel_users(): array
{
    $users = [];

    foreach (glob('/var/cpanel/users/*') ?: [] as $file) {
        if (!is_file($file)) {
            continue;
        }

        $user = normalize_cpanel_user(basename($file));
        if ($user === '') {
            continue;
        }

        $users[$user] = true;
    }

    $out = array_keys($users);
    sort($out, SORT_NATURAL | SORT_FLAG_CASE);

    return $out;
}

function parse_userdatadomains(): array
{
    $map = [];
    $file = '/etc/userdatadomains';

    if (!is_readable($file)) {
        return [];
    }

    $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        return [];
    }

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || strpos($line, ':') === false) {
            continue;
        }

        [$domain, $rest] = explode(':', $line, 2);
        $domain = normalize_host($domain);

        if ($domain === '' || should_skip_domain_name($domain) || !domain_looks_valid($domain)) {
            continue;
        }

        $parts = array_map('trim', explode('==', trim($rest)));
        if (empty($parts[0])) {
            continue;
        }

        $user = normalize_cpanel_user($parts[0]);
        if ($user === '') {
            continue;
        }

        $map[$user][] = $domain;
    }

    foreach ($map as $user => $domains) {
        $map[$user] = finalize_domains($domains);
    }

    return $map;
}

function parse_userdomains(): array
{
    $map = [];
    $file = '/etc/userdomains';

    if (!is_readable($file)) {
        return [];
    }

    $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        return [];
    }

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || strpos($line, ':') === false) {
            continue;
        }

        [$domain, $user] = explode(':', $line, 2);

        $domain = normalize_host($domain);
        $user   = normalize_cpanel_user($user);

        if ($user === '' || $domain === '') {
            continue;
        }

        if (should_skip_domain_name($domain) || !domain_looks_valid($domain)) {
            continue;
        }

        $map[$user][] = $domain;
    }

    foreach ($map as $user => $domains) {
        $map[$user] = finalize_domains($domains);
    }

    return $map;
}

function get_domains_from_userdata_dir(string $user): array
{
    $domains = [];
    $userdataDir = '/var/cpanel/userdata/' . $user;

    if (!is_dir($userdataDir)) {
        return [];
    }

    foreach (glob($userdataDir . '/*') ?: [] as $file) {
        if (!is_file($file)) {
            continue;
        }

        $base = basename($file);
        if ($base === '' || $base[0] === '.') {
            continue;
        }

        if ($base === 'main' || $base === 'cache' || $base === 'userdata.cache') {
            continue;
        }

        $domain = normalize_host($base);

        if (should_skip_domain_name($domain) || !domain_looks_valid($domain)) {
            continue;
        }

        $domains[] = $domain;
    }

    return finalize_domains($domains);
}

function get_domains_from_uapi(string $user): array
{
    $domains = [];

    $cmd = '/usr/local/cpanel/bin/uapi --user=' . escapeshellarg($user) . ' DomainInfo list_domains --output=json 2>/dev/null';
    $raw = shell_exec($cmd);

    if (!is_string($raw) || trim($raw) === '') {
        return [];
    }

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        return [];
    }

    $data = $decoded['result']['data'] ?? null;
    if (!is_array($data)) {
        return [];
    }

    foreach (['main_domain', 'addon_domains', 'parked_domains', 'sub_domains'] as $key) {
        if (!array_key_exists($key, $data)) {
            continue;
        }

        if (is_string($data[$key]) && $data[$key] !== '') {
            $domains[] = $data[$key];
            continue;
        }

        if (is_array($data[$key])) {
            foreach ($data[$key] as $d) {
                if (is_string($d) && $d !== '') {
                    $domains[] = $d;
                }
            }
        }
    }

    return finalize_domains($domains);
}

function get_domain_map(): array
{
    $map = parse_userdatadomains();
    if (!empty($map)) {
        return $map;
    }

    $map = parse_userdomains();
    if (!empty($map)) {
        return $map;
    }

    $map = [];
    foreach (get_all_cpanel_users() as $user) {
        $domains = get_domains_from_userdata_dir($user);
        if (!empty($domains)) {
            $map[$user] = $domains;
        }
    }

    return $map;
}

function get_domains_for_user(string $user): array
{
    $user = normalize_cpanel_user($user);
    if ($user === '') {
        return [];
    }

    $map = get_domain_map();
    if (isset($map[$user]) && !empty($map[$user])) {
        return $map[$user];
    }

    return get_domains_from_uapi($user);
}

function get_all_user_domains(): array
{
    $rows = [];
    $map = get_domain_map();

    foreach ($map as $user => $domains) {
        foreach ($domains as $domain) {
            $rows[] = [
                'user'   => $user,
                'domain' => $domain,
            ];
        }
    }

    usort($rows, static function ($a, $b) {
        return [$a['user'], $a['domain']] <=> [$b['user'], $b['domain']];
    });

    return $rows;
}

function get_current_cpanel_user(): string
{
    foreach ([
        'REMOTE_USER',
        'CPANEL_USER',
        'REMOTE_LOGNAME',
        'USER',
    ] as $key) {
        $v = $_SERVER[$key] ?? getenv($key);
        if (is_string($v) && trim($v) !== '') {
            return normalize_cpanel_user($v);
        }
    }

    $cmd = '/usr/local/cpanel/bin/uapi --output=json Variables get_user_information 2>/dev/null';
    $raw = shell_exec($cmd);
    if (is_string($raw) && trim($raw) !== '') {
        $decoded = json_decode($raw, true);
        $data = $decoded['result']['data'] ?? null;
        if (is_array($data)) {
            foreach (['user', 'cpuser', 'current_user'] as $key) {
                if (!empty($data[$key]) && is_string($data[$key])) {
                    return normalize_cpanel_user($data[$key]);
                }
            }
        }
    }

    return '';
}

function build_exact_host_set(array $listResponse): array
{
    $rows = $listResponse['rows'] ?? $listResponse;
    $set = [];

    if (!is_array($rows)) {
        return $set;
    }

    foreach ($rows as $row) {
        if (!is_array($row)) {
            continue;
        }

        if (($row['type'] ?? '') !== 'host') {
            continue;
        }

        $value = normalize_host((string)($row['value'] ?? ''));
        if ($value !== '') {
            $set[$value] = true;
        }
    }

    return $set;
}
