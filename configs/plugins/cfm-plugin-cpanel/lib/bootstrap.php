<?php

require_once __DIR__ . '/cfm_api.php';
require_once __DIR__ . '/domain_provider.php';
require_once __DIR__ . '/actions.php';

function cgi_send_headers(string $contentType = 'text/html; charset=utf-8', array $extraHeaders = []): void
{
    echo "Content-Type: {$contentType}\r\n";
    foreach ($extraHeaders as $line) {
        echo $line . "\r\n";
    }
    echo "\r\n";
}

function cfm_bootstrap(string $mode): void
{
    if (!in_array($mode, ['whm', 'cpanel'], true)) {
        cgi_send_headers('text/html; charset=utf-8');
        echo 'Invalid mode';
        exit;
    }

    $extraHeaders = [];

    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_name('CFMEXCLUDES');

        $sid = $_COOKIE['CFMEXCLUDES'] ?? '';
        if ($sid !== '' && preg_match('/^[a-zA-Z0-9,-]{1,128}$/', $sid)) {
            session_id($sid);
        }

        session_start();

        if ($sid === '' || $sid !== session_id()) {
            $cookieParams = session_get_cookie_params();
            $extraHeaders[] = sprintf(
                'Set-Cookie: CFMEXCLUDES=%s; Path=%s; HttpOnly; SameSite=Lax',
                session_id(),
                $cookieParams['path'] ?: '/'
            );
        }
    }

    handle_asset_request($mode, $extraHeaders);
    handle_ajax_action($mode, $extraHeaders);

    try {
        if ($mode === 'whm') {
            $rows = get_all_user_domains();
            $currentUser = '';
            $pageTitle = 'CFM - WHM';
        } else {
            $currentUser = get_current_cpanel_user();
            $rows = [];

            if ($currentUser !== '') {
                $domains = get_domains_for_user($currentUser);
                if (empty($domains)) {
                    foreach (get_all_user_domains() as $row) {
                        if (normalize_cpanel_user((string)($row['user'] ?? '')) === $currentUser) {
                            $d = normalize_host((string)($row['domain'] ?? ''));
                            if ($d !== '') {
                                $domains[] = $d;
                            }
                        }
                    }
                    $domains = finalize_domains($domains);
                }

                foreach ($domains as $domain) {
                    $domain = normalize_host((string)$domain);
                    if ($domain !== '') {
                        $rows[] = ['user' => $currentUser, 'domain' => $domain];
                    }
                }
            }

            $pageTitle = 'CFM Dashboard';
        }

        $challengeSet = build_exact_host_set(cfm_list_excludes('challenge'));
        $wafSet       = build_exact_host_set(cfm_list_excludes('waf'));
$csrfToken    = session_token($mode);
        $modeName     = $mode;

        cgi_send_headers('text/html; charset=utf-8', $extraHeaders);
    } catch (Throwable $e) {
        cgi_send_headers('text/html; charset=utf-8', $extraHeaders);
        echo '<h2>CFM Excludes</h2>';
        echo '<pre>' . h($e->getMessage()) . '</pre>';
        exit;
    }

    include __DIR__ . '/../templates/index.php';
    exit;
}
