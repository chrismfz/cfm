#!/usr/local/cpanel/3rdparty/bin/php
<?php

// PHP runs as CLI SAPI via shebang — $_GET/$_COOKIE/$_POST are not
// auto-populated from the CGI environment. Bootstrap them manually.
parse_str((string)getenv('QUERY_STRING'), $_GET);
$_SERVER['REQUEST_METHOD'] = (string)getenv('REQUEST_METHOD');
foreach (explode(';', (string)getenv('HTTP_COOKIE')) as $pair) {
    $pair = trim($pair);
    if (($eq = strpos($pair, '=')) !== false) {
        $_COOKIE[urldecode(substr($pair, 0, $eq))] = urldecode(substr($pair, $eq + 1));
    }
}

$remoteUser = (string)getenv('REMOTE_USER');
if ($remoteUser !== 'root') {
    echo "Content-Type: text/html; charset=utf-8\r\n\r\n";
    echo "<h2>403 Forbidden</h2><p>This tool is restricted to the root account.</p>";
    exit;
}

require_once '/usr/local/cpanel/base/cfm/lib/bootstrap.php';
cfm_bootstrap('whm');
