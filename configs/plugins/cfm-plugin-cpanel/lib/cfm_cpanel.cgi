#!/usr/local/cpanel/3rdparty/bin/php
<?php

parse_str((string)getenv('QUERY_STRING'), $_GET);
foreach ([
    'REQUEST_METHOD',
    'REQUEST_URI',
    'QUERY_STRING',
    'REMOTE_USER',
    'CPANEL_USER',
    'CP_SECURITY_TOKEN',
    'cp_security_token',
    'HTTP_COOKIE',
] as $k) {
    $_SERVER[$k] = (string)getenv($k);
}
foreach (explode(';', (string)getenv('HTTP_COOKIE')) as $pair) {
    $pair = trim($pair);
    if (($eq = strpos($pair, '=')) !== false) {
        $_COOKIE[urldecode(substr($pair, 0, $eq))] = urldecode(substr($pair, $eq + 1));
    }
}

require_once '/usr/local/cpanel/base/cfm/lib/bootstrap.php';
cfm_bootstrap('cpanel');
