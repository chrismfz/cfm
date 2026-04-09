#!/usr/local/cpanel/3rdparty/bin/php
<?php

parse_str((string)getenv('QUERY_STRING'), $_GET);
$_SERVER['REQUEST_METHOD'] = (string)getenv('REQUEST_METHOD');
foreach (explode(';', (string)getenv('HTTP_COOKIE')) as $pair) {
    $pair = trim($pair);
    if (($eq = strpos($pair, '=')) !== false) {
        $_COOKIE[urldecode(substr($pair, 0, $eq))] = urldecode(substr($pair, $eq + 1));
    }
}

require_once '/usr/local/cpanel/base/cfm/lib/bootstrap.php';
cfm_bootstrap('cpanel');
