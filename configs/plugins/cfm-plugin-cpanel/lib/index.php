<?php
http_response_code(410);
header('Content-Type: text/plain; charset=utf-8');

echo "Deprecated: this legacy UI file is not used by the cPanel plugin runtime.\n";
echo "Canonical UI file: templates/index.php (installed to /usr/local/cpanel/base/cfm/templates/index.php).\n";
echo "Authoritative metadata source: /api/v1/cpanel/user-info\n";
