<?php
// PaperTrail — desk status. The desk reports the runtime settings it runs
// under; the same values are in attachments/etc/app.ini.
header('Content-Type: text/plain; charset=utf-8');
$keys = [
    'php.version' => PHP_VERSION,
    'apache' => apache_get_version(),
    'mpm' => 'prefork (single worker)',
    'session.name' => ini_get('session.name'),
    'session.use_strict_mode' => ini_get('session.use_strict_mode'),
    'session.use_cookies' => ini_get('session.use_cookies'),
    'session.upload_progress.enabled' => ini_get('session.upload_progress.enabled'),
    'session.upload_progress.cleanup' => ini_get('session.upload_progress.cleanup'),
    'memory_limit' => ini_get('memory_limit'),
    'post_max_size' => ini_get('post_max_size'),
    'upload_max_filesize' => ini_get('upload_max_filesize'),
    'display_errors' => ini_get('display_errors'),
    'disable_functions' => ini_get('disable_functions'),
];
echo "# PaperTrail desk status\n";
foreach ($keys as $k => $v) {
    echo str_pad($k, 34) . "= " . ($v === false ? '(off)' : $v) . "\n";
}
echo str_pad('seal', 34) . "= /flag (readable by the web account)\n";
