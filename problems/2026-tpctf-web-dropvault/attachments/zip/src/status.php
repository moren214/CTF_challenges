<?php
// DropVault — ops status board.
//
// Shows the runtime settings of the worker that serves this request, so the
// on-call engineer can confirm the request-handling budget at a glance.

$board = [
    'PHP version'         => PHP_VERSION,
    'SAPI'                => PHP_SAPI,
    'memory_limit'        => ini_get('memory_limit'),
    'post_max_size'       => ini_get('post_max_size'),
    'upload_max_filesize' => ini_get('upload_max_filesize'),
    'max_file_uploads'    => ini_get('max_file_uploads'),
    'display_errors'      => ini_get('display_errors'),
    'error_reporting'     => ini_get('error_reporting'),
    'session.save_path'   => ini_get('session.save_path'),
    'session.upload_progress.enabled' => ini_get('session.upload_progress.enabled'),
    'session.upload_progress.cleanup' => ini_get('session.upload_progress.cleanup'),
    'session.use_strict_mode'         => ini_get('session.use_strict_mode'),
    'session.use_cookies'             => ini_get('session.use_cookies'),
    'fatal_error_backtraces'          => ini_get('fatal_error_backtraces'),
];

header('Content-Type: text/html; charset=utf-8');
echo '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    . '<title>Ops status board — DropVault</title></head>'
    . '<body style="font-family:system-ui,sans-serif;margin:3rem auto;max-width:42rem">'
    . '<h1>Ops status board</h1>'
    . '<p><a href="/">front page</a> &middot; <a href="/upload.php">drop a file</a></p>'
    . '<table border="1" cellpadding="6">';
foreach ($board as $k => $v) {
    echo '<tr><th>' . htmlspecialchars($k, ENT_QUOTES) . '</th><td><code>'
        . htmlspecialchars($v === false ? '(unset)' : (string) $v, ENT_QUOTES)
        . '</code></td></tr>';
}
echo '</table>';
echo '<p style="color:#5a6478">Settings shown are the live values of the worker that rendered this page.</p>';
echo '</body></html>';
