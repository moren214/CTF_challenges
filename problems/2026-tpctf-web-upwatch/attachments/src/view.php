<?php
// UpWatch — serve a stored file back.
// The id is taken from the query string and joined straight onto the storage
// path: the board trusts whatever the asker hands it.
$f = isset($_GET['f']) ? (string)$_GET['f'] : '';
if ($f === '' || $f[0] === '/') {
    http_response_code(400);
    exit('missing id');
}
$path = __DIR__ . '/files/' . $f;
if (!is_file($path)) {
    http_response_code(404);
    exit('no such entry');
}
header('Content-Type: application/octet-stream');
header('Content-Length: ' . filesize($path));
readfile($path);
