<?php
declare(strict_types=1);
header('Content-Type: text/plain; charset=utf-8');
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo "POST a plain-text recipe\n";
    exit;
}
$body = file_get_contents('php://input');
if (!is_string($body) || strlen($body) > 1024 || strpos($body, "\0") !== false) {
    http_response_code(400);
    exit;
}
if (file_put_contents('/tmp/x', $body, LOCK_EX) === false) {
    http_response_code(500);
    exit;
}
echo "saved\n";
