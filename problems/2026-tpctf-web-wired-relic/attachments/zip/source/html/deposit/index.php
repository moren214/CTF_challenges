<?php
// Handoff scratch area. An armed relay slot may leave and recover a small
// number of short-lived handoff notes. Notes are plain text, named with a
// short lowercase identifier, and never leave /tmp.
require '/var/www/relic-lib/lib.php';

$state = relic_open_state();
$armed = $state !== null && $state['s'] === 'armed';
$namePattern = '/^[a-z][a-z0-9]{0,7}$/';

header('Content-Type: text/plain; charset=utf-8');

if (isset($_GET['read'])) {
    if (!$armed) {
        http_response_code(403);
        echo "denied\n";
        exit;
    }
    $name = (string) $_GET['read'];
    if (!preg_match($namePattern, $name)) {
        http_response_code(400);
        echo "bad note name\n";
        exit;
    }
    $path = '/tmp/' . $name;
    if (!is_file($path)) {
        http_response_code(404);
        echo "no such note\n";
        exit;
    }
    readfile($path);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'leave') {
    if (!$armed) {
        http_response_code(403);
        echo "denied\n";
        exit;
    }
    $name    = (string) ($_POST['name'] ?? '');
    $content = (string) ($_POST['content'] ?? '');
    if (!preg_match($namePattern, $name)) {
        http_response_code(400);
        echo "bad note name\n";
        exit;
    }
    if (strlen($content) > 2000 || strpos($content, "\0") !== false) {
        http_response_code(413);
        echo "note too large\n";
        exit;
    }
    if (file_put_contents('/tmp/' . $name, $content) === false) {
        http_response_code(500);
        echo "scratch write failed\n";
        exit;
    }
    http_response_code(200);
    echo "left\n";
    exit;
}

http_response_code(200);
if (!$armed) {
    echo "relay scratch area: no armed slot\n";
    exit;
}
echo "relay scratch area: armed\n";
