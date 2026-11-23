<?php
// ExtStore admin console. The only job this script has is to hand a theme bundle
// to the request pipeline and report health; it stores nothing and runs nothing.
$stage = $_GET['stage'] ?? 'home';
if ($stage === 'home') {
    echo "<!doctype html><meta charset=utf-8><title>ExtStore console</title>";
    echo "<h1>ExtStore admin console</h1>";
    echo "<p>Theme bundles are queued by the request pipeline, not by this script.</p>";
    echo "<p>POST multipart/form-data to <code>/console.php?stage=upload</code>.</p>";
    echo "<p>Client: <a href=\"/assets/console.js\">/assets/console.js</a></p>";
    exit;
}
if ($stage === 'upload') {
    echo "queued ".count($_FILES)." file(s)";
    exit;
}
http_response_code(404);
echo "unknown stage";
