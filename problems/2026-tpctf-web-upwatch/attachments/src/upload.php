<?php
// UpWatch — receive one upload, store it under a random id, remember metadata.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('method not allowed');
}
$caption = isset($_POST['caption']) ? (string)$_POST['caption'] : '';
$caption = mb_substr($caption, 0, 64);
$id = bin2hex(random_bytes(16));
$dir = __DIR__ . '/files';

$f = isset($_FILES['upload']) ? $_FILES['upload'] : null;
if (!$f || $f['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    exit('no usable upload: ' . htmlspecialchars((string)($f['error'] ?? 'missing')));
}
if (!is_uploaded_file($f['tmp_name'])) {
    http_response_code(400);
    exit('not an uploaded file');
}
$size = filesize($f['tmp_name']);
$stored = "$dir/$id";
if (!move_uploaded_file($f['tmp_name'], $stored)) {
    http_response_code(500);
    exit('storage failed');
}
$meta = [
    'id' => $id,
    'caption' => $caption !== '' ? $caption : '(no caption)',
    'size' => $size,
    'time' => date('Y-m-d H:i:s'),
];
file_put_contents("$dir/$id.json", json_encode($meta, JSON_UNESCAPED_UNICODE));
?>
<!doctype html>
<html lang="zh"><head><meta charset="utf-8"><title>已接收 · UpWatch</title></head>
<body style="font-family:system-ui,sans-serif;max-width:640px;margin:40px auto">
<h2>已接收</h2>
<p>看板把你的文件保管为 <code><?= htmlspecialchars($id) ?></code>。</p>
<p><a href="view.php?f=<?= htmlspecialchars($id) ?>">查看这个文件</a> · <a href="index.php">回到看板</a></p>
</body></html>
