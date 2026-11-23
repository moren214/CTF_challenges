<?php
// UpWatch — a tiny upload board. Lists what the board currently holds.
$files = [];
$dir = __DIR__ . '/files';
if (is_dir($dir)) {
    foreach (scandir($dir) as $ent) {
        if (preg_match('/^[0-9a-f]{32}$/', $ent)) {
            $meta = json_decode(@file_get_contents("$dir/$ent.json"), true);
            if (is_array($meta)) {
                $files[] = $meta;
            }
        }
    }
    $files = array_reverse($files);
}
?>
<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>UpWatch · 上传看板</title>
<style>
body{font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;color:#222}
form{border:1px solid #ddd;border-radius:8px;padding:16px}
input,textarea{width:100%;box-sizing:border-box;margin:4px 0 12px}
table{border-collapse:collapse;width:100%;margin-top:24px}
td,th{border-bottom:1px solid #eee;padding:6px;text-align:left;font-size:14px}
code{background:#f4f4f4;padding:1px 4px;border-radius:3px}
</style>
</head>
<body>
<h2>UpWatch</h2>
<p>把文件交给看板保管：填一句话说明，选一个文件，看板接收、编号、留档。</p>
<form action="upload.php" method="post" enctype="multipart/form-data">
  <label>说明</label>
  <input type="text" name="caption" maxlength="64" placeholder="这个文件是什么">
  <label>文件</label>
  <input type="file" name="upload">
  <button type="submit">提交到看板</button>
</form>
<?php if ($files): ?>
<table>
  <tr><th>编号</th><th>说明</th><th>大小</th><th>时间</th><th></th></tr>
  <?php foreach ($files as $f): ?>
  <tr>
    <td><code><?= htmlspecialchars($f['id']) ?></code></td>
    <td><?= htmlspecialchars($f['caption']) ?></td>
    <td><?= (int)$f['size'] ?> B</td>
    <td><?= htmlspecialchars($f['time']) ?></td>
    <td><a href="view.php?f=<?= htmlspecialchars($f['id']) ?>">查看</a></td>
  </tr>
  <?php endforeach; ?>
</table>
<?php else: ?>
<p style="color:#888">看板还是空的。</p>
<?php endif; ?>
</body>
</html>
