<?php
// MemTrace 巡检面板 —— 公开只读的运行参数视图（不涉及会话）
header('Content-Type: text/html; charset=utf-8');
$keys = [
    'memory_limit', 'post_max_size', 'upload_max_filesize',
    'expose_php', 'display_errors', 'display_startup_errors', 'error_reporting',
    'session.save_path', 'session.name', 'session.use_strict_mode',
    'session.use_cookies', 'session.upload_progress.enabled',
    'session.upload_progress.cleanup',
];
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>MemTrace · 巡检面板</title>
<style>
 body{font-family:ui-monospace,Consolas,monospace;background:#101418;color:#cfd8dc;margin:0;padding:2rem}
 h1{color:#80cbc4;border-bottom:1px solid #37474f;padding-bottom:.4rem}
 table{border-collapse:collapse;margin:1rem 0}
 td,th{border:1px solid #37474f;padding:.35rem .8rem;text-align:left}
 th{background:#1c2329;color:#80cbc4}
 a{color:#4dd0e1}
</style>
</head>
<body>
<h1>MemTrace · 巡检面板</h1>
<p>PHP <?= htmlspecialchars(PHP_VERSION, ENT_QUOTES) ?> · SAPI <?= htmlspecialchars(PHP_SAPI, ENT_QUOTES) ?>
· <?= PHP_INT_SIZE * 8 ?>bit · <?= htmlspecialchars(PHP_OS, ENT_QUOTES) ?></p>
<table>
<tr><th>参数</th><th>当前值</th></tr>
<?php foreach ($keys as $k): ?>
<tr><td><?= htmlspecialchars($k, ENT_QUOTES) ?></td><td><?= htmlspecialchars((string)ini_get($k), ENT_QUOTES) ?></td></tr>
<?php endforeach; ?>
</table>
<p><a href="/">返回观测台首页</a></p>
</body>
</html>
