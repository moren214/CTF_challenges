<?php
// MemTrace 观测台首页 —— 展示当前 worker 进程状态（不涉及会话）
header('Content-Type: text/html; charset=utf-8');
$pid = getmypid();
$php = PHP_VERSION;
$sapi = PHP_SAPI;
$int_size = PHP_INT_SIZE;
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>MemTrace · 请求生命周期观测台</title>
<style>
 body{font-family:ui-monospace,Consolas,monospace;background:#101418;color:#cfd8dc;margin:0;padding:2rem}
 h1{color:#80cbc4;border-bottom:1px solid #37474f;padding-bottom:.4rem}
 table{border-collapse:collapse;margin:1rem 0}
 td,th{border:1px solid #37474f;padding:.35rem .8rem;text-align:left}
 th{background:#1c2329;color:#80cbc4}
 .ok{color:#9ccc9c}.warn{color:#ffcc80}
 a{color:#4dd0e1}
 footer{margin-top:2rem;color:#607d8b;font-size:.85rem}
</style>
</head>
<body>
<h1>MemTrace · 请求生命周期观测台</h1>
<p>MemTrace 挂载在生产网边缘，供蓝队巡检 PHP 请求生命周期的运行状态。
本轮巡检基线：<span class="ok">请求过滤器已上线</span>，
<span class="ok">运行参数已收紧</span>。台面宣称已能挡住目前公开的攻击载荷。</p>

<table>
<tr><th>项目</th><th>当前值</th></tr>
<tr><td>worker PID</td><td><?= htmlspecialchars((string)$pid, ENT_QUOTES) ?></td></tr>
<tr><td>PHP 版本</td><td><?= htmlspecialchars($php, ENT_QUOTES) ?>（<?= htmlspecialchars($sapi, ENT_QUOTES) ?>）</td></tr>
<tr><td>指针宽度</td><td><?= (int)$int_size * 8 ?> bit</td></tr>
<tr><td>观测台状态</td><td class="ok">运行中</td></tr>
</table>

<p>更多运行参数见 <a href="/info.php">/info.php</a>（巡检面板，公开只读）。</p>

<footer>MemTrace <?= htmlspecialchars($php, ENT_QUOTES) ?> · 蓝队加固版 2026-11 · 冗余观测持续记录中</footer>
</body>
</html>
