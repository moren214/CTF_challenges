<?php
declare(strict_types=1);

$shots = [
    ['id' => 1, 'title' => '晨雾中的渡口', 'author' => 'lin',   'likes' => 128, 'tag' => 'landscape'],
    ['id' => 2, 'title' => '雨后的天台',   'author' => 'yuki',  'likes' => 96,  'tag' => 'urban'],
    ['id' => 3, 'title' => '夜市灯牌',     'author' => 'zhou',  'likes' => 214, 'tag' => 'urban'],
    ['id' => 4, 'title' => '海堤上的风',   'author' => 'lin',   'likes' => 77,  'tag' => 'landscape'],
];

$tag = isset($_GET['tag']) ? (string) $_GET['tag'] : '';
$visible = $tag === ''
    ? $shots
    : array_values(array_filter($shots, static fn(array $s): bool => $s['tag'] === $tag));

$version = PHP_VERSION;
?>
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PixelBoard · 团队图片看板</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; font: 15px/1.6 -apple-system, "Segoe UI", "PingFang SC", sans-serif; background: #0e1116; color: #e6edf3; }
  header { padding: 28px 32px; border-bottom: 1px solid #1f2630; display: flex; align-items: baseline; gap: 12px; }
  header h1 { margin: 0; font-size: 20px; letter-spacing: .5px; }
  header span { color: #7d8794; font-size: 13px; }
  main { padding: 24px 32px 64px; display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 16px; }
  article { background: #151b23; border: 1px solid #222b36; border-radius: 10px; padding: 16px 18px; }
  article h2 { margin: 0 0 6px; font-size: 15px; font-weight: 600; }
  article p { margin: 0; color: #97a1ad; font-size: 13px; }
  footer { padding: 18px 32px 40px; color: #5d6673; font-size: 12px; }
  code { color: #c8d1db; }
</style>
</head>
<body>
<header>
  <h1>PixelBoard</h1>
  <span>团队作品集 · <?= count($visible) ?> 张</span>
</header>
<main>
<?php foreach ($visible as $s): ?>
  <article>
    <h2><?= htmlspecialchars($s['title'], ENT_QUOTES, 'UTF-8') ?></h2>
    <p><?= htmlspecialchars($s['author'], ENT_QUOTES, 'UTF-8') ?> · <?= (int) $s['likes'] ?> 赞 · #<?= htmlspecialchars($s['tag'], ENT_QUOTES, 'UTF-8') ?></p>
  </article>
<?php endforeach; ?>
</main>
<footer>
  服务版本 <code>PHP <?= htmlspecialchars($version, ENT_QUOTES, 'UTF-8') ?></code> ·
  镜像 <code>pixelboard/base</code>
</footer>
</body>
</html>
