<?php
declare(strict_types=1);
header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html><html lang="en"><meta charset="utf-8"><title>Stream Gate</title>
<style>body{font:17px system-ui;margin:6rem auto;max-width:42rem;color:#243142}code{background:#eef2f6;padding:.15rem .4rem}</style>
<h1>Stream Gate</h1>
<p>The service accepts streaming submissions. Buffered POST bodies are rejected by the ingress.</p>
<p>Worker status: <a href="/healthz.php">healthy</a>. Export files are served from <code>/e/</code>.</p>
</html>
