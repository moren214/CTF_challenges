<?php
declare(strict_types=1);
header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html><html lang="en"><meta charset="utf-8"><title>Worker Ledger</title>
<style>body{font:17px system-ui;margin:6rem auto;max-width:42rem;color:#243142}code{background:#eef2f6;padding:.15rem .4rem}</style>
<h1>Worker Ledger</h1>
<p>Two ledger workers serve this endpoint. Their IDs can be checked at <a href="/worker.php">/worker.php</a>.</p>
<p>Worker status: <a href="/healthz.php">healthy</a>. Export files are served from <code>/e/</code>.</p>
</html>
