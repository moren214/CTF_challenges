<?php
// DropVault — internal file drop service, front page.
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DropVault</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 3rem auto; max-width: 42rem; color: #1c2333; }
  h1 { margin-bottom: 0.25rem; }
  p.tagline { color: #5a6478; margin-top: 0; }
  nav a { margin-right: 1.25rem; }
  table { border-collapse: collapse; margin-top: 1.5rem; }
  td, th { border: 1px solid #c9cfdd; padding: 0.35rem 0.75rem; text-align: left; }
  code { background: #eef1f7; padding: 0.1rem 0.3rem; }
</style>
</head>
<body>
<h1>DropVault</h1>
<p class="tagline">Internal file drop for the operations team.</p>
<nav>
  <a href="/upload.php">Drop a file</a>
  <a href="/status.php">Ops status board</a>
</nav>
<p>
  DropVault accepts small text artefacts (logs, notes, CSV exports) and keeps
  them on the box for the on-call engineer. Uploads go through the standard
  multipart form at <code>/upload.php</code>; the runtime settings that
  govern request handling are shown on the <a href="/status.php">status
  board</a>.
</p>
<table>
  <tr><th>Endpoint</th><th>Purpose</th></tr>
  <tr><td><code>/upload.php</code></td><td>multipart drop endpoint (POST) and upload form (GET)</td></tr>
  <tr><td><code>/status.php</code></td><td>ops status board: runtime settings of the worker</td></tr>
  <tr><td><code>/healthz.php</code></td><td>liveness probe used by the platform</td></tr>
</table>
</body>
</html>
