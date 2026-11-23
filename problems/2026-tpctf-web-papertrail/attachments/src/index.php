<?php
// PaperTrail — internal submission desk.
// The complete source of the desk and every Apache/PHP config file it runs
// under ships with the challenge as attachments/ — nothing is hidden.
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>PaperTrail — submission desk</title>
<style>body{font-family:Georgia,serif;max-width:46em;margin:3em auto;line-height:1.5;color:#222}a{color:#045}code{background:#f4f0e8;padding:0 .3em}</style>
</head>
<body>
<h1>PaperTrail</h1>
<p>PaperTrail is the internal submission desk of the review office.
Authors post a manuscript through the <a href="/submit.php">intake scanner</a>,
and the desk reports what it saw — nothing more. The desk keeps its
<em>seal</em> (the flag) in the file <code>/flag</code> on this host, where
only the web account may read it.</p>
<ul>
  <li><a href="/submit.php">Intake scanner</a> — post a manuscript; metadata only, files are never written to disk.</li>
  <li><a href="/status.php">Desk status</a> — runtime configuration the desk reports about itself.</li>
</ul>
<p style="color:#666;font-size:.9em">Desk software: PHP <?= htmlspecialchars(PHP_VERSION) ?>, Apache prefork, one worker.
Source &amp; configuration: see the challenge attachments (<code>app/</code>, <code>etc/</code>).</p>
</body>
</html>
