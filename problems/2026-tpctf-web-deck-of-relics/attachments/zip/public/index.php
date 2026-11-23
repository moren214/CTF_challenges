<?php
// Deck of Relics — front hall and gallery floor.
header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Deck of Relics</title>
<style>
body{font-family:Georgia,serif;max-width:46rem;margin:2rem auto;padding:0 1rem;color:#2b2b2b}
h1{border-bottom:2px solid #8b7355;padding-bottom:.4rem}
.mut{color:#7a6a52}
</style></head>
<body>
<h1>Deck of Relics</h1>
<p>A small catalog of museum curios kept by <em>the house of eight attendants</em>.
Each relic below is a piece of the intake bookkeeping; nothing here is for taking.</p>

<ul>
  <li><a href="/relic.php?id=1">Relic #1 — the intake ledger</a></li>
  <li><a href="/relic.php?id=2">Relic #2 — the attendants' rota</a></li>
  <li><a href="/relic.php?id=3">Relic #3 — the keepsake tokens</a></li>
</ul>

<p class="mut">House areas:</p>
<ul>
  <li><a href="/status.php">The observatory</a> — which attendant is on duty for you, and the rota as a whole.</li>
  <li><a href="/healthz.php">healthz</a></li>
</ul>

<p class="mut">Deliveries to the house are accepted as multipart forms. The gallery floor doubles
as the attendants' workbench: artifacts left there while handling a delivery stay next to the
exhibits until the next tour.</p>
</body>
</html>
