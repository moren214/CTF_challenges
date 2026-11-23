<?php
// Deck of Relics — catalog pages (flavor only; no secrets here).
$id = $_GET['id'] ?? '1';
$pages = [
  '1' => ["Relic #1 — the intake ledger",
    "Every delivery arrives as a multipart form. The conveyor (RFC 1867) opens a
     progress entry for it as soon as the first byte is on the belt, long before
     any exhibit script is consulted — the ledger is written by the house, not by
     the exhibition."],
  '2' => ["Relic #2 — the attendants' rota",
    "The house keeps exactly eight attendants (ServerLimit 8). An attendant owns
     every request on a client line for as long as the request is in flight; a
     new line is answered by whichever attendant reaches it first. An attendant
     that collapses mid-shift is replaced before the next bell — the replacement
     inherits the old desk, ledger and all."],
  '3' => ["Relic #3 — the keepsake tokens",
    "A visitor may present a session token of their own choosing when delivering a
     form; the house records it in the intake ledger. Tokens are handed back over
     the counter whenever the attendants settle one — look for the keepsake in
     the reply. The attendants are trained to show their diagnostics openly."],
];
if (!isset($pages[$id])) { http_response_code(404); echo "unknown relic\n"; return; }
[$title, $body] = $pages[$id];
header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title><?=htmlspecialchars($title)?></title></head>
<body style="font-family:Georgia,serif;max-width:40rem;margin:2rem auto">
<h1><?=htmlspecialchars($title)?></h1>
<p style="white-space:pre-line"><?=htmlspecialchars($body)?></p>
<p><a href="/index.php">back to the deck</a></p>
</body></html>
