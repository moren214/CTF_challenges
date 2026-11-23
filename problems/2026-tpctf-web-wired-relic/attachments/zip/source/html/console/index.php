<?php
// Relay console: a two-stage courier handshake.
//   open    -> a pending slot with a server-generated slot nonce
//   refresh -> echo the slot challenge for a given ticket
//   arm     -> the courier returns the challenge; the slot becomes armed
// An armed slot may read/write the short-lived handoff scratch area.
require '/var/www/relic-lib/lib.php';

$action = $_POST['action'] ?? $_GET['action'] ?? '';

if ($action === 'open' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $nonce  = bin2hex(random_bytes(12));
    $ticket = bin2hex(random_bytes(8));
    relic_send_state(['s' => 'open', 'n' => $nonce, 'e' => time() + 600]);
    relic_json([
        'status' => 'pending',
        'ticket' => $ticket,
        'instruction' => 'refresh the slot challenge, then confirm it to arm the slot',
    ]);
}

if ($action === 'refresh') {
    $state = relic_open_state();
    if ($state === null || $state['s'] !== 'open') {
        relic_json(['status' => 'denied', 'reason' => 'no pending slot'], 403);
    }
    $ticket = (string) ($_POST['ticket'] ?? $_GET['ticket'] ?? '');
    if (!preg_match('/^[a-f0-9]{16}$/', $ticket)) {
        relic_json(['status' => 'denied', 'reason' => 'bad slot'], 403);
    }
    relic_json([
        'status' => 'pending',
        'challenge' => hash('sha256', $state['n'] . ':' . $ticket),
    ]);
}

if ($action === 'arm' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $state = relic_open_state();
    if ($state === null || $state['s'] !== 'open') {
        relic_json(['status' => 'denied', 'reason' => 'no pending slot'], 403);
    }
    $ticket = (string) ($_POST['ticket'] ?? '');
    $proof  = (string) ($_POST['proof'] ?? '');
    if (!preg_match('/^[a-f0-9]{16}$/', $ticket)) {
        relic_json(['status' => 'denied', 'reason' => 'bad slot'], 403);
    }
    $challenge = hash('sha256', $state['n'] . ':' . $ticket);
    if (!hash_equals($challenge, $proof)) {
        relic_json(['status' => 'denied', 'reason' => 'slot proof mismatch'], 403);
    }
    relic_send_state(['s' => 'armed', 'n' => $state['n'], 'e' => time() + 1800]);
    relic_json(['status' => 'armed', 'note' => 'handoff scratch area released']);
}

header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html><head><title>Relay console</title></head>
<body>
<h1>Courier relay console</h1>
<p>The relay keeps a short-lived handoff scratch area for field couriers.
A courier first opens a slot, then confirms the slot challenge carried by
the pending slot. Confirmed slots may leave or recover handoff notes.</p>
<ol>
  <li><code>POST /console/index.php</code> <code>action=open</code> &rarr; a
      <em>ticket</em> and a pending slot cookie.</li>
  <li><code>action=refresh</code> with the <code>ticket</code> &rarr; the
      slot challenge.</li>
  <li><code>action=arm</code> with the <code>ticket</code> and the
      <code>challenge</code> as <code>proof</code>.</li>
</ol>
<p>Handoff notes are managed at <a href="/deposit/index.php">/deposit/</a>.</p>
</body></html>
