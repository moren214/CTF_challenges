<?php
// Deck of Relics — the observatory.
// Tells you which attendant (prefork child) owns your client line.
// Deliberately minimal: no filesystem work, just the attendant number.
header('Content-Type: text/plain');
echo 'attendant=' . getmypid() . "\n";
echo 'rota=8 attendants (ServerLimit 8); a client line stays with one';
echo " attendant while it is kept open; a collapsed attendant is replaced\n";
