<?php
// DropVault — multipart drop endpoint.
//
// Accepts one artefact per request under the "drop" file control, validates
// it against the artefact policy and stores it under the vault directory.

const VAULT_DIR = '/tmp/dropvault';
const MAX_ARTEFACT_BYTES = 2097152;      // 2 MiB per artefact
const ALLOWED_EXTENSIONS = ['txt', 'md', 'log', 'csv'];

function extension_of(string $name): string
{
    $dot = strrpos($name, '.');
    return $dot === false ? '' : strtolower(substr($name, $dot + 1));
}

function page_top(string $title): string
{
    return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        . '<title>' . htmlspecialchars($title, ENT_QUOTES) . '</title></head>'
        . '<body style="font-family:system-ui,sans-serif;margin:3rem auto;max-width:42rem">'
        . '<h1>' . htmlspecialchars($title, ENT_QUOTES) . '</h1>'
        . '<p><a href="/">front page</a> &middot; <a href="/status.php">status board</a></p>';
}

$receipt = null;
$notice = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_FILES['drop']) || !is_array($_FILES['drop'])) {
        $notice = 'No artefact received: attach exactly one file under the "drop" control.';
    } elseif ($_FILES['drop']['error'] !== UPLOAD_ERR_OK) {
        $notice = 'The upload did not complete cleanly (code ' . (int) $_FILES['drop']['error'] . ').';
    } elseif ($_FILES['drop']['size'] > MAX_ARTEFACT_BYTES) {
        $notice = 'Artefact exceeds the 2 MiB per-item policy.';
    } elseif (!in_array(extension_of($_FILES['drop']['name']), ALLOWED_EXTENSIONS, true)) {
        $notice = 'Artefact type not on the policy list (txt, md, log, csv).';
    } else {
        if (!is_dir(VAULT_DIR)) {
            @mkdir(VAULT_DIR, 0770, true);
        }
        $stored = VAULT_DIR . '/' . bin2hex(random_bytes(8)) . '.' . extension_of($_FILES['drop']['name']);
        if (move_uploaded_file($_FILES['drop']['tmp_name'], $stored)) {
            $receipt = [
                'name' => $_FILES['drop']['name'],
                'size' => $_FILES['drop']['size'],
                'stored' => $stored,
            ];
        } else {
            $notice = 'The vault rejected the artefact; contact the on-call engineer.';
        }
    }
}

echo page_top('Drop a file — DropVault');

if ($receipt !== null) {
    echo '<p>Artefact accepted.</p><table border="1" cellpadding="6">';
    foreach ($receipt as $k => $v) {
        echo '<tr><th>' . htmlspecialchars($k, ENT_QUOTES) . '</th><td>'
            . htmlspecialchars((string) $v, ENT_QUOTES) . '</td></tr>';
    }
    echo '</table>';
} else {
    if ($notice !== null) {
        echo '<p style="color:#a33">' . htmlspecialchars($notice, ENT_QUOTES) . '</p>';
    }
    echo '<form method="post" enctype="multipart/form-data" action="/upload.php">';
    echo '<p><label>Artefact <input type="file" name="drop"></label></p>';
    echo '<p><button type="submit">Drop it</button></p>';
    echo '</form>';
}
echo '</body></html>';
