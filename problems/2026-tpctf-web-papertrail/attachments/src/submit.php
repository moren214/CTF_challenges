<?php
// PaperTrail — intake scanner.
//
// Metadata only: the scanner never writes an uploaded byte to disk. It
// counts and describes what arrived, and that is the whole feature. There
// is deliberately no code path here that stores, includes, evaluates or
// executes anything.
header('Content-Type: text/plain; charset=utf-8');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    echo "# PaperTrail intake scanner\n";
    echo "POST multipart/form-data to this endpoint to have a manuscript's\n";
    echo "metadata described. Files are inspected, never stored.\n";
    exit;
}

$ctype = $_SERVER['CONTENT_TYPE'] ?? '';
if (stripos($ctype, 'multipart/form-data') === false) {
    echo "intake: multipart/form-data only\n";
    exit;
}

$fields = $_POST;
$files = $_FILES;

echo "# intake report\n";
echo "fields: " . count($fields) . "\n";
echo "files:  " . count($files) . "\n";
foreach (array_slice($files, 0, 10, true) as $name => $f) {
    if (!is_array($f) || !isset($f['name'], $f['size'])) { continue; }
    echo "file   " . sprintf('%-24s', substr((string)$name, 0, 24))
       . " size=" . (int)$f['size'] . "\n";
}
foreach (array_slice($fields, 0, 10, true) as $name => $v) {
    if (!is_string($v)) { continue; }
    echo "field  " . sprintf('%-24s', substr($name, 0, 24))
       . " len=" . strlen($v) . "\n";
}
echo "stored: nothing (metadata-only scanner)\n";
