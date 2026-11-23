<?php
// Courier relay console: signing helpers and small utilities.
// This file lives outside the document root (see the Dockerfile).

const RELIC_KEY_PATH = '/var/www/private/console.key';
const RELIC_COOKIE   = 'relic_state';

function relic_key(): string
{
    if (!is_readable(RELIC_KEY_PATH)) {
        http_response_code(503);
        header('Content-Type: text/plain');
        echo "console signing material unavailable\n";
        exit;
    }
    $key = trim((string) file_get_contents(RELIC_KEY_PATH));
    if (strlen($key) < 16) {
        http_response_code(503);
        header('Content-Type: text/plain');
        echo "console signing material unavailable\n";
        exit;
    }
    return $key;
}

function relic_b64u(string $raw): string
{
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}

function relic_b64u_decode(string $text): string
{
    $text = strtr($text, '-_', '+/');
    $pad = strlen($text) % 4;
    if ($pad !== 0) {
        $text .= str_repeat('=', 4 - $pad);
    }
    return (string) base64_decode($text, true);
}

/** Sign a state payload (array) into cookie form. */
function relic_seal(array $payload): string
{
    $body = relic_b64u(json_encode($payload, JSON_UNESCAPED_SLASHES));
    return 'v1.' . $body . '.' . hash_hmac('sha256', 'v1.' . $body, relic_key());
}

/** Verify and decode the state cookie; null when absent/invalid/expired. */
function relic_open_state(): ?array
{
    $raw = $_COOKIE[RELIC_COOKIE] ?? '';
    $parts = explode('.', $raw);
    if (count($parts) !== 3 || $parts[0] !== 'v1') {
        return null;
    }
    $expected = hash_hmac('sha256', 'v1.' . $parts[1], relic_key());
    if (!hash_equals($expected, $parts[2])) {
        return null;
    }
    $payload = json_decode(relic_b64u_decode($parts[1]), true);
    if (!is_array($payload) || !isset($payload['s'], $payload['e'], $payload['n'])) {
        return null;
    }
    if ((int) $payload['e'] < time()) {
        return null;
    }
    return $payload;
}

function relic_send_state(array $payload): void
{
    setcookie(RELIC_COOKIE, relic_seal($payload), [
        'path' => '/',
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

function relic_json(array $data, int $code = 200): void
{
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}
