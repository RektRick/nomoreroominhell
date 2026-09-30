<?php

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');


//============================================================
// CONFIG
//============================================================

const API_SECRET = 'CHANGE_THIS_SECRET';

// Idealmente este directorio NO debe ser públicamente accesible.
const LOG_FILE = __DIR__ . '/../private/sessions.jsonl';


//============================================================
// RESPONSE
//============================================================

function respond(int $status, array $data): never
{
    http_response_code($status);

    echo json_encode(
        $data,
        JSON_UNESCAPED_SLASHES |
        JSON_UNESCAPED_UNICODE
    );

    exit;
}


//============================================================
// ONLY POST
//============================================================

if ($_SERVER['REQUEST_METHOD'] !== 'POST')
{
    respond(405, [
        'ok' => false,
        'error' => 'method_not_allowed'
    ]);
}


//============================================================
// CHECK API SECRET
//============================================================

$providedSecret =
    $_SERVER['HTTP_X_MOSCAWARE_SECRET']
    ?? '';


if (!hash_equals(
        API_SECRET,
        $providedSecret))
{
    respond(401, [
        'ok' => false,
        'error' => 'unauthorized'
    ]);
}

$raw =
    file_get_contents('php://input');


if ($raw === false || $raw === '')
{
    respond(400, [
        'ok' => false,
        'error' => 'empty_body'
    ]);
}


$data =
    json_decode(
        $raw,
        true
    );


if (!is_array($data))
{
    respond(400, [
        'ok' => false,
        'error' => 'invalid_json'
    ]);
}

$username =
    trim(
        (string)(
            $data['username']
            ?? ''
        )
    );


$licenseKey =
    trim(
        (string)(
            $data['license_key']
            ?? ''
        )
    );


if ($username === '' ||
    $licenseKey === '')
{
    respond(400, [
        'ok' => false,
        'error' => 'missing_fields'
    ]);
}

if (!preg_match(
        '/^[A-Za-z0-9_]{3,20}$/',
        $username))
{
    respond(400, [
        'ok' => false,
        'error' => 'invalid_username'
    ]);
}

$directory =
    dirname(LOG_FILE);


if (!is_dir($directory))
{
    if (!mkdir(
            $directory,
            0755,
            true
        ))
    {
        respond(500, [
            'ok' => false,
            'error' => 'storage_error'
        ]);
    }
}

$entry = [
    'time' =>
        gmdate('c'),

    'username' =>
        $username,

    'license_hash' =>
        hash(
            'sha256',
            $licenseKey
        ),

    'ip' =>
        $_SERVER['REMOTE_ADDR']
        ?? ''
];


$line =
    json_encode(
        $entry,
        JSON_UNESCAPED_SLASHES |
        JSON_UNESCAPED_UNICODE
    )
    . PHP_EOL;


$result =
    file_put_contents(
        LOG_FILE,
        $line,
        FILE_APPEND |
        LOCK_EX
    );


if ($result === false)
{
    respond(500, [
        'ok' => false,
        'error' => 'write_failed'
    ]);
}

respond(200, [
    'ok' => true,
    'username' => $username
]);
