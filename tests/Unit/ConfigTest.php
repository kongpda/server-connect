<?php

/*
 * config/server-connect.php reads its switches from the environment. A value
 * like "off" must not turn a guard's exception on: (bool) "off" is true.
 */

function serverConnectConfig(array $env): array
{
    foreach ($env as $name => $value) {
        putenv("{$name}={$value}");
    }

    try {
        return require __DIR__.'/../../config/server-connect.php';
    } finally {
        foreach (array_keys($env) as $name) {
            putenv($name);
        }
    }
}

test('the allow switches stay off unless the environment clearly turns them on', function (string $value, bool $expected) {
    $config = serverConnectConfig(['SERVER_CONNECT_ALLOW_PRIVATE' => $value, 'SERVER_CONNECT_ALLOW_LOCAL' => $value]);

    expect($config['allow_private'])->toBe($expected)->and($config['allow_local'])->toBe($expected);
})->with([
    'off' => ['off', false],
    'no' => ['no', false],
    'false' => ['false', false],
    '0' => ['0', false],
    'typo' => ['ture', false],
    'true' => ['true', true],
    '1' => ['1', true],
    'on' => ['on', true],
]);

test('the allow switches default to off', function () {
    $config = serverConnectConfig([]);

    expect($config['allow_private'])->toBeFalse()->and($config['allow_local'])->toBeFalse();
});
