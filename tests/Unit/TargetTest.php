<?php

use Kongpda\ServerConnect\InvalidTarget;
use Kongpda\ServerConnect\SshException;
use Kongpda\ServerConnect\Target;
use Kongpda\ServerConnect\TargetGuard;

test('accepts plain hosts, IPv6 literals and login names', function () {
    expect((string) new Target('203.0.113.10', 22, 'root'))->toBe('root@203.0.113.10')
        ->and((string) new Target('ci-1.example.com', 2222, 'deploy'))->toBe('deploy@ci-1.example.com:2222')
        ->and((string) new Target('[2001:db8::1]', 22, 'root'))->toBe('root@[2001:db8::1]');
});

test('refuses option injection and smuggled users', function (string $host, string $user, int $port) {
    new Target($host, $port, $user);
})->with([
    'host option' => ['-oProxyCommand=sh', 'root', 22],
    'user option' => ['example.com', '-oProxyCommand=sh', 22],
    'user in host' => ['root@example.com', 'root', 22],
    'space in host' => ['example.com rm', 'root', 22],
    'space in user' => ['example.com', 'ro ot', 22],
    'newline in user' => ['example.com', "root\nx", 22],
    'empty host' => ['', 'root', 22],
    'port 0' => ['example.com', 'root', 0],
    'port too big' => ['example.com', 'root', 70000],
])->throws(InvalidTarget::class);

test('the guard refuses loopback, metadata and multicast, and allows private networks', function () {
    $guard = new TargetGuard;

    foreach (['127.0.0.1', '::1', '0.0.0.0', '169.254.169.254', 'fe80::1', '224.0.0.1', '::ffff:127.0.0.1'] as $address) {
        expect(fn () => $guard->resolve($address))->toThrow(fn (SshException $e) => expect($e->reason)->toBe(SshException::REFUSED_TARGET));
    }

    expect($guard->resolve('10.0.0.5'))->toBe('10.0.0.5')
        ->and($guard->resolve('192.168.1.20'))->toBe('192.168.1.20')
        ->and($guard->resolve('100.64.1.2'))->toBe('100.64.1.2')
        ->and($guard->resolve('[2001:db8::1]'))->toBe('2001:db8::1');
});

test('the guard refuses this application\'s own address unless local targets are allowed', function () {
    $lookup = fn (string $host): array => match ($host) {
        'ci.example.com' => ['203.0.113.5'],
        'runner.example.com' => ['2001:db8::7', '203.0.113.9'],
        'self.example.com' => ['203.0.113.5'],
        default => [],
    };

    $guard = new TargetGuard(false, ['ci.example.com'], $lookup);
    expect(fn () => $guard->resolve('self.example.com'))->toThrow(SshException::class, 'own server')
        ->and($guard->resolve('runner.example.com'))->toBe('203.0.113.9')
        ->and(fn () => $guard->resolve('nowhere.example.com'))->toThrow(SshException::class, "doesn't resolve");

    $relaxed = new TargetGuard(true, ['ci.example.com'], $lookup);
    expect($relaxed->resolve('self.example.com'))->toBe('203.0.113.5')
        ->and($relaxed->resolve('127.0.0.1'))->toBe('127.0.0.1');
});
