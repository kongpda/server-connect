<?php

use Kongpda\ServerConnect\InvalidTarget;
use Kongpda\ServerConnect\SshException;
use Kongpda\ServerConnect\Target;
use Kongpda\ServerConnect\TargetGuard;

test('accepts plain hosts, IPv6 literals and login names', function () {
    expect((string) new Target('203.0.113.10', 22, 'root'))->toBe('root@203.0.113.10')
        ->and((string) new Target('ci-1.example.com', 2222, 'deploy'))->toBe('deploy@ci-1.example.com:2222')
        ->and((string) new Target('[2001:db8::1]', 22, 'root'))->toBe('root@[2001:db8::1]')
        ->and((string) new Target('2001:db8::1', 22, 'root'))->toBe('root@[2001:db8::1]');
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
    // A trailing newline would reach logs and messages that quote the host.
    'newline after host' => ["example.com\n", 'root', 22],
    'newline after IP' => ["203.0.113.5\n", 'root', 22],
    // Only a bare host: a port or brackets around a name aren't what they look like.
    'port in host' => ['203.0.113.5:22', 'root', 22],
    'port after IPv6' => ['[2001:db8::1]:22', 'root', 22],
    'brackets around a name' => ['[example.com]', 'root', 22],
    'empty label' => ['example..com', 'root', 22],
    'port 0' => ['example.com', 'root', 0],
    'port too big' => ['example.com', 'root', 70000],
])->throws(InvalidTarget::class);

test('the guard refuses loopback, metadata, multicast and private networks by default', function (string $address) {
    expect(fn () => (new TargetGuard)->resolve($address))
        ->toThrow(fn (SshException $e) => expect($e->reason)->toBe(SshException::REFUSED_TARGET));
})->with([
    '127.0.0.1', '::1', '0.0.0.0', '169.254.169.254', 'fe80::1', '224.0.0.1', '::ffff:127.0.0.1',
    '10.0.0.5', '172.17.0.1', '192.168.1.20', '100.64.1.2', '100.100.100.200', 'fd00:ec2::254', 'fec0::1',
    '192.0.0.170', '198.18.0.1', '64:ff9b:1::a00:5', '::ffff:0:a9fe:a9fe', '100::1',
]);

test('the guard allows public addresses, and private networks when asked', function () {
    $guard = new TargetGuard;
    $private = new TargetGuard(allowPrivate: true);

    expect($guard->resolve('203.0.113.10'))->toBe('203.0.113.10')
        ->and($guard->resolve('[2001:db8::1]'))->toBe('2001:db8::1')
        ->and($private->resolve('10.0.0.5'))->toBe('10.0.0.5')
        ->and($private->resolve('192.168.1.20'))->toBe('192.168.1.20')
        ->and($private->resolve('100.64.1.2'))->toBe('100.64.1.2')
        ->and($private->resolve('fd12::5'))->toBe('fd12::5')
        ->and(fn () => $private->resolve('169.254.169.254'))->toThrow(SshException::class, 'link-local')
        ->and(fn () => $private->resolve('127.0.0.1'))->toThrow(SshException::class, 'loopback');
});

test('this machine\'s interface addresses count as its own', function () {
    $guard = new TargetGuard(interfaceAddresses: ['203.0.113.77', '2001:db8::77']);

    expect(fn () => $guard->resolve('203.0.113.77'))->toThrow(SshException::class, 'own server')
        ->and(fn () => $guard->resolve('2001:db8:0::77'))->toThrow(SshException::class, 'own server')
        ->and($guard->resolve('203.0.113.78'))->toBe('203.0.113.78');
});

test('the guard sees through IPv4 addresses wrapped in IPv6', function (string $address) {
    expect(fn () => (new TargetGuard)->resolve($address))
        ->toThrow(fn (SshException $e) => expect($e->reason)->toBe(SshException::REFUSED_TARGET));
})->with([
    'mapped loopback' => ['::ffff:127.0.0.1'],
    'compatible loopback' => ['::127.0.0.1'],
    'NAT64 metadata' => ['64:ff9b::a9fe:a9fe'],
    '6to4 metadata' => ['2002:a9fe:a9fe::1'],
    '6to4 loopback' => ['2002:7f00:1::'],
]);

test('wrapped addresses of this application count as its own', function () {
    $guard = new TargetGuard(false, [' 203.0.113.5 '], allowPrivate: true);

    expect(fn () => $guard->resolve('64:ff9b::cb00:7105'))->toThrow(SshException::class, 'own server')
        ->and($guard->resolve('64:ff9b::a00:5'))->toBe('64:ff9b::a00:5');
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
