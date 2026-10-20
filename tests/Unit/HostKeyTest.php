<?php

use Kongpda\ServerConnect\HostKey;
use Kongpda\ServerConnect\HostKeyChanged;
use Kongpda\ServerConnect\HostKeyPolicy;
use Kongpda\ServerConnect\InvalidHostKey;
use Kongpda\ServerConnect\Testing\FakeConnector;

test('parses ed25519, ECDSA and RSA keys and fingerprints them like ssh-keygen', function (string $file) {
    $key = HostKey::parse(keyFixture($file));

    expect($key->fingerprint())->toMatch('/^SHA256:[A-Za-z0-9+\/]{43}$/')
        ->and(HostKey::parse($key->toLine())->equals($key))->toBeTrue();
})->with(['ed25519_plain.pub', 'ecdsa_plain.pub', 'rsa_passphrase.pub']);

test('an RSA key signed as rsa-sha2-512 is the same key as ssh-rsa', function () {
    $line = HostKey::parse(keyFixture('rsa_passphrase.pub'))->toLine();
    $signed = HostKey::parse('rsa-sha2-512 '.explode(' ', $line)[1]);

    expect($signed->algorithm)->toBe('ssh-rsa')->and($signed->fingerprint())->toBe(HostKey::parse($line)->fingerprint());
});

dataset('malformed host keys', fn (): array => [
    'no data' => ['ssh-ed25519'],
    'not base64' => ['ssh-ed25519 !!!'],
    'wrong declared type' => ['ssh-rsa '.explode(' ', keyFixture('ed25519_plain.pub'))[1]],
    'unknown type' => ['ssh-dss '.base64_encode(pack('N', 7).'ssh-dss')],
    'trailing bytes' => ['ssh-ed25519 '.base64_encode(base64_decode(explode(' ', keyFixture('ed25519_plain.pub'))[1]).'x')],
]);

test('rejects malformed keys', function (string $line) {
    HostKey::parse($line);
})->with('malformed host keys')->throws(InvalidHostKey::class);

test('the pinned policy trusts on first use and blocks a changed key before authentication', function () {
    $first = HostKey::parse(FakeConnector::randomHostKey());
    $other = HostKey::parse(FakeConnector::randomHostKey());
    $pinned = null;

    HostKeyPolicy::pinned(null, function (HostKey $key) use (&$pinned) {
        $pinned = $key->fingerprint();
    })($first);
    expect($pinned)->toBe($first->fingerprint());

    HostKeyPolicy::pinned($pinned, fn () => throw new LogicException('not first use'))($first);

    try {
        HostKeyPolicy::pinned($pinned, fn () => null)($other);
        $this->fail('a changed key was accepted');
    } catch (HostKeyChanged $exception) {
        expect($exception->presented->fingerprint())->toBe($other->fingerprint())
            ->and($exception->pinnedFingerprint)->toBe($pinned)
            ->and($exception->getMessage())->toContain($pinned, $other->fingerprint(), 'rebuilt');
    }
});

test('a minimum RSA size refuses shorter RSA host keys and leaves other types alone', function () {
    $rsa = keyFixture('rsa_passphrase.pub');
    $bits = HostKey::parse($rsa)->rsaBits();

    expect($bits)->toBeInt()->toBeGreaterThanOrEqual(2048)
        ->and(HostKey::parse($rsa, minRsaBits: $bits)->rsaBits())->toBe($bits)
        ->and(HostKey::parse(keyFixture('ed25519_plain.pub'), minRsaBits: 4096)->rsaBits())->toBeNull()
        ->and(fn () => HostKey::parse($rsa, minRsaBits: $bits + 1))->toThrow(InvalidHostKey::class, 'RSA host keys must be at least '.($bits + 1)." bits. This one is {$bits}.");
});
