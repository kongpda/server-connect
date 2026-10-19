<?php

use Kongpda\ServerConnect\HostKey;
use Kongpda\ServerConnect\InvalidPrivateKey;
use Kongpda\ServerConnect\PrivateKey;

test('passphrase-protected OpenSSH keys need the right passphrase', function (string $file) {
    $text = keyFixture($file);
    $expected = HostKey::parse(keyFixture($file.'.pub'))->fingerprint();

    expect(PrivateKey::isEncrypted($text))->toBeTrue();
    expect(fn () => PrivateKey::load($text))->toThrow(fn (InvalidPrivateKey $e) => expect($e->reason)->toBe(InvalidPrivateKey::PASSPHRASE_REQUIRED));
    expect(fn () => PrivateKey::load($text, 'wrong horse'))->toThrow(fn (InvalidPrivateKey $e) => expect($e->reason)->toBe(InvalidPrivateKey::WRONG_PASSPHRASE));

    $key = PrivateKey::load($text, 'correct horse');
    expect($key->fingerprint())->toBe($expected);

    // Decrypt once, store without the passphrase…
    $plain = $key->toOpenSsh();
    expect(PrivateKey::isEncrypted($plain))->toBeFalse()
        ->and(PrivateKey::load($plain)->fingerprint())->toBe($expected);

    // …or keep it locked with a passphrase.
    $locked = $key->toOpenSsh('another passphrase', rounds: 2);
    expect(PrivateKey::isEncrypted($locked))->toBeTrue()
        ->and(PrivateKey::load($locked, 'another passphrase')->fingerprint())->toBe($expected);
})->with(['ed25519_passphrase', 'rsa_passphrase']);

test('loads unencrypted OpenSSH and PEM keys', function (string $file, string $type) {
    $key = PrivateKey::load(keyFixture($file));

    expect($key->type)->toBe($type)
        ->and($key->fingerprint())->toBe(HostKey::parse(keyFixture($file.'.pub'))->fingerprint())
        ->and(PrivateKey::isEncrypted(keyFixture($file)))->toBeFalse();
})->with([
    ['ed25519_plain', 'ssh-ed25519'],
    ['ecdsa_plain', 'ecdsa-sha2-nistp256'],
    ['rsa_pem_plain', 'ssh-rsa'],
]);

test('keeps the comment of an unencrypted OpenSSH key', function () {
    expect(PrivateKey::load(keyFixture('ed25519_plain'))->publicLine)->toEndWith(' fixture-plain');
});

test('refuses text that is not a private key', function (string $text) {
    expect(fn () => PrivateKey::load($text))->toThrow(fn (InvalidPrivateKey $e) => expect($e->reason)->toBe(InvalidPrivateKey::UNSUPPORTED));
})->with(fn (): array => [
    'empty' => [''],
    'a public key' => [keyFixture('ed25519_plain.pub')],
    'garbage' => ["-----BEGIN OPENSSH PRIVATE KEY-----\nbm9wZQ==\n-----END OPENSSH PRIVATE KEY-----"],
]);

test('generates Ed25519 keys and never prints the private part', function () {
    $key = PrivateKey::generateEd25519('proofr@ci.example.com');

    expect($key->publicLine)->toStartWith('ssh-ed25519 ')->toEndWith(' proofr@ci.example.com')
        ->and(print_r($key, true))->not->toContain('PRIVATE')
        ->and(PrivateKey::load($key->toOpenSsh())->fingerprint())->toBe($key->fingerprint());

    expect(fn () => serialize($key))->toThrow(LogicException::class);
});
