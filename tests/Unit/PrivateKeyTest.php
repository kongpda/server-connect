<?php

use Kongpda\ServerConnect\HostKey;
use Kongpda\ServerConnect\InvalidPrivateKey;
use Kongpda\ServerConnect\PrivateKey;
use phpseclib3\Crypt\EC;

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
    $key = PrivateKey::generateEd25519('deploy@ci.example.com');

    expect($key->publicLine)->toStartWith('ssh-ed25519 ')->toEndWith(' deploy@ci.example.com')
        ->and(print_r($key, true))->not->toContain('PRIVATE')
        ->and(PrivateKey::load($key->toOpenSsh())->fingerprint())->toBe($key->fingerprint());

    expect(fn () => serialize($key))->toThrow(LogicException::class);
});

/**
 * The fixture with its bcrypt rounds replaced.
 */
function withKdfRounds(string $text, int $rounds): string
{
    $binary = (string) base64_decode((string) preg_replace('/-----[^-]+-----|\s+/', '', $text), true);
    $offset = 15;
    $offset += 4 + unpack('N', substr($binary, $offset, 4))[1]; // cipher
    $offset += 4 + unpack('N', substr($binary, $offset, 4))[1]; // kdf name
    $offset += 4; // kdf options length
    $offset += 4 + unpack('N', substr($binary, $offset, 4))[1]; // salt
    $binary = substr_replace($binary, pack('N', $rounds), $offset, 4);

    return "-----BEGIN OPENSSH PRIVATE KEY-----\n".chunk_split(base64_encode($binary), 70, "\n")."-----END OPENSSH PRIVATE KEY-----\n";
}

test('refuses keys whose passphrase work factor would hold a worker', function () {
    $text = keyFixture('ed25519_passphrase');

    expect(fn () => PrivateKey::load(withKdfRounds($text, 0xFFFFFFFF), 'correct horse'))
        ->toThrow(fn (InvalidPrivateKey $e) => expect($e->getMessage())->toContain('at most '.PrivateKey::MAX_KDF_ROUNDS))
        ->and(fn () => PrivateKey::load(withKdfRounds($text, 0), 'correct horse'))->toThrow(InvalidPrivateKey::class)
        ->and(fn () => PrivateKey::load("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----", 'x'))
        ->toThrow(InvalidPrivateKey::class, 'PKCS#8');
});

test('refuses PuTTY keys, whose Argon2 cost comes from the key text', function () {
    // A comment that looks like an encrypted PEM key once let this past the work-factor check.
    $blob = explode(' ', keyFixture('ed25519_plain.pub'))[1];
    $text = implode("\n", [
        'PuTTY-User-Key-File-3: ssh-ed25519',
        'Encryption: aes256-cbc',
        'Comment: PRIVATE KEY Proc-Type: 4,ENCRYPTED',
        'Public-Lines: 2',
        ...str_split($blob, 64),
        'Key-Derivation: Argon2id',
        'Argon2-Memory: 65536',
        'Argon2-Passes: 50',
        'Argon2-Parallelism: 1',
        'Argon2-Salt: 00112233445566778899aabbccddeeff',
        'Private-Lines: 1',
        base64_encode(random_bytes(48)),
        'Private-MAC: '.str_repeat('00', 32),
    ]);

    $started = microtime(true);

    expect(fn () => PrivateKey::load($text, 'x'))->toThrow(fn (InvalidPrivateKey $e) => expect($e->reason)->toBe(InvalidPrivateKey::UNSUPPORTED))
        ->and(microtime(true) - $started)->toBeLessThan(0.5)
        ->and(fn () => PrivateKey::load("junk\n".keyFixture('ed25519_plain')))->toThrow(InvalidPrivateKey::class);
});

test('keeps the comment of a passphrase-protected OpenSSH key', function () {
    // The comment sits inside the encrypted part, so it is only readable once decrypted.
    expect(PrivateKey::load(keyFixture('ed25519_passphrase'), 'correct horse')->comment())->toBe('fixture-ed25519');
});

test('a key on a curve OpenSSH has no name for is refused as unsupported, not a phpseclib error', function () {
    $pem = EC::createKey('secp256k1')->toString('PKCS8');

    expect(fn () => PrivateKey::load($pem))->toThrow(fn (InvalidPrivateKey $e) => expect($e->reason)->toBe(InvalidPrivateKey::UNSUPPORTED));
});

test('at most 32 bcrypt rounds, about 16 seconds of a worker', function () {
    expect(PrivateKey::MAX_KDF_ROUNDS)->toBe(32)
        ->and(fn () => PrivateKey::load(withKdfRounds(keyFixture('ed25519_passphrase'), 33), 'correct horse'))
        ->toThrow(InvalidPrivateKey::class, 'at most 32');
});
