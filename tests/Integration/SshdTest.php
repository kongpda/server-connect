<?php

/*
 * Against a real sshd. Skipped unless SERVER_CONNECT_SSHD=host:port is set;
 * scripts/test-ssh starts a throwaway sshd in Docker and runs these.
 * Expects a user with a password and no authorized_keys yet.
 */

use Kongpda\ServerConnect\Credentials;
use Kongpda\ServerConnect\Facts\Probe;
use Kongpda\ServerConnect\HostKey;
use Kongpda\ServerConnect\HostKeyChanged;
use Kongpda\ServerConnect\HostKeyPolicy;
use Kongpda\ServerConnect\KeyInstaller;
use Kongpda\ServerConnect\Phpseclib\PhpseclibConnector;
use Kongpda\ServerConnect\PrivateKey;
use Kongpda\ServerConnect\SshException;
use Kongpda\ServerConnect\Target;
use Kongpda\ServerConnect\Testing\FakeConnector;

beforeEach(function () {
    $sshd = (string) getenv('SERVER_CONNECT_SSHD');

    if ($sshd === '') {
        $this->markTestSkipped('Set SERVER_CONNECT_SSHD=host:port (see scripts/test-ssh).');
    }

    [$host, $port] = explode(':', $sshd);
    $this->address = $host;
    $this->target = new Target($host, (int) $port, (string) (getenv('SERVER_CONNECT_SSHD_USER') ?: 'tester'));
    $this->password = (string) getenv('SERVER_CONNECT_SSHD_PASSWORD');
    $this->connector = new PhpseclibConnector(8, 5);
});

test('scans an Ed25519 host key with the fingerprint ssh-keygen prints', function () {
    $key = $this->connector->scanHostKey($this->target, $this->address);

    expect($key->algorithm)->toBe('ssh-ed25519');

    $expected = (string) getenv('SERVER_CONNECT_SSHD_FINGERPRINT');

    if ($expected !== '') {
        expect($key->fingerprint())->toBe($expected);
    }
});

test('a pinned fingerprint that does not match stops before authentication', function () {
    $other = HostKey::parse(FakeConnector::randomHostKey());

    expect(fn () => $this->connector->connect($this->target, $this->address, Credentials::password($this->password), HostKeyPolicy::pinned($other->fingerprint(), fn () => null)))
        ->toThrow(HostKeyChanged::class);
});

test('a wrong password is an authentication failure', function () {
    expect(fn () => $this->connector->connect($this->target, $this->address, Credentials::password('definitely-wrong'), fn () => null))
        ->toThrow(SshException::class, 'refused the password');
});

test('installs a generated key with the password, then logs in with it', function () {
    $pinned = null;
    $key = PrivateKey::generateEd25519('server-connect-test');

    (new KeyInstaller($this->connector))->install($this->target, $this->address, $this->password, $key, HostKeyPolicy::pinned(null, function (HostKey $hostKey) use (&$pinned) {
        $pinned = $hostKey->fingerprint();
    }));

    expect($pinned)->toStartWith('SHA256:');

    $session = $this->connector->connect($this->target, $this->address, Credentials::key($key), HostKeyPolicy::expect($pinned));
    $listing = $session->run('cat ~/.ssh/authorized_keys; stat -c %a ~/.ssh ~/.ssh/authorized_keys');
    $session->disconnect();

    expect(substr_count($listing->output, $key->publicLine))->toBe(1)
        ->and($listing->output)->toContain("700\n600");

    // Idempotent: a second install doesn't add the key again.
    (new KeyInstaller($this->connector))->install($this->target, $this->address, $this->password, $key, HostKeyPolicy::expect($pinned));
    $session = $this->connector->connect($this->target, $this->address, Credentials::key($key), HostKeyPolicy::expect($pinned));
    expect(substr_count($session->run('cat ~/.ssh/authorized_keys')->output, $key->publicLine))->toBe(1);
    $session->disconnect();
});

test('passphrase-protected Ed25519 and RSA keys log in once decrypted', function (string $fixture) {
    $key = PrivateKey::load(keyFixture($fixture), 'correct horse');
    (new KeyInstaller($this->connector))->install($this->target, $this->address, $this->password, $key, fn () => null);

    $session = $this->connector->connect($this->target, $this->address, Credentials::key($key), fn () => null);
    expect($session->run('id -un')->output)->toBe($this->target->user."\n");
    $session->disconnect();
})->with(['ed25519_passphrase', 'rsa_passphrase']);

test('runs commands with stdin, exit codes, stderr, streaming and a wall-clock timeout', function () {
    $key = PrivateKey::generateEd25519();
    (new KeyInstaller($this->connector))->install($this->target, $this->address, $this->password, $key, fn () => null);
    $session = $this->connector->connect($this->target, $this->address, Credentials::key($key), fn () => null);

    $echo = $session->run('read line; echo "got $line"; echo oops >&2; exit 3', "a secret on stdin\n", null);
    expect($echo->exitCode)->toBe(3)->and($echo->output)->toBe("got a secret on stdin\noops\n");

    $script = $session->run('sh -s', "echo hello from stdin\nexit 0\n");
    expect($script->output)->toBe("hello from stdin\n")->and($script->successful())->toBeTrue();

    $chunks = [];
    $streamed = $session->run('for i in 1 2 3; do echo line $i; sleep 0.3; done', '', function (string $chunk) use (&$chunks) {
        $chunks[] = $chunk;
    });
    expect(implode('', $chunks))->toBe("line 1\nline 2\nline 3\n")->and(count($chunks))->toBeGreaterThan(1)
        ->and($streamed->output)->toBe("line 1\nline 2\nline 3\n");

    $started = microtime(true);
    $slow = $session->run('sleep 30', '', null, 3);
    expect($slow->timedOut)->toBeTrue()->and(microtime(true) - $started)->toBeLessThan(10);

    // A command that keeps printing still times out.
    $started = microtime(true);
    $chatty = $session->run('while :; do echo tick; sleep 1; done', '', null, 3);
    expect($chatty->timedOut)->toBeTrue()->and(microtime(true) - $started)->toBeLessThan(6);
    $session->disconnect();

    // Output beyond the limit is dropped from the result but still streamed.
    $capped = new PhpseclibConnector(8, 5, maxOutputBytes: 1000);
    $session = $capped->connect($this->target, $this->address, Credentials::key($key), fn () => null);
    $seen = 0;
    $big = $session->run('head -c 5000 /dev/zero | tr "\\0" x', '', function (string $chunk) use (&$seen) {
        $seen += strlen($chunk);
    });
    expect($big->truncated)->toBeTrue()->and(strlen($big->output))->toBe(1000)->and($seen)->toBe(5000)
        ->and(print_r($session, true))->not->toContain('auth')
        ->and(fn () => serialize($session))->toThrow(LogicException::class);
    $session->disconnect();

    $session = $this->connector->connect($this->target, $this->address, Credentials::key($key), fn () => null);
    $facts = Probe::run($session);
    $session->disconnect();

    expect($facts->isLinux())->toBeTrue()->and($facts->normalizedArch())->not->toBeNull()->and($facts->isRoot)->toBeFalse();
});

test('a killed command has no exit code, even after one that succeeded', function () {
    // phpseclib keeps the last exit status; reusing it would make a killed command look successful.
    $session = $this->connector->connect($this->target, $this->address, Credentials::password($this->password), fn () => null);

    $ok = $session->run('exit 0');
    $killed = $session->run('kill -9 $$');
    $session->disconnect();

    expect($ok->exitCode)->toBe(0)->and($killed->exitCode)->toBeNull()->and($killed->successful())->toBeFalse();
});

test('stderr counts toward the output cap and is not kept in memory', function () {
    $capped = new PhpseclibConnector(8, 5, maxOutputBytes: 1000);
    $session = $capped->connect($this->target, $this->address, Credentials::password($this->password), fn () => null);

    memory_reset_peak_usage();
    $before = memory_get_usage();
    $result = $session->run('head -c 30000000 /dev/zero >&2');
    $session->disconnect();

    expect($result->truncated)->toBeTrue()->and(strlen($result->output))->toBe(1000)
        ->and(memory_get_peak_usage() - $before)->toBeLessThan(10 * 1024 * 1024);
});

test('a closed port is unreachable, quickly', function () {
    $started = microtime(true);

    expect(fn () => $this->connector->connect(new Target($this->address, 1, 'tester'), $this->address, Credentials::password('x'), fn () => null))
        ->toThrow(SshException::class, 'refused the connection');
    expect(microtime(true) - $started)->toBeLessThan(10);
});
