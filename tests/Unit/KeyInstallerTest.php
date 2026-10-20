<?php

use Kongpda\ServerConnect\Credentials;
use Kongpda\ServerConnect\HostKeyChanged;
use Kongpda\ServerConnect\HostKeyPolicy;
use Kongpda\ServerConnect\KeyInstaller;
use Kongpda\ServerConnect\PrivateKey;
use Kongpda\ServerConnect\SshException;
use Kongpda\ServerConnect\Target;
use Kongpda\ServerConnect\Testing\FakeConnector;

beforeEach(function () {
    $this->server = new FakeConnector;
    $this->server->passwords = ['hunter2'];
    $this->server->authorizedKeys = [];
    $this->key = PrivateKey::generateEd25519('app@test');
    $this->target = new Target('203.0.113.10', 22, 'root');
    $this->trust = HostKeyPolicy::pinned(null, fn () => null);
});

test('installs the key with the password over stdin, then logs in with the key', function () {
    $this->server->on(KeyInstaller::MARKER, function (string $command, string $stdin) {
        $this->server->authorizedKeys[] = trim($stdin);

        return ["SC_KEY_OK\n", 0];
    })->on('server-connect:verify-key', ["SC_VERIFY_OK\n", 0]);

    (new KeyInstaller($this->server))->install($this->target, '203.0.113.10', 'hunter2', $this->key, $this->trust);

    expect($this->server->connections)->sequence(
        fn ($c) => $c->auth->toBe('password'),
        fn ($c) => $c->auth->toBe('key'),
    );
    $install = $this->server->commands[0];
    expect($install['stdin'])->toBe($this->key->publicLine."\n")
        ->and($install['command'])->not->toContain('hunter2')->not->toContain($this->key->publicLine)
        ->and($install['command'])->toContain('umask 077', 'grep -qxF', 'restorecon', 'tail -c 1');
});

test('the install script is valid sh and idempotent', function () {
    expect(shellSyntaxOk(KeyInstaller::SCRIPT))->toBeTrue();

    $home = sys_get_temp_dir().'/sc-'.bin2hex(random_bytes(4));
    mkdir($home);
    file_put_contents("{$home}/seed", '');
    @mkdir("{$home}/.ssh");
    file_put_contents("{$home}/.ssh/authorized_keys", 'ssh-ed25519 AAAAexisting no-newline');

    foreach ([1, 2] as $run) {
        $process = proc_open(['sh', '-c', KeyInstaller::SCRIPT], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, ['HOME' => $home, 'PATH' => getenv('PATH')]);
        fwrite($pipes[0], $this->key->publicLine."\n");
        fclose($pipes[0]);
        $out = stream_get_contents($pipes[1]);
        proc_close($process);
        expect(trim((string) $out))->toBe('SC_KEY_OK');
    }

    expect(file_get_contents("{$home}/.ssh/authorized_keys"))->toBe("ssh-ed25519 AAAAexisting no-newline\n".$this->key->publicLine."\n")
        ->and(substr(sprintf('%o', fileperms("{$home}/.ssh/authorized_keys")), -3))->toBe('600');
});

test('a wrong password, a failed script and a refused key each explain themselves', function () {
    $installer = new KeyInstaller($this->server);

    expect(fn () => $installer->install($this->target, '203.0.113.10', 'nope', $this->key, $this->trust))
        ->toThrow(SshException::class, 'refused the credentials');

    $this->server->on(KeyInstaller::MARKER, ["mkdir: cannot create directory: Read-only file system\n", 1]);
    expect(fn () => $installer->install($this->target, '203.0.113.10', 'hunter2', $this->key, $this->trust))
        ->toThrow(SshException::class, 'Read-only file system');

    $this->server->on(KeyInstaller::MARKER, ["SC_KEY_OK\n", 0]);
    expect(fn () => $installer->install($this->target, '203.0.113.10', 'hunter2', $this->key, $this->trust))
        ->toThrow(SshException::class, 'logging in with it still fails');
});

test('a changed host key stops before the password is sent', function () {
    $installer = new KeyInstaller($this->server);

    expect(fn () => $installer->install($this->target, '203.0.113.10', 'hunter2', $this->key, HostKeyPolicy::pinned('SHA256:somethingelse', fn () => null)))
        ->toThrow(HostKeyChanged::class);
    expect($this->server->connections)->toBe([]);
});

test('credentials never serialize or dump their secret', function () {
    $credentials = Credentials::password('hunter2');

    expect(print_r($credentials, true))->not->toContain('hunter2')
        ->and(fn () => serialize($credentials))->toThrow(LogicException::class);
});

test('the check after installing must reach the same server, even on first use', function () {
    $pinned = [];
    $trust = HostKeyPolicy::pinned(null, function ($key) use (&$pinned) {
        $pinned[] = $key->fingerprint();
    });
    $this->server->on(KeyInstaller::MARKER, function (): array {
        $this->server->hostKey = FakeConnector::randomHostKey(); // another machine answers next

        return [KeyInstaller::OK_MARKER."\n", 0];
    });

    expect(fn () => (new KeyInstaller($this->server))->install($this->target, '203.0.113.10', 'hunter2', $this->key, $trust))
        ->toThrow(HostKeyChanged::class);
    expect($pinned)->toHaveCount(1)
        ->and($this->server->connections)->toHaveCount(1);
});
