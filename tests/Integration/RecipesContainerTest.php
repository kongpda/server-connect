<?php

/*
 * Runs recipe scripts for real in a Debian container. Skipped unless
 * SERVER_CONNECT_RECIPES_CONTAINER names one; scripts/test-recipes starts it.
 * These recipes can lock a user out of their server, so their behaviour is
 * tested, not just their text.
 */

use Kongpda\ServerConnect\Recipes\Recipes;
use Kongpda\ServerConnect\Shell\Shims;

beforeEach(function () {
    $this->container = (string) getenv('SERVER_CONNECT_RECIPES_CONTAINER');

    if ($this->container === '') {
        $this->markTestSkipped('Set SERVER_CONNECT_RECIPES_CONTAINER (see scripts/test-recipes).');
    }
});

/**
 * @param  array<string, string>  $env
 * @return array{0: int, 1: string}
 */
function inContainer(string $container, string $user, string $script, array $env = []): array
{
    $command = ['docker', 'exec', '-i', '-u', $user];

    foreach ($env as $name => $value) {
        array_push($command, '-e', "{$name}={$value}");
    }

    array_push($command, $container, 'sh', '-s');
    $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    fwrite($pipes[0], $script);
    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]).stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);

    return [proc_close($process), $output];
}

test('the firewall keeps the port this connection reached open, not only sshd_config\'s', function () {
    // sshd_config says 22, but this connection came in on 2222 (socket activation or a
    // local redirect); 2200 is the port outside the NAT, which means nothing here.
    $script = (string) Recipes::find('ufw')?->script(2200);
    [$exit, $output] = inContainer($this->container, 'root', $script, ['SSH_CONNECTION' => '203.0.113.9 50000 172.17.0.2 2222']);

    expect($exit)->toBe(0, $output)
        ->and($output)->toMatch('/^22\/tcp\s+ALLOW IN/m')
        ->and($output)->toMatch('/^2222\/tcp\s+ALLOW IN/m')
        ->and($output)->toContain('deny (incoming)')
        ->and($output)->not->toContain('DOCKER-USER');
});

test('the firewall warns that Docker-published ports bypass it', function () {
    // A user who enables UFW to close a container's port would otherwise think it is closed.
    inContainer($this->container, 'root', "printf '#!/bin/sh\\nexit 0\\n' > /usr/local/bin/docker && chmod +x /usr/local/bin/docker");
    [$exit, $output] = inContainer($this->container, 'root', (string) Recipes::find('ufw')?->script(22));
    inContainer($this->container, 'root', 'rm -f /usr/local/bin/docker');

    expect($exit)->toBe(0, $output)->and($output)->toContain('bypass UFW');
});

test('a non-root login finds tools in sbin', function () {
    // Debian gives non-root users no /usr/sbin in PATH, where ufw and sshd live.
    [$exit, $output] = inContainer($this->container, 'tester', Shims::script('test:path', 'command -v ufw', strict: false), ['PATH' => '/usr/local/bin:/usr/bin:/bin:/usr/games']);

    expect($exit)->toBe(0, $output)->and(trim($output))->toBe('/usr/sbin/ufw');
});

test('hardening SSH says so when sudo needs a password, instead of blaming sshd_config', function () {
    inContainer($this->container, 'root', 'id nosudo >/dev/null 2>&1 || useradd -m -s /bin/sh nosudo');
    [$exit, $output] = inContainer($this->container, 'nosudo', (string) Recipes::find('harden-ssh')?->script(22));

    expect($exit)->not->toBe(0)->and($output)->toContain('needs root, or passwordless sudo')
        ->and($output)->not->toContain('include');
});

test('hardening SSH refuses until the login user has a key, then turns passwords off', function () {
    $script = (string) Recipes::find('harden-ssh')?->script(22);
    $dropIn = '/etc/ssh/sshd_config.d/00-server-connect.conf';

    $public = trim(keyFixture('ed25519_plain.pub'));

    [$exit, $output] = inContainer($this->container, 'tester', $script);
    [, $present] = inContainer($this->container, 'root', "test -e {$dropIn} && echo present || echo absent");

    expect($exit)->not->toBe(0)->and($output)->toContain('No SSH key is set up for tester')
        ->and(trim($present))->toBe('absent');

    // A commented-out key can't log in either.
    inContainer($this->container, 'tester', "mkdir -p ~/.ssh && echo '# {$public}' > ~/.ssh/authorized_keys");
    [$exit, $output] = inContainer($this->container, 'tester', $script);

    expect($exit)->not->toBe(0)->and($output)->toContain('No SSH key is set up for tester');

    inContainer($this->container, 'tester', "echo '{$public}' > ~/.ssh/authorized_keys");
    // A running sshd (no systemd here), so the reload is real.
    inContainer($this->container, 'root', 'pgrep -x sshd >/dev/null || /usr/sbin/sshd');

    [$exit, $output] = inContainer($this->container, 'tester', $script);
    [, $running] = inContainer($this->container, 'root', 'pgrep -x sshd >/dev/null && echo running || echo stopped');

    expect($exit)->toBe(0, $output)->and($output)->toContain('passwordauthentication no')->toContain('sshd reloaded')
        ->and(trim($running))->toBe('running');
});

test('a hardening rollback puts the previous drop-in back instead of deleting it', function () {
    // The previous file may be the one keeping the server reachable; rollback must not lose it.
    $dropIn = '/etc/ssh/sshd_config.d/00-server-connect.conf';
    inContainer($this->container, 'root', "printf '# previous\\n' > {$dropIn} && cp /etc/ssh/sshd_config /tmp/sshd_config.orig && sed -i '1i PasswordAuthentication yes' /etc/ssh/sshd_config");

    [$exit, $output] = inContainer($this->container, 'tester', (string) Recipes::find('harden-ssh')?->script(22));
    [, $kept] = inContainer($this->container, 'root', "cat {$dropIn}; ls /etc/ssh/sshd_config.d/; mv /tmp/sshd_config.orig /etc/ssh/sshd_config");

    expect($exit)->not->toBe(0)->and($output)->toContain('Rolled back')
        ->and($kept)->toContain('# previous')->not->toContain('.bak');
});
