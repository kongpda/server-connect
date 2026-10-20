<?php

/*
 * Runs recipe scripts for real in a Debian container. Skipped unless
 * SERVER_CONNECT_RECIPES_CONTAINER names one; scripts/test-recipes starts it.
 * These recipes can lock a user out of their server, so their behaviour is
 * tested, not just their text.
 */

use Kongpda\ServerConnect\Recipes\Recipes;

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
        ->and($output)->toContain('deny (incoming)');
});

test('hardening SSH refuses until the login user has a key, then turns passwords off', function () {
    $script = (string) Recipes::find('harden-ssh')?->script(22);
    $dropIn = '/etc/ssh/sshd_config.d/00-server-connect.conf';

    [$exit, $output] = inContainer($this->container, 'tester', $script);
    [, $present] = inContainer($this->container, 'root', "test -e {$dropIn} && echo present || echo absent");

    expect($exit)->not->toBe(0)->and($output)->toContain('No SSH key is set up for tester')
        ->and(trim($present))->toBe('absent');

    $public = trim(keyFixture('ed25519_plain.pub'));
    inContainer($this->container, 'tester', "mkdir -p ~/.ssh && echo '{$public}' > ~/.ssh/authorized_keys");

    [$exit, $output] = inContainer($this->container, 'tester', $script);

    expect($exit)->toBe(0, $output)->and($output)->toContain('passwordauthentication no');
});
