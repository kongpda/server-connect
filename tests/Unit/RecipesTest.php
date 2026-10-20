<?php

use Kongpda\ServerConnect\Recipes\InvalidRecipeParam;
use Kongpda\ServerConnect\Recipes\Recipe;
use Kongpda\ServerConnect\Recipes\Recipes;
use Kongpda\ServerConnect\Recipes\SafetyLevel;
use Kongpda\ServerConnect\Shell\Shims;

test('the recipe set is closed and the prepare sequence is ordered', function () {
    expect(array_keys(Recipes::all()))->toBe(['essentials', 'docker', 'swap', 'ufw', 'fail2ban', 'unattended-upgrades', 'harden-ssh', 'apt-upgrade', 'reboot'])
        ->and(array_map(fn (Recipe $r) => $r->id, Recipes::prepareSequence()))->toBe(['essentials', 'docker', 'swap', 'ufw', 'fail2ban', 'unattended-upgrades', 'harden-ssh'])
        ->and(Recipes::find('rm-rf'))->toBeNull();
});

test('firewall, sshd and reboot are high risk', function () {
    foreach (['ufw', 'harden-ssh', 'reboot'] as $id) {
        expect(Recipes::find($id)?->safety)->toBe(SafetyLevel::HighRisk);
    }
    expect(Recipes::find('essentials')?->safety->needsConfirmation())->toBeFalse();
});

test('every recipe script is valid sh with the shims and the SSH port bound', function () {
    foreach (Recipes::all() as $recipe) {
        $script = $recipe->script(2222);

        expect(shellSyntaxOk($script))->toBeTrue("{$recipe->id} has a syntax error")
            ->and($script)->toStartWith("# server-connect:recipe-{$recipe->id}\n")
            ->and($script)->toContain("SUDO='sudo -n'", "SSH_PORT='2222'");
    }
});

test('the firewall keeps the ports sshd listens on open, falling back to the connection port', function () {
    expect(Recipes::find('ufw')?->script(2222))
        ->toContain("sshd -T 2>/dev/null | awk '\$1==\"port\"{print \$2}'")
        ->toContain('[ -n "$P" ] || P=$SSH_PORT')
        ->toContain('ufw allow "${p}/tcp"');
});

test('hardening SSH only tightens PermitRootLogin when it is yes', function () {
    $script = (string) Recipes::find('harden-ssh')?->script(22);

    expect($script)->toContain('permitrootlogin')
        ->toContain('= yes ]; then R=\'PermitRootLogin prohibit-password')
        ->not->toContain('\\nPermitRootLogin prohibit-password\\nPasswordAuthentication');
});

test('params are validated and quoted, and unknown ones never reach the shell', function () {
    $swap = Recipes::find('swap');
    expect($swap?->script(22, ['SWAP_SIZE' => '4096', 'EVIL' => '$(reboot)']))->toContain("SWAP_SIZE='4096'")->not->toContain('EVIL')
        ->and($swap?->script(22))->toContain("SWAP_SIZE='2048'");

    expect(fn () => $swap?->script(22, ['SWAP_SIZE' => "4096'; reboot; '"]))->toThrow(InvalidRecipeParam::class)
        ->and(fn () => Recipes::find('ufw')?->script(22, ['EXTRA_PORTS' => 'from any']))->toThrow(InvalidRecipeParam::class);
    // sh reads a leading zero as octal, and $((0999+512)) aborts the script.
    expect(fn () => $swap?->script(22, ['SWAP_SIZE' => '0999']))->toThrow(InvalidRecipeParam::class);
    expect(Recipes::find('ufw')?->script(22, ['EXTRA_PORTS' => '443 6000:6010/tcp']))->toContain("EXTRA_PORTS='443 6000:6010/tcp'");
});

test('quote survives single quotes', function () {
    expect(Shims::quote("it's"))->toBe("'it'\\''s'");
});
