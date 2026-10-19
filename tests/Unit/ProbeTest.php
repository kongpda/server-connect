<?php

use Kongpda\ServerConnect\Credentials;
use Kongpda\ServerConnect\Facts\Probe;
use Kongpda\ServerConnect\Facts\Provider;
use Kongpda\ServerConnect\HostKeyPolicy;
use Kongpda\ServerConnect\Monitor\MetricsProbe;
use Kongpda\ServerConnect\PrivateKey;
use Kongpda\ServerConnect\SshException;
use Kongpda\ServerConnect\Target;
use Kongpda\ServerConnect\Testing\FakeConnector;

function sampleProbeOutput(): string
{
    return <<<'OUT'
@@OSREL@@
PRETTY_NAME="Ubuntu 24.04.1 LTS"
ID=ubuntu
ID_LIKE=debian
VERSION_ID="24.04"
@@UNAME@@
Linux
x86_64
@@NPROC@@
4
@@MEM@@
MemTotal:        8040960 kB
MemAvailable:    6144000 kB
SwapTotal:       2097148 kB
@@DISK@@
165000000 120000000
@@LOAD@@
0.42 0.30 0.25 1/200 1234
@@UPTIME@@
86400.55 300000.00
@@VENDOR@@
Hetzner
@@ID@@
1000
@@SUDO@@
yes
@@SYSTEMD@@
yes
@@CURL@@
yes
@@PKG@@
apt-get
@@DOCKER@@
Docker version 29.0.1, build abc
@@DOCKERD@@
active
@@DACCESS@@
sudo
@@REBOOT@@
no
@@UFW@@
active
@@FAIL2BAN@@
inactive
@@UNATT@@
configured
@@SWAP@@
/swapfile
@@SSHD@@
permitrootlogin prohibit-password
passwordauthentication no
@@DPKG@@
free
@@X_RUNNER@@
proofr-runner 0.2.0
@@END@@
OUT;
}

test('parses one probe into facts', function () {
    $facts = Probe::parse(sampleProbeOutput());

    expect($facts->isLinux())->toBeTrue()
        ->and($facts->normalizedArch())->toBe('x86_64')
        ->and($facts->osId)->toBe('ubuntu')->and($facts->osVersion)->toBe('24.04')->and($facts->isDebianLike())->toBeTrue()
        ->and($facts->provider)->toBe(Provider::Hetzner)
        ->and($facts->cpuCount)->toBe(4)
        ->and($facts->memoryTotalMb)->toBe(7852)->and($facts->memoryAvailableMb)->toBe(6000)->and($facts->swapTotalMb)->toBe(2047)
        ->and($facts->diskTotalGb)->toBe(157.4)->and($facts->diskFreeGb)->toBe(114.4)
        ->and($facts->load1)->toBe(0.42)->and($facts->uptimeSeconds)->toBe(86400)
        ->and($facts->isRoot)->toBeFalse()->and($facts->sudo)->toBe('yes')->and($facts->canBecomeRoot())->toBeTrue()
        ->and($facts->dockerInstalled)->toBeTrue()->and($facts->dockerVersion)->toBe('29.0.1')->and($facts->dockerAccess)->toBe('sudo')
        ->and($facts->ufwActive)->toBeTrue()->and($facts->fail2banActive)->toBeFalse()->and($facts->unattendedUpgrades)->toBeTrue()
        ->and($facts->swapPresent)->toBeTrue()
        ->and($facts->sshdPasswordAuth)->toBeFalse()->and($facts->sshdRootLogin)->toBe('prohibit-password')
        ->and($facts->extra)->toBe(['RUNNER' => 'proofr-runner 0.2.0'])
        ->and($facts->toArray())->toHaveKeys(['os_name', 'provider', 'docker_access']);
});

test('a missing section is unknown, not zero', function () {
    $facts = Probe::parse("@@UNAME@@\nLinux\naarch64\n@@END@@\n");

    expect($facts->normalizedArch())->toBe('aarch64')
        ->and($facts->memoryTotalMb)->toBeNull()->and($facts->diskFreeGb)->toBeNull()->and($facts->cpuCount)->toBeNull()
        ->and($facts->sudo)->toBe('no')->and($facts->provider)->toBe(Provider::Unknown);
});

test('output without probe markers is an error with the server\'s message', function () {
    Probe::parse("sh: not found\n");
})->throws(SshException::class, 'sh: not found');

test('the probe is one read-only round trip through sh -s', function () {
    $server = (new FakeConnector)->on(Probe::MARKER, [sampleProbeOutput(), 0]);
    $session = $server->connect(new Target('203.0.113.1', 22, 'root'), '203.0.113.1', Credentials::key(PrivateKey::generateEd25519()), HostKeyPolicy::pinned(null, fn () => null));

    expect(Probe::run($session, ['RUNNER' => 'proofr-runner version 2>/dev/null'])->extra['RUNNER'])->toBe('proofr-runner 0.2.0')
        ->and($server->commands)->toHaveCount(1)
        ->and($server->commands[0]['command'])->toBe('sh -s')
        ->and($server->commands[0]['stdin'])->toContain('@@X_RUNNER@@; proofr-runner version');

    expect(shellSyntaxOk(Probe::script(['RUNNER' => 'proofr-runner version 2>/dev/null'])))->toBeTrue()
        ->and(fn () => Probe::script(['bad name' => 'x']))->toThrow(InvalidArgumentException::class);
});

test('metrics come from two /proc/stat samples', function () {
    $metrics = MetricsProbe::parse("@@STAT1@@\ncpu  100 0 100 800 0 0 0 0 0 0\n@@STAT2@@\ncpu  150 0 150 900 0 0 0 0 0 0\n@@MEM@@\nMemTotal: 2048000 kB\nMemAvailable: 1024000 kB\n@@DISK@@\n2097152 1048576\n@@LOAD@@\n1.5 1 1 1/1 1\n@@UPTIME@@\n100.2 1\n@@END@@\n");

    expect($metrics->cpuPercent)->toBe(50.0)
        ->and($metrics->memoryTotalMb)->toBe(2000)->and($metrics->memoryUsedMb)->toBe(1000)
        ->and($metrics->diskTotalGb)->toBe(2.0)->and($metrics->diskFreeGb)->toBe(1.0)
        ->and($metrics->load1)->toBe(1.5)->and($metrics->uptimeSeconds)->toBe(100);
    expect(MetricsProbe::parse('')->cpuPercent)->toBeNull()
        ->and(shellSyntaxOk(MetricsProbe::script()))->toBeTrue();
});
