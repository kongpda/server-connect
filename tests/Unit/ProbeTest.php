<?php

use Kongpda\ServerConnect\CommandResult;
use Kongpda\ServerConnect\Credentials;
use Kongpda\ServerConnect\Facts\Probe;
use Kongpda\ServerConnect\Facts\Provider;
use Kongpda\ServerConnect\HostKeyPolicy;
use Kongpda\ServerConnect\Monitor\MetricsProbe;
use Kongpda\ServerConnect\PrivateKey;
use Kongpda\ServerConnect\Session;
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
@@PRODUCT@@
vServer
@@VIRT@@
kvm
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
myapp-agent 0.2.0
@@END@@
OUT;
}

test('parses one probe into facts', function () {
    $facts = Probe::parse(sampleProbeOutput());

    expect($facts->isLinux())->toBeTrue()
        ->and($facts->normalizedArch())->toBe('x86_64')
        ->and($facts->osId)->toBe('ubuntu')->and($facts->osVersion)->toBe('24.04')->and($facts->isDebianLike())->toBeTrue()
        ->and($facts->provider)->toBe(Provider::Hetzner)->and($facts->provider->isCloud())->toBeTrue()
        ->and($facts->virtualization)->toBe('kvm')->and($facts->isVirtualMachine())->toBeTrue()->and($facts->isContainer())->toBeFalse()
        ->and($facts->cpuCount)->toBe(4)
        ->and($facts->memoryTotalMb)->toBe(7852)->and($facts->memoryAvailableMb)->toBe(6000)->and($facts->swapTotalMb)->toBe(2047)
        ->and($facts->diskTotalGb)->toBe(157.4)->and($facts->diskFreeGb)->toBe(114.4)
        ->and($facts->load1)->toBe(0.42)->and($facts->uptimeSeconds)->toBe(86400)
        ->and($facts->isRoot)->toBeFalse()->and($facts->sudo)->toBe('yes')->and($facts->canBecomeRoot())->toBeTrue()
        ->and($facts->dockerInstalled)->toBeTrue()->and($facts->dockerVersion)->toBe('29.0.1')->and($facts->dockerAccess)->toBe('sudo')
        ->and($facts->ufwActive)->toBeTrue()->and($facts->fail2banActive)->toBeFalse()->and($facts->unattendedUpgrades)->toBeTrue()
        ->and($facts->swapPresent)->toBeTrue()
        ->and($facts->sshdPasswordAuth)->toBeFalse()->and($facts->sshdRootLogin)->toBe('prohibit-password')
        ->and($facts->extra)->toBe(['RUNNER' => 'myapp-agent 0.2.0'])
        ->and($facts->toArray())->toHaveKeys(['os_name', 'provider', 'virtualization', 'docker_access']);
});

test('a missing section is unknown, not zero', function () {
    $facts = Probe::parse("@@UNAME@@\nLinux\naarch64\n@@END@@\n");

    expect($facts->normalizedArch())->toBe('aarch64')
        ->and($facts->memoryTotalMb)->toBeNull()->and($facts->diskFreeGb)->toBeNull()->and($facts->cpuCount)->toBeNull()
        ->and($facts->sudo)->toBe('no')->and($facts->provider)->toBe(Provider::Unknown)
        ->and($facts->virtualization)->toBeNull()->and($facts->isVirtualMachine())->toBeNull();
});

test('output without probe markers is an error with the server\'s message', function () {
    Probe::parse("sh: not found\n");
})->throws(SshException::class, 'sh: not found');

test('the probe is one read-only round trip through sh -s', function () {
    $server = (new FakeConnector)->on(Probe::MARKER, [sampleProbeOutput(), 0]);
    $session = $server->connect(new Target('203.0.113.1', 22, 'root'), '203.0.113.1', Credentials::key(PrivateKey::generateEd25519()), HostKeyPolicy::pinned(null, fn () => null));

    expect(Probe::run($session, ['RUNNER' => 'myapp-agent version 2>/dev/null'])->extra['RUNNER'])->toBe('myapp-agent 0.2.0')
        ->and($server->commands)->toHaveCount(1)
        ->and($server->commands[0]['command'])->toBe('sh -s')
        ->and($server->commands[0]['stdin'])->toContain('@@X_RUNNER@@; myapp-agent version');

    expect(shellSyntaxOk(Probe::script(['RUNNER' => 'myapp-agent version 2>/dev/null'])))->toBeTrue()
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

test('the provider names clouds and the hypervisors of your own VMs', function (string $vendor, string $product, Provider $provider, bool $cloud) {
    expect(Provider::fromDmi($vendor, $product))->toBe($provider)
        ->and($provider->isCloud())->toBe($cloud);
})->with([
    'hetzner' => ['Hetzner', 'vServer', Provider::Hetzner, true],
    'digitalocean' => ['DigitalOcean', 'Droplet', Provider::DigitalOcean, true],
    'oracle cloud' => ['OracleCloud.com', 'BM.Standard', Provider::Oracle, true],
    'proxmox, libvirt, multipass, utm' => ['QEMU', 'Standard PC (Q35 + ICH9, 2009)', Provider::Qemu, false],
    'virtualbox (innotek)' => ['innotek GmbH', 'VirtualBox', Provider::VirtualBox, false],
    'virtualbox (oracle vendor)' => ['Oracle Corporation', 'VirtualBox', Provider::VirtualBox, false],
    'vmware' => ['VMware, Inc.', 'VMware Virtual Platform', Provider::Vmware, false],
    'parallels' => ['Parallels International GmbH.', 'Parallels ARM Virtual Machine', Provider::Parallels, false],
    'bare metal' => ['Dell Inc.', 'PowerEdge R650', Provider::Unknown, false],
]);

test('a local VM and a container are told apart', function () {
    $vm = Probe::parse("@@UNAME@@\nLinux\nx86_64\n@@VENDOR@@\nQEMU\n@@VIRT@@\nqemu\n@@END@@\n");
    $lxc = Probe::parse("@@UNAME@@\nLinux\nx86_64\n@@VIRT@@\nlxc\n@@END@@\n");
    $metal = Probe::parse("@@UNAME@@\nLinux\nx86_64\n@@VIRT@@\nnone\n@@END@@\n");
    $junk = Probe::parse("@@UNAME@@\nLinux\nx86_64\n@@VIRT@@\n\$(reboot)\n@@END@@\n");

    expect($vm->provider)->toBe(Provider::Qemu)->and($vm->isVirtualMachine())->toBeTrue()
        ->and($lxc->isContainer())->toBeTrue()->and($lxc->isVirtualMachine())->toBeFalse()
        ->and($metal->isVirtualMachine())->toBeFalse()->and($metal->isContainer())->toBeFalse()
        ->and($junk->virtualization)->toBeNull();
});

test('a probe answer that stops part way is an error, not "no sudo, no ufw"', function () {
    $cut = substr(sampleProbeOutput(), 0, (int) strpos(sampleProbeOutput(), '@@SUDO@@'));

    expect(fn () => Probe::parse($cut))->toThrow(SshException::class, 'stopped part way');
});

test('a cut-off or timed-out probe throws instead of guessing', function () {
    $session = new class implements Session
    {
        public bool $truncate = true;

        public function run(string $command, string $stdin = '', ?Closure $onOutput = null, int $timeoutSeconds = 60): CommandResult
        {
            return $this->truncate
                ? new CommandResult(0, sampleProbeOutput(), truncated: true)
                : new CommandResult(null, "@@STAT1@@\n", timedOut: true);
        }

        public function disconnect(): void {}
    };

    expect(fn () => Probe::run($session))->toThrow(SshException::class, 'cut off');

    $session->truncate = false;
    expect(fn () => MetricsProbe::run($session))->toThrow(SshException::class, 'timed out');
});

test('hostile numbers from a server become unknown, so facts and metrics still encode', function () {
    $facts = Probe::parse("@@UNAME@@\nLinux\nx86_64\n@@LOAD@@\n1e999 -1 NAN\n@@UPTIME@@\n-5 0\n@@DISK@@\n99999999999999999999 -1\n@@END@@\n");
    $metrics = MetricsProbe::parse("@@STAT1@@\ncpu 100 0 100 800\n@@STAT2@@\ncpu 50 0 50 -900\n@@MEM@@\nMemTotal: 1024 kB\nMemAvailable: 999999999 kB\n@@LOAD@@\n1e999 1 1\n@@UPTIME@@\nINF 1\n@@END@@\n");

    expect($facts->load1)->toBeNull()->and($facts->load5)->toBeNull()->and($facts->load15)->toBeNull()
        ->and($facts->uptimeSeconds)->toBeNull()->and($facts->diskTotalGb)->toBeNull()->and($facts->diskFreeGb)->toBeNull()
        ->and(json_encode($facts->toArray(), JSON_THROW_ON_ERROR))->toBeString()
        ->and($metrics->cpuPercent)->toBeNull()->and($metrics->load1)->toBeNull()->and($metrics->uptimeSeconds)->toBeNull()
        ->and($metrics->memoryUsedMb)->toBeNull()
        ->and(json_encode($metrics->toArray(), JSON_THROW_ON_ERROR))->toBeString();
});

test('the error for a probe that did not run quotes only a short, printable part of the answer', function () {
    try {
        Probe::parse("sh: \x1b[31mnot found\x07\n".str_repeat('x', 5_000_000));
        $this->fail('expected an exception');
    } catch (SshException $e) {
        expect(strlen($e->getMessage()))->toBeLessThan(300)
            ->and($e->getMessage())->toContain('sh: [31mnot found')->not->toContain("\x1b")->not->toContain("\x07");
    }
});

test('CPU use leaves out guest time, which /proc/stat already counts in user time', function () {
    // 50 user jiffies, all of them guest time, out of 100: 50%, not 60% (guest counted twice).
    $metrics = MetricsProbe::parse("@@STAT1@@\ncpu  0 0 0 0 0 0 0 0 0 0\n@@STAT2@@\ncpu  50 0 0 50 0 0 0 0 50 0\n@@END@@\n");

    expect($metrics->cpuPercent)->toBe(50.0);
});

test('metrics polls run no docker or sudo checks', function () {
    expect(MetricsProbe::script())->not->toContain('docker')->not->toContain('sudo')
        ->and(shellSyntaxOk(MetricsProbe::script()))->toBeTrue();
});

/**
 * Run one probe section with its absolute paths pointed at test files.
 *
 * @param  array<string, string>  $paths
 */
function runProbeSection(string $name, array $paths): string
{
    preg_match('/^echo @@'.$name.'@@;.*$/m', Probe::script(), $line);
    $process = proc_open(['sh', '-c', strtr($line[0], $paths)], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $output = (string) stream_get_contents($pipes[1]);
    proc_close($process);

    return trim(str_replace("@@{$name}@@", '', $output));
}

test('ufw counts as active from its own config, which a non-root user can read', function () {
    // `systemctl is-active ufw` only says the boot unit ran: it is "active" after `ufw disable` too.
    $conf = tempnam(sys_get_temp_dir(), 'ufw');

    file_put_contents($conf, "# comment\nENABLED=no\n");
    $disabled = runProbeSection('UFW', ['/etc/ufw/ufw.conf' => $conf]);
    file_put_contents($conf, "ENABLED=yes\n");
    $enabled = runProbeSection('UFW', ['/etc/ufw/ufw.conf' => $conf]);
    unlink($conf);

    expect($disabled)->toBe('inactive')->and($enabled)->toBe('active')
        ->and(runProbeSection('UFW', ['/etc/ufw/ufw.conf' => '/nonexistent/ufw.conf']))->toBe('inactive');
});

test('a commented-out unattended-upgrades line does not count as configured', function () {
    $conf = tempnam(sys_get_temp_dir(), 'apt');

    file_put_contents($conf, "// APT::Periodic::Unattended-Upgrade \"1\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n");
    $off = runProbeSection('UNATT', ['/etc/apt/apt.conf.d/20auto-upgrades' => $conf]);
    file_put_contents($conf, "APT::Periodic::Update-Package-Lists \"1\";\n  APT::Periodic::Unattended-Upgrade \"1\";\n");
    $on = runProbeSection('UNATT', ['/etc/apt/apt.conf.d/20auto-upgrades' => $conf]);
    unlink($conf);

    expect($off)->toBe('none')->and($on)->toBe('configured');
});

test('a newer installed kernel than the running one means a reboot is needed', function () {
    // Debian doesn't write /var/run/reboot-required; a new vmlinuz in /boot is the sign.
    $boot = sys_get_temp_dir().'/sc-boot-'.getmypid();
    is_dir($boot) || mkdir($boot);
    $running = trim((string) shell_exec('uname -r'));
    touch("{$boot}/vmlinuz-{$running}");
    $paths = ['/var/run/reboot-required' => '/nonexistent', '/boot/vmlinuz-' => "{$boot}/vmlinuz-", 's|^/boot/vmlinuz-||' => "s|^{$boot}/vmlinuz-||"];

    $current = runProbeSection('REBOOT', $paths);
    touch("{$boot}/vmlinuz-999.0.0-1-amd64");
    $newer = runProbeSection('REBOOT', $paths);
    array_map('unlink', glob("{$boot}/*") ?: []);
    rmdir($boot);

    expect($current)->toBe('no')->and($newer)->toBe('yes');
});

test('server strings in facts are short, printable, and known values where a list exists', function () {
    $facts = Probe::parse("@@OSREL@@\nPRETTY_NAME=\"Evil\x1b[2J ".str_repeat('x', 100_000)."\"\nID=\"deb\x07ian\"\n@@UNAME@@\nLinux\x00\nx86_64\n@@PKG@@\n<img src=x>\n@@DOCKER@@\nDocker version 1.0<script>, build x\n@@SSHD@@\npermitrootlogin <b>yes</b>\n@@END@@\n");

    expect(mb_strlen((string) $facts->osName))->toBeLessThanOrEqual(100)
        ->and($facts->osName)->not->toContain("\x1b")
        ->and($facts->osId)->toBe('debian')
        ->and($facts->kernel)->toBe('Linux')->and($facts->isLinux())->toBeTrue()
        ->and($facts->packageManager)->toBeNull()
        ->and($facts->dockerVersion)->toBe('1.0')
        ->and($facts->sshdRootLogin)->toBeNull();
});

test('extra sections must be keyed by name, not a plain list', function () {
    expect(fn () => Probe::script(['echo hi']))->toThrow(InvalidArgumentException::class, 'Invalid probe section name');
});

test('a metrics answer that is cut off throws instead of reading as all unknown', function (CommandResult $result) {
    $session = new class($result) implements Session
    {
        public function __construct(private CommandResult $result) {}

        public function run(string $command, string $stdin = '', ?Closure $onOutput = null, int $timeoutSeconds = 60): CommandResult
        {
            return $this->result;
        }

        public function disconnect(): void {}
    };

    expect(fn () => MetricsProbe::run($session))->toThrow(SshException::class, 'metrics probe was cut off');
})->with([
    'no end marker' => [new CommandResult(0, "@@STAT1@@\ncpu 1 2 3 4\n")],
    'truncated' => [new CommandResult(0, "@@STAT1@@\n@@END@@\n", truncated: true)],
    'not a shell' => [new CommandResult(127, "This account is currently not available.\n")],
]);

test('a complete metrics answer still parses through run()', function () {
    $server = (new FakeConnector)->on(MetricsProbe::MARKER, ["@@LOAD@@\n0.5 1 1\n@@END@@\n", 0]);
    $session = $server->connect(new Target('203.0.113.1', 22, 'root'), '203.0.113.1', Credentials::key(PrivateKey::generateEd25519()), fn () => null);

    expect(MetricsProbe::run($session)->load1)->toBe(0.5);
});
