<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Facts;

/**
 * A read-only snapshot of a server from one probe. A field the probe couldn't
 * read is null (never 0, so "unknown" can't pass for "none").
 */
final readonly class ServerFacts
{
    /**
     * @param  array<string, string>  $extra  output of caller-supplied sections, by name
     */
    public function __construct(
        public string $kernel,
        public ?string $arch,
        public ?string $osId,
        public ?string $osVersion,
        public ?string $osName,
        public ?string $osLike,
        public Provider $provider,
        public ?int $cpuCount,
        public ?int $memoryTotalMb,
        public ?int $memoryAvailableMb,
        public ?int $swapTotalMb,
        public ?float $diskTotalGb,
        public ?float $diskFreeGb,
        public ?float $load1,
        public ?float $load5,
        public ?float $load15,
        public ?int $uptimeSeconds,
        public bool $isRoot,
        /** "root", "yes" (passwordless sudo) or "no" */
        public string $sudo,
        public bool $systemd,
        public bool $curl,
        public ?string $packageManager,
        public bool $dockerInstalled,
        public ?string $dockerVersion,
        public bool $dockerActive,
        /** "ok", "sudo", "denied" or "unknown" */
        public string $dockerAccess,
        public bool $rebootRequired,
        public bool $ufwActive,
        public bool $fail2banActive,
        public bool $unattendedUpgrades,
        public bool $swapPresent,
        public ?bool $sshdPasswordAuth,
        public ?string $sshdRootLogin,
        public bool $dpkgLocked,
        public array $extra = [],
        /**
         * systemd-detect-virt's answer: "none" on bare metal, a hypervisor
         * ("kvm", "qemu", "oracle" for VirtualBox, "vmware", "microsoft",
         * "parallels", "apple", "xen") or a container ("lxc", "docker",
         * "podman", "wsl"…). Null when the server has no systemd-detect-virt.
         */
        public ?string $virtualization = null,
    ) {}

    public function isLinux(): bool
    {
        return strtolower($this->kernel) === 'linux';
    }

    /**
     * "x86_64" or "aarch64" (normalized from amd64/arm64), or null when unsupported or unknown.
     */
    public function normalizedArch(): ?string
    {
        return match (strtolower((string) $this->arch)) {
            'x86_64', 'amd64' => 'x86_64',
            'aarch64', 'arm64' => 'aarch64',
            default => null,
        };
    }

    /**
     * A hypervisor guest: a cloud VPS or a VM of your own. Null when unknown.
     */
    public function isVirtualMachine(): ?bool
    {
        return match ($this->virtualization) {
            null => null,
            'none' => false,
            default => ! $this->isContainer(),
        };
    }

    /**
     * A container (LXC, Docker, Podman, systemd-nspawn, WSL, OpenVZ). Docker,
     * swap and firewall changes there usually need the host's help.
     */
    public function isContainer(): bool
    {
        return in_array($this->virtualization, ['lxc', 'lxc-libvirt', 'docker', 'podman', 'systemd-nspawn', 'rkt', 'wsl', 'openvz', 'proot', 'pouch', 'container-other'], true);
    }

    public function canBecomeRoot(): bool
    {
        return $this->sudo === 'root' || $this->sudo === 'yes';
    }

    public function isDebianLike(): bool
    {
        return in_array($this->osId, ['ubuntu', 'debian'], true)
            || str_contains(' '.$this->osLike.' ', ' debian ')
            || str_contains(' '.$this->osLike.' ', ' ubuntu ');
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'kernel' => $this->kernel,
            'arch' => $this->arch,
            'os_id' => $this->osId,
            'os_version' => $this->osVersion,
            'os_name' => $this->osName,
            'provider' => $this->provider->value,
            'virtualization' => $this->virtualization,
            'cpu_count' => $this->cpuCount,
            'memory_total_mb' => $this->memoryTotalMb,
            'memory_available_mb' => $this->memoryAvailableMb,
            'swap_total_mb' => $this->swapTotalMb,
            'disk_total_gb' => $this->diskTotalGb,
            'disk_free_gb' => $this->diskFreeGb,
            'load_1' => $this->load1,
            'load_5' => $this->load5,
            'load_15' => $this->load15,
            'uptime_seconds' => $this->uptimeSeconds,
            'is_root' => $this->isRoot,
            'sudo' => $this->sudo,
            'systemd' => $this->systemd,
            'curl' => $this->curl,
            'package_manager' => $this->packageManager,
            'docker_installed' => $this->dockerInstalled,
            'docker_version' => $this->dockerVersion,
            'docker_active' => $this->dockerActive,
            'docker_access' => $this->dockerAccess,
            'reboot_required' => $this->rebootRequired,
            'ufw_active' => $this->ufwActive,
            'fail2ban_active' => $this->fail2banActive,
            'unattended_upgrades' => $this->unattendedUpgrades,
            'swap_present' => $this->swapPresent,
            'sshd_password_auth' => $this->sshdPasswordAuth,
            'sshd_root_login' => $this->sshdRootLogin,
            'dpkg_locked' => $this->dpkgLocked,
        ];
    }
}
