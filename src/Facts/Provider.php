<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Facts;

/**
 * Where the server runs, inferred from DMI (/sys/class/dmi/id/sys_vendor and
 * product_name): a plain string match, no metadata endpoint call.
 *
 * Cloud cases name the provider. The other cases name the hypervisor of a
 * machine you run yourself (a local or home-lab VM). Qemu is any QEMU/KVM
 * guest that doesn't name its host: Proxmox, libvirt, Multipass, UTM, Lima,
 * and also some smaller VPS hosts, so it doesn't prove the VM is local.
 */
enum Provider: string
{
    case DigitalOcean = 'digitalocean';
    case Hetzner = 'hetzner';
    case Aws = 'aws';
    case Gcp = 'gcp';
    case Azure = 'azure';
    case Vultr = 'vultr';
    case Linode = 'linode';
    case Scaleway = 'scaleway';
    case Oracle = 'oracle';
    case Ovh = 'ovh';
    case Qemu = 'qemu';
    case VirtualBox = 'virtualbox';
    case Vmware = 'vmware';
    case Parallels = 'parallels';
    case Unknown = 'unknown';

    public static function fromVendor(string $vendor): self
    {
        return self::fromDmi($vendor);
    }

    public static function fromDmi(string $vendor, string $product = ''): self
    {
        $vendor = strtolower(trim($vendor));
        $product = strtolower(trim($product));

        return match (true) {
            str_contains($vendor, 'digitalocean') => self::DigitalOcean,
            str_contains($vendor, 'hetzner') => self::Hetzner,
            str_contains($vendor, 'amazon') => self::Aws,
            str_contains($vendor, 'google') => self::Gcp,
            // Hyper-V guests report Microsoft too; they count as Azure here.
            str_contains($vendor, 'microsoft') => self::Azure,
            str_contains($vendor, 'vultr') => self::Vultr,
            str_contains($vendor, 'linode'), str_contains($vendor, 'akamai') => self::Linode,
            str_contains($vendor, 'scaleway') => self::Scaleway,
            // VirtualBox reports "innotek GmbH" (older) or "Oracle Corporation" with product "VirtualBox".
            str_contains($vendor, 'innotek'), str_contains($product, 'virtualbox') => self::VirtualBox,
            str_contains($vendor, 'oracle') => self::Oracle,
            str_contains($vendor, 'ovh') => self::Ovh,
            str_contains($vendor, 'vmware') => self::Vmware,
            str_contains($vendor, 'parallels') => self::Parallels,
            str_contains($vendor, 'qemu') => self::Qemu,
            default => self::Unknown,
        };
    }

    /**
     * A known public cloud, as opposed to a VM you run yourself or an unknown host.
     */
    public function isCloud(): bool
    {
        return ! in_array($this, [self::Qemu, self::VirtualBox, self::Vmware, self::Parallels, self::Unknown], true);
    }
}
