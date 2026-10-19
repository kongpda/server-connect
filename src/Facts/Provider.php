<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Facts;

/**
 * Hosting provider inferred from the DMI vendor (/sys/class/dmi/id/sys_vendor):
 * a plain string match, no metadata endpoint call.
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
    case Unknown = 'unknown';

    public static function fromVendor(string $vendor): self
    {
        $vendor = strtolower($vendor);

        return match (true) {
            str_contains($vendor, 'digitalocean') => self::DigitalOcean,
            str_contains($vendor, 'hetzner') => self::Hetzner,
            str_contains($vendor, 'amazon') => self::Aws,
            str_contains($vendor, 'google') => self::Gcp,
            str_contains($vendor, 'microsoft') => self::Azure,
            str_contains($vendor, 'vultr') => self::Vultr,
            str_contains($vendor, 'linode'), str_contains($vendor, 'akamai') => self::Linode,
            str_contains($vendor, 'scaleway') => self::Scaleway,
            str_contains($vendor, 'oracle') => self::Oracle,
            str_contains($vendor, 'ovh') => self::Ovh,
            default => self::Unknown,
        };
    }
}
