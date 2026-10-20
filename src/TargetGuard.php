<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect;

use Closure;

/**
 * Resolves a host and refuses targets an app shouldn't connect to:
 *
 * - always: unspecified, link-local (cloud metadata), multicast, reserved
 *   and special-purpose ranges;
 * - unless $allowLocal: loopback, this machine's own interface addresses
 *   and the hosts in $ownHosts;
 * - unless $allowPrivate: private networks (10/8, 172.16/12, 192.168/16,
 *   100.64/10 shared/CGNAT, which holds some clouds' metadata, IPv6 ULA
 *   fc00::/7, which holds AWS's IPv6 metadata, and site-local fec0::/10).
 *
 * IPv4 addresses wrapped in IPv6 (mapped, translated, compatible, NAT64,
 * 6to4) are judged as IPv4. In a multi-tenant app, leave $allowPrivate off,
 * or users can reach your internal network through it. A single-user,
 * self-hosted app may turn it on to reach VMs on its own LAN or tailnet.
 *
 * Connect to the address resolve() returns, so a DNS answer that changes
 * between the check and the connection can't slip past it.
 */
final class TargetGuard
{
    /**
     * @var Closure(string): list<string>
     */
    private Closure $lookup;

    /**
     * @param  bool  $allowLocal  allow loopback and $ownHosts (a runner on this very box)
     * @param  list<string>  $ownHosts  host names or IPs this application is reached at
     * @param  (Closure(string): list<string>)|null  $lookup  resolver, for tests
     * @param  bool  $allowPrivate  allow private, CGNAT and ULA ranges
     * @param  list<string>|null  $interfaceAddresses  this machine's addresses (null: read them), for tests
     */
    public function __construct(
        private readonly bool $allowLocal = false,
        private readonly array $ownHosts = [],
        ?Closure $lookup = null,
        private readonly bool $allowPrivate = false,
        private readonly ?array $interfaceAddresses = null,
    ) {
        $this->lookup = $lookup ?? self::dnsLookup(...);
    }

    /**
     * @throws SshException
     */
    public function resolve(string $host): string
    {
        $host = trim($host, '[] ');
        $addresses = filter_var($host, FILTER_VALIDATE_IP) !== false ? [$host] : ($this->lookup)($host);

        if ($addresses === []) {
            throw new SshException("{$host} doesn't resolve to an address. Check the host name, or use the server's IP address.", SshException::UNREACHABLE);
        }

        $own = $this->allowLocal ? [] : $this->ownAddresses();

        foreach ($addresses as $address) {
            $problem = $this->problemWith($address, $own);

            if ($problem !== null) {
                throw new SshException("Refusing to connect to {$host} ({$address}): {$problem}", SshException::REFUSED_TARGET);
            }
        }

        foreach ($addresses as $address) {
            if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                return $address;
            }
        }

        return $addresses[0];
    }

    /**
     * @param  list<string>  $own
     */
    private function problemWith(string $address, array $own): ?string
    {
        $packed = @inet_pton($address);

        if ($packed === false) {
            return 'it is not a valid IP address.';
        }

        // An IPv4 address wrapped in IPv6 is judged as the IPv4 address.
        if (strlen($packed) === 16) {
            $packed = self::embeddedIpv4($packed) ?? $packed;
        }

        $normalized = (string) inet_ntop($packed);
        $loopback = 'it is this machine (loopback).';
        $self = 'it is this application\'s own server.';

        $private = $this->allowPrivate ? null : 'it is a private network address. This app only connects to public addresses.';

        if (strlen($packed) === 4) {
            $first = ord($packed[0]);
            $second = ord($packed[1]);
            $third = ord($packed[2]);

            return match (true) {
                $first === 127 => $this->allowLocal ? null : $loopback,
                $first === 0 => 'it is an unspecified address.',
                $first === 169 && $second === 254 => 'it is a link-local address (cloud metadata lives there).',
                $first >= 224 => 'it is a multicast or reserved address.',
                $first === 192 && $second === 0 && $third === 0 => 'it is a special-purpose address.',
                $first === 198 && ($second & 0xFE) === 18 => 'it is a benchmarking address.',
                in_array($normalized, $own, true) => $self,
                $first === 10,
                $first === 172 && ($second & 0xF0) === 16,
                $first === 192 && $second === 168,
                $first === 100 && ($second & 0xC0) === 64 => $private,
                default => null,
            };
        }

        $first = ord($packed[0]);
        $second = ord($packed[1]);

        return match (true) {
            $packed === str_repeat("\0", 15)."\1" => $this->allowLocal ? null : $loopback,
            $packed === str_repeat("\0", 16) => 'it is an unspecified address.',
            $first === 0xFE && ($second & 0xC0) === 0x80 => 'it is a link-local address.',
            $first === 0xFF => 'it is a multicast address.',
            str_starts_with($packed, "\x00\x64\xff\x9b\x00\x01") => 'it is a local-use NAT64 address.',
            str_starts_with($packed, "\x01\x00".str_repeat("\0", 6)) => 'it is a discard-only address.',
            in_array($normalized, $own, true) => $self,
            ($first & 0xFE) === 0xFC,
            $first === 0xFE && ($second & 0xC0) === 0xC0 => $private,
            default => null,
        };
    }

    /**
     * The IPv4 address inside an IPv4-mapped (::ffff:0:0/96), translated
     * (::ffff:0:0:0/96), IPv4-compatible (::/96), NAT64 (64:ff9b::/96) or
     * 6to4 (2002::/16) address.
     */
    private static function embeddedIpv4(string $packed): ?string
    {
        $prefix12 = substr($packed, 0, 12);

        if ($prefix12 === str_repeat("\0", 10)."\xff\xff"
            || $prefix12 === str_repeat("\0", 8)."\xff\xff\0\0"
            || $prefix12 === "\x00\x64\xff\x9b".str_repeat("\0", 8)) {
            return substr($packed, 12);
        }

        // ::/96 except :: and ::1, which are judged as IPv6.
        if ($prefix12 === str_repeat("\0", 12) && ltrim(substr($packed, 12), "\0") !== '' && substr($packed, 12) !== "\0\0\0\1") {
            return substr($packed, 12);
        }

        if (str_starts_with($packed, "\x20\x02")) {
            return substr($packed, 2, 4);
        }

        return null;
    }

    /**
     * @return list<string>
     */
    private function ownAddresses(): array
    {
        $addresses = [];

        foreach ($this->interfaceAddresses ?? self::localInterfaceAddresses() as $address) {
            $packed = @inet_pton($address);

            if ($packed !== false) {
                $addresses[] = (string) inet_ntop($packed);
            }
        }

        foreach ($this->ownHosts as $host) {
            $host = trim($host);

            if ($host === '' || $host === 'localhost') {
                continue;
            }

            foreach (filter_var($host, FILTER_VALIDATE_IP) !== false ? [$host] : ($this->lookup)($host) as $address) {
                $packed = @inet_pton($address);

                if ($packed !== false) {
                    $addresses[] = (string) inet_ntop($packed);
                }
            }
        }

        return $addresses;
    }

    /**
     * @return list<string>
     */
    private static function localInterfaceAddresses(): array
    {
        $addresses = [];

        foreach (function_exists('net_get_interfaces') ? (net_get_interfaces() ?: []) : [] as $interface) {
            foreach ($interface['unicast'] ?? [] as $unicast) {
                if (isset($unicast['address']) && is_string($unicast['address'])) {
                    $addresses[] = $unicast['address'];
                }
            }
        }

        return $addresses;
    }

    /**
     * @return list<string>
     */
    private static function dnsLookup(string $host): array
    {
        if (preg_match('/\A[A-Za-z0-9.-]+\z/', $host) !== 1) {
            return [];
        }

        $addresses = gethostbynamel($host) ?: [];

        foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $record) {
            if (isset($record['ipv6']) && is_string($record['ipv6'])) {
                $addresses[] = $record['ipv6'];
            }
        }

        return array_values(array_unique($addresses));
    }
}
