<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect;

use Closure;

/**
 * Resolves a host and refuses obviously wrong targets before connecting:
 * loopback, unspecified, link-local (cloud metadata), multicast and the
 * caller's own addresses. Private ranges (10/8, 192.168/16, 100.64/10…) are
 * allowed: a VPS on a private network or a tailnet is a normal target.
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
     */
    public function __construct(
        private readonly bool $allowLocal = false,
        private readonly array $ownHosts = [],
        ?Closure $lookup = null,
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

        // IPv4-mapped IPv6 (::ffff:a.b.c.d) is judged as the IPv4 address.
        if (strlen($packed) === 16 && str_starts_with($packed, str_repeat("\0", 10)."\xff\xff")) {
            $packed = substr($packed, 12);
        }

        $normalized = (string) inet_ntop($packed);
        $loopback = 'it is this machine (loopback).';
        $self = 'it is this application\'s own server.';

        if (strlen($packed) === 4) {
            $first = ord($packed[0]);
            $second = ord($packed[1]);

            return match (true) {
                $first === 127 => $this->allowLocal ? null : $loopback,
                $first === 0 => 'it is an unspecified address.',
                $first === 169 && $second === 254 => 'it is a link-local address (cloud metadata lives there).',
                $first >= 224 => 'it is a multicast or reserved address.',
                in_array($normalized, $own, true) => $self,
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
            in_array($normalized, $own, true) => $self,
            default => null,
        };
    }

    /**
     * @return list<string>
     */
    private function ownAddresses(): array
    {
        $addresses = [];

        foreach ($this->ownHosts as $host) {
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
    private static function dnsLookup(string $host): array
    {
        if (preg_match('/^[A-Za-z0-9.-]+$/', $host) !== 1) {
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
