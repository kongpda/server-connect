<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Phpseclib;

use phpseclib3\Net\SSH2;

/**
 * phpseclib's SSH2 with two additions this package relies on:
 * reading the host key the server sent before its signature is checked
 * (so a hostile RSA key is refused before the expensive check), and
 * forgetting the login credentials phpseclib keeps for reconnecting.
 *
 * @internal
 */
final class GuardedSsh2 extends SSH2
{
    /**
     * The raw host key blob from the key exchange, unverified. Call after
     * the handshake (getServerIdentification() runs it).
     */
    public function unverifiedHostKeyBlob(): ?string
    {
        $read = function (): mixed {
            /** @phpstan-ignore property.private */
            return $this->server_public_host_key;
        };
        $blob = \Closure::bind($read, $this, SSH2::class)();

        return is_string($blob) && $blob !== '' ? $blob : null;
    }

    /**
     * Drop the stored password or key, so it can't leak through a dump and
     * phpseclib can't silently reconnect and send it again.
     */
    public function forgetCredentials(): void
    {
        $this->auth = [];
    }

    /**
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['class' => self::class];
    }

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        throw new \LogicException('SSH connections must not be serialized.');
    }
}
