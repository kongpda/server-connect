<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Phpseclib;

use phpseclib3\Exception\ConnectionClosedException;
use phpseclib3\Net\SSH2;

/**
 * phpseclib's SSH2 with the additions this package relies on:
 * reading the host key the server sent before its signature is checked
 * (so a hostile RSA key is refused before the expensive check), forgetting
 * the login credentials phpseclib keeps for reconnecting, a hard deadline for
 * channel reads, and clearing the exit status and stderr copy phpseclib keeps
 * between commands.
 *
 * @internal
 */
final class GuardedSsh2 extends SSH2
{
    private ?float $hardDeadline = null;

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
     * A wall-clock limit for channel reads, including phpseclib's own close
     * loop, which otherwise keeps reading while a server keeps sending. Past
     * it, the connection is dropped. Null turns it off.
     */
    public function setHardDeadline(?float $at): void
    {
        $this->hardDeadline = $at;
    }

    /**
     * Forget the previous command's exit status: phpseclib keeps it, so a
     * command that ends without one would report the last command's.
     */
    public function resetExitStatus(): void
    {
        \Closure::bind(function (): void {
            // phpseclib documents it as int, but starts it as null and checks for null.
            $this->exit_status = null; // @phpstan-ignore assign.propertyType
        }, $this, SSH2::class)();
    }

    /**
     * @param  int  $client_channel
     * @param  bool  $skip_extended
     * @return mixed
     */
    protected function get_channel_packet($client_channel, $skip_extended = false)
    {
        if ($this->hardDeadline !== null && microtime(true) > $this->hardDeadline) {
            $this->hardDeadline = null;
            $this->disconnect();

            throw new ConnectionClosedException('The command ran past its deadline; the connection was dropped.');
        }

        try {
            return parent::get_channel_packet($client_channel, $skip_extended);
        } finally {
            // phpseclib also copies every stderr chunk into a log it never trims. The
            // session already gets stderr through read(), so drop the copy.
            \Closure::bind(function (): void {
                $this->stdErrorLog = '';
            }, $this, SSH2::class)();
        }
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
