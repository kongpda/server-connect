<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Phpseclib;

use Closure;
use Kongpda\ServerConnect\Connector;
use Kongpda\ServerConnect\Credentials;
use Kongpda\ServerConnect\HostKey;
use Kongpda\ServerConnect\InvalidHostKey;
use Kongpda\ServerConnect\Session;
use Kongpda\ServerConnect\SshException;
use Kongpda\ServerConnect\Target;
use phpseclib3\Net\SSH2;
use Throwable;

/**
 * Real SSH with phpseclib.
 *
 * - The TCP connect and the handshake share one timeout (8 s by default),
 *   and the server's identification line must arrive within it, in the
 *   first 8 KB.
 * - Only modern algorithms are offered: curve25519/ECDH key exchange,
 *   AEAD or CTR ciphers with SHA-2 MACs, and Ed25519, ECDSA or
 *   SHA-2 RSA host keys (Ed25519 preferred, so the pinned key is the same
 *   on every connection).
 * - The host key is checked for size before its signature is verified,
 *   and shown to the caller before authentication.
 * - The password or key is forgotten once the login finishes.
 */
final class PhpseclibConnector implements Connector
{
    public const HOST_KEY_PREFERENCE = [
        'ssh-ed25519',
        'ecdsa-sha2-nistp256',
        'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521',
        'rsa-sha2-512',
        'rsa-sha2-256',
    ];

    public const KEX_PREFERENCE = [
        'curve25519-sha256',
        'curve25519-sha256@libssh.org',
        'ecdh-sha2-nistp256',
        'ecdh-sha2-nistp384',
        'ecdh-sha2-nistp521',
    ];

    public const CIPHER_PREFERENCE = [
        'chacha20-poly1305@openssh.com',
        'aes256-gcm@openssh.com',
        'aes128-gcm@openssh.com',
        'aes128-ctr',
    ];

    public const MAC_PREFERENCE = [
        'hmac-sha2-256-etm@openssh.com',
        'hmac-sha2-512-etm@openssh.com',
        'hmac-sha2-256',
        'hmac-sha2-512',
    ];

    /**
     * How much the server may send before its identification line.
     */
    private const MAX_BANNER_BYTES = 8192;

    private readonly int $connectTimeoutSeconds;

    private readonly int $keepAliveSeconds;

    /**
     * @param  int  $connectTimeoutSeconds  for the TCP connect and the handshake (at least 1)
     * @param  int  $minRsaBits  refuse RSA host keys shorter than this
     * @param  int  $maxOutputBytes  output kept per command; the rest still streams to $onOutput
     */
    public function __construct(
        int $connectTimeoutSeconds = 8,
        int $keepAliveSeconds = 5,
        private readonly int $minRsaBits = 2048,
        private readonly int $maxOutputBytes = PhpseclibSession::DEFAULT_MAX_OUTPUT_BYTES,
    ) {
        $this->connectTimeoutSeconds = max(1, $connectTimeoutSeconds);
        $this->keepAliveSeconds = max(1, $keepAliveSeconds);
    }

    public function connect(Target $target, string $address, Credentials $credentials, Closure $verifyHostKey): Session
    {
        $where = (string) $target;
        [$ssh, $hostKey] = $this->open($target, $address);

        // Throws to refuse. Nothing has been sent to the server yet.
        try {
            $verifyHostKey($hostKey);
        } catch (Throwable $exception) {
            $ssh->disconnect();

            throw $exception;
        }

        try {
            $key = $credentials->privateKey();
            $loggedIn = $key === null
                ? $ssh->login($target->user, $credentials->passwordValue())
                : $ssh->login($target->user, $key->phpseclib());
        } catch (Throwable) {
            // phpseclib's messages don't contain credentials; drop them anyway.
            if (! $ssh->isConnected()) {
                throw new SshException("The connection to {$where} dropped while logging in. Try again; if it keeps happening, check the server's sshd log.", SshException::DROPPED);
            }

            $ssh->disconnect();

            throw new SshException("Logging in to {$where} failed before authentication finished. Check that sshd allows this user.", SshException::AUTHENTICATION);
        } finally {
            $ssh->forgetCredentials();
        }

        if (! $loggedIn) {
            $ssh->disconnect();

            throw new SshException($credentials->isPassword()
                ? "The server refused the password for {$target->user}. Check it, and that the server allows password logins for this user (PasswordAuthentication yes)."
                : "The server refused the key for {$target->user}. Add its public key to ~/.ssh/authorized_keys of {$target->user} on the server, or use the one-time password option.",
                SshException::AUTHENTICATION);
        }

        return new PhpseclibSession($ssh, $where, $this->maxOutputBytes);
    }

    public function scanHostKey(Target $target, string $address): HostKey
    {
        [$ssh, $hostKey] = $this->open($target, $address);
        $ssh->disconnect();

        return $hostKey;
    }

    /**
     * Connect, check the host key's size, then verify the server's signature
     * over the key exchange.
     *
     * @return array{0: GuardedSsh2, 1: HostKey}
     */
    private function open(Target $target, string $address): array
    {
        $where = (string) $target;
        $deadline = microtime(true) + $this->connectTimeoutSeconds;
        $socket = $this->openSocket($address, $target->port, $where, $deadline);

        try {
            $ssh = new GuardedSsh2($socket, $target->port, max(1, (int) ceil($deadline - microtime(true))));
            $ssh->setKeepAlive($this->keepAliveSeconds);
            $ssh->setPreferredAlgorithms(self::algorithms());
            $ssh->getServerIdentification(); // runs the handshake
            $blob = $ssh->unverifiedHostKeyBlob();
        } catch (Throwable $exception) {
            self::close($socket);

            throw new SshException(self::describeConnectFailure($where, $exception->getMessage()), SshException::UNREACHABLE);
        }

        if ($blob === null) {
            self::close($socket);

            throw new SshException("{$where} didn't finish the SSH handshake. Check that the address points at an SSH server that supports modern algorithms (OpenSSH 6.5 or newer).", SshException::UNREACHABLE);
        }

        try {
            // Size limits first: a huge RSA key would make the signature check take hours.
            $unverified = HostKey::fromBlob($blob, null, $this->minRsaBits);
            $presented = $ssh->getServerPublicHostKey();
        } catch (InvalidHostKey $exception) {
            $ssh->disconnect();

            throw new SshException("{$where} sent a host key this package won't use: ".$exception->getMessage(), SshException::UNREACHABLE);
        } catch (Throwable) {
            $ssh->disconnect();

            throw new SshException("{$where} didn't prove it holds its host key.", SshException::UNREACHABLE);
        }

        if (! is_string($presented)) {
            $ssh->disconnect();

            throw new SshException("{$where} didn't prove it holds its host key. Check that the address points at an SSH server.", SshException::UNREACHABLE);
        }

        return [$ssh, $unverified];
    }

    /**
     * Open the TCP connection and wait, within the deadline, until the
     * server's identification line ("SSH-2.0-…") is waiting in the first
     * MAX_BANNER_BYTES. The bytes are only peeked at; phpseclib reads them.
     *
     * @return resource
     */
    private function openSocket(string $address, int $port, string $where, float $deadline)
    {
        $host = str_contains($address, ':') ? '['.trim($address, '[]').']' : $address;
        $errno = 0;
        $errstr = '';

        set_error_handler(fn (): bool => true, E_WARNING | E_NOTICE);

        try {
            $socket = stream_socket_client("tcp://{$host}:{$port}", $errno, $errstr, max(1, $deadline - microtime(true)));
        } finally {
            restore_error_handler();
        }

        if ($socket === false) {
            throw new SshException(self::describeConnectFailure($where, $errstr !== '' ? $errstr : 'timed out'), SshException::UNREACHABLE);
        }

        $seen = -1;

        while (true) {
            $remaining = $deadline - microtime(true);

            if ($remaining <= 0) {
                self::close($socket);

                throw new SshException("Connecting to {$where} timed out waiting for the SSH greeting. Check that the address points at an SSH server.", SshException::UNREACHABLE);
            }

            $read = [$socket];
            $write = $except = null;
            $ready = @stream_select($read, $write, $except, 0, (int) (min($remaining, 0.25) * 1_000_000));

            if ($ready === false) {
                self::close($socket);

                throw new SshException("The connection to {$where} failed while waiting for the SSH greeting.", SshException::UNREACHABLE);
            }

            if ($ready === 0) {
                continue;
            }

            $peeked = stream_socket_recvfrom($socket, self::MAX_BANNER_BYTES, STREAM_PEEK);

            if ($peeked === false || $peeked === '') {
                self::close($socket);

                throw new SshException("{$where} closed the connection before greeting. Is this an SSH server?", SshException::UNREACHABLE);
            }

            $start = str_starts_with($peeked, 'SSH-') ? 0 : strpos($peeked, "\nSSH-");

            if ($start !== false && strpos($peeked, "\n", $start + 1) !== false) {
                return $socket;
            }

            if (strlen($peeked) >= self::MAX_BANNER_BYTES) {
                self::close($socket);

                throw new SshException("{$where} sent too much before its SSH greeting. Is this an SSH server?", SshException::UNREACHABLE);
            }

            if (strlen($peeked) === $seen) {
                usleep(50_000); // nothing new yet; the data already there keeps the socket readable
            }

            $seen = strlen($peeked);
        }
    }

    /**
     * @return array<string, mixed>
     */
    private static function algorithms(): array
    {
        $direction = [
            'crypt' => array_values(array_intersect(self::CIPHER_PREFERENCE, SSH2::getSupportedEncryptionAlgorithms())),
            'mac' => array_values(array_intersect(self::MAC_PREFERENCE, SSH2::getSupportedMACAlgorithms())),
            'comp' => ['none'],
        ];

        return [
            'kex' => array_values(array_intersect(self::KEX_PREFERENCE, SSH2::getSupportedKEXAlgorithms())),
            'hostkey' => array_values(array_intersect(self::HOST_KEY_PREFERENCE, SSH2::getSupportedHostKeyAlgorithms())),
            'client_to_server' => $direction,
            'server_to_client' => $direction,
        ];
    }

    /**
     * @param  resource  $socket
     */
    private static function close($socket): void
    {
        if (is_resource($socket)) {
            fclose($socket);
        }
    }

    private static function describeConnectFailure(string $where, string $message): string
    {
        $message = trim($message);
        $lower = strtolower($message);

        return match (true) {
            str_contains($lower, 'refused') => "{$where} refused the connection. Is sshd running, and is the port right?",
            str_contains($lower, 'timed out'), str_contains($lower, 'timeout') => "Connecting to {$where} timed out. Check the address, and that the server's firewall allows SSH from this machine.",
            str_contains($lower, 'no route'), str_contains($lower, 'unreachable') => "There is no route to {$where}. Check the address.",
            str_contains($lower, 'no algorithms'), str_contains($lower, 'no compatible') => "{$where} doesn't support the modern SSH algorithms this package requires (OpenSSH 6.5 or newer does).",
            default => "Can't connect to {$where}: ".mb_substr((string) preg_replace('/[\x00-\x1f\x7f]/', '', $message), 0, 200),
        };
    }
}
