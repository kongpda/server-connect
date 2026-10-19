<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Phpseclib;

use Closure;
use Kongpda\ServerConnect\Connector;
use Kongpda\ServerConnect\Credentials;
use Kongpda\ServerConnect\HostKey;
use Kongpda\ServerConnect\Session;
use Kongpda\ServerConnect\SshException;
use Kongpda\ServerConnect\Target;
use phpseclib3\Net\SSH2;
use Throwable;

/**
 * Real SSH with phpseclib: an 8 s connect timeout, keepalives every 5 s, the
 * host key checked before authentication, and Ed25519 host keys preferred so
 * the key that gets pinned is the same on every connection.
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
        'ssh-rsa',
    ];

    public function __construct(
        private readonly int $connectTimeoutSeconds = 8,
        private readonly int $keepAliveSeconds = 5,
    ) {}

    public function connect(Target $target, string $address, Credentials $credentials, Closure $verifyHostKey): Session
    {
        $where = (string) $target;
        [$ssh, $hostKey] = $this->open($target, $address);

        // Throws to refuse. Nothing has been sent to the server yet.
        $verifyHostKey($hostKey);

        try {
            $key = $credentials->privateKey();
            $loggedIn = $key === null
                ? $ssh->login($target->user, $credentials->passwordValue())
                : $ssh->login($target->user, $key->phpseclib());
        } catch (Throwable) {
            // phpseclib's messages don't contain credentials; drop them anyway.
            throw new SshException("Logging in to {$where} failed before authentication finished. Check that sshd allows this user.", SshException::AUTHENTICATION);
        }

        if (! $loggedIn) {
            throw new SshException($credentials->isPassword()
                ? "The server refused the password for {$target->user}. Check it, and that the server allows password logins for this user (PasswordAuthentication yes)."
                : "The server refused the key for {$target->user}. Add its public key to ~/.ssh/authorized_keys of {$target->user} on the server, or use the one-time password option.",
                SshException::AUTHENTICATION);
        }

        return new PhpseclibSession($ssh, $where);
    }

    public function scanHostKey(Target $target, string $address): HostKey
    {
        [$ssh, $hostKey] = $this->open($target, $address);
        $ssh->disconnect();

        return $hostKey;
    }

    /**
     * Connect and verify the server's signature over the key exchange.
     *
     * @return array{0: SSH2, 1: HostKey}
     */
    private function open(Target $target, string $address): array
    {
        $where = (string) $target;

        // fsockopen() reports a refused or timed-out connection as a PHP warning too: keep it
        // out of the caller's error handler and use it as the exception message instead.
        $warning = null;
        set_error_handler(function (int $level, string $message) use (&$warning): bool {
            $warning = $message;

            return true;
        }, E_WARNING | E_NOTICE);

        try {
            $ssh = new SSH2($address, $target->port, $this->connectTimeoutSeconds);
            $ssh->setTimeout($this->connectTimeoutSeconds);
            $ssh->setKeepAlive($this->keepAliveSeconds);
            $supported = SSH2::getSupportedHostKeyAlgorithms();
            $ssh->setPreferredAlgorithms(['hostkey' => array_values(array_intersect(self::HOST_KEY_PREFERENCE, $supported))]);
            $presented = $ssh->getServerPublicHostKey();
        } catch (Throwable $exception) {
            throw new SshException(self::describeConnectFailure($where, $exception->getMessage().' '.$warning), SshException::UNREACHABLE);
        } finally {
            restore_error_handler();
        }

        if (! is_string($presented)) {
            throw new SshException("{$where} didn't prove it holds its host key. Check that the address points at an SSH server.", SshException::UNREACHABLE);
        }

        try {
            return [$ssh, HostKey::parse($presented)];
        } catch (Throwable) {
            throw new SshException("{$where} sent a host key that can't be read.", SshException::UNREACHABLE);
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
            default => "Can't connect to {$where}: ".mb_substr($message, 0, 200),
        };
    }
}
