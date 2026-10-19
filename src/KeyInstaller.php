<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect;

use Closure;
use SensitiveParameter;

/**
 * Installs a public key with a password used once, then proves the key works.
 *
 * The password only lives in memory for this call. The key travels on stdin
 * to a fixed, idempotent script: umask 077, ~/.ssh 0700 and
 * authorized_keys 0600, a missing trailing newline repaired before
 * appending, the key added only once, SELinux labels restored, and an OK
 * marker printed at the end. Then a second connection logs in with the key.
 */
final class KeyInstaller
{
    public const MARKER = 'server-connect:install-key';

    public const OK_MARKER = 'SC_KEY_OK';

    public const VERIFY_MARKER = 'SC_VERIFY_OK';

    public const SCRIPT = '# '.self::MARKER."\n"
        .'umask 077; D="$HOME/.ssh"; F="$D/authorized_keys"; IFS= read -r K || [ -n "$K" ]; '
        .'[ -n "$K" ] || { echo "no key received" >&2; exit 1; }; '
        .'mkdir -p "$D" && chmod 700 "$D" && touch "$F" && chmod 600 "$F" || exit 1; '
        .'if ! grep -qxF "$K" "$F"; then if [ -s "$F" ] && [ -n "$(tail -c 1 "$F")" ]; then echo >> "$F"; fi; printf "%s\n" "$K" >> "$F" || exit 1; fi; '
        .'if command -v restorecon >/dev/null 2>&1; then restorecon -R "$D" >/dev/null 2>&1 || true; fi; '
        .'echo '.self::OK_MARKER;

    public function __construct(private readonly Connector $connector) {}

    /**
     * @param  Closure(HostKey): void  $verifyHostKey
     *
     * @throws SshException
     */
    public function install(Target $target, string $address, #[SensitiveParameter] string $password, PrivateKey $key, Closure $verifyHostKey, int $timeoutSeconds = 45): void
    {
        if ($password === '') {
            throw new SshException('Enter the server password.', SshException::AUTHENTICATION);
        }

        if (! self::isPublicKeyLine($key->publicLine)) {
            throw new SshException('The public key is not a plain OpenSSH key line.', SshException::AUTHENTICATION);
        }

        $session = $this->connector->connect($target, $address, Credentials::password($password), $verifyHostKey);

        try {
            $result = $session->run('sh -c '.Shell\Shims::quote(self::SCRIPT), $key->publicLine."\n", null, $timeoutSeconds);
        } finally {
            $session->disconnect();
        }

        if ($result->timedOut) {
            throw new SshException('The server didn\'t finish installing the key in time.', SshException::TIMEOUT);
        }

        if (! $result->successful() || ! in_array(self::OK_MARKER, array_map('trim', explode("\n", $result->output)), true)) {
            $first = trim((string) strtok($result->output, "\n"));

            throw new SshException('Installing the key failed'.($first !== '' ? ': '.mb_substr($first, 0, 200) : '.').' Check that the home directory of '.$target->user.' is writable.', SshException::AUTHENTICATION);
        }

        $this->verify($target, $address, $key, $verifyHostKey);
    }

    /**
     * @param  Closure(HostKey): void  $verifyHostKey
     *
     * @throws SshException
     */
    public function verify(Target $target, string $address, PrivateKey $key, Closure $verifyHostKey): void
    {
        try {
            $session = $this->connector->connect($target, $address, Credentials::key($key), $verifyHostKey);
        } catch (SshException $exception) {
            if ($exception->reason !== SshException::AUTHENTICATION) {
                throw $exception;
            }

            throw new SshException("The key was added, but logging in with it still fails. The server may not allow key logins for {$target->user} (check PubkeyAuthentication and AuthorizedKeysFile in sshd_config).", SshException::AUTHENTICATION);
        }

        try {
            $result = $session->run('echo '.self::VERIFY_MARKER.' # server-connect:verify-key', '', null, 15);
        } finally {
            $session->disconnect();
        }

        if (! str_contains($result->output, self::VERIFY_MARKER)) {
            throw new SshException('Logged in with the key, but the server didn\'t run a test command.', SshException::AUTHENTICATION);
        }
    }

    /**
     * One plain OpenSSH public key line: type, base64 and an optional comment.
     * No authorized_keys options (command="…", from=…), one line only.
     */
    public static function isPublicKeyLine(string $line): bool
    {
        if ($line === '' || strlen($line) > 8192 || preg_match('/[\x00-\x1f\x7f]/', $line) === 1) {
            return false;
        }

        $parts = explode(' ', $line);

        return count($parts) >= 2
            && in_array($parts[0], ['ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'], true)
            && strlen($parts[1]) >= 16
            && preg_match('/^[A-Za-z0-9+\/=]+$/', $parts[1]) === 1;
    }
}
