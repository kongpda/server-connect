<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect;

use phpseclib3\Crypt\Common\PrivateKey as PhpseclibPrivateKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use SensitiveParameter;
use Throwable;

/**
 * An SSH client private key, decrypted in memory. Load it from OpenSSH or PEM
 * text (with its passphrase when it has one), or generate a new Ed25519 key.
 * Never printed or serialized; export it explicitly with toOpenSsh().
 */
final class PrivateKey
{
    public const MAX_TEXT_LENGTH = 32768;

    public const MIN_RSA_BITS = 2048;

    private function __construct(
        private readonly PhpseclibPrivateKey $key,
        public readonly string $type,
        public readonly string $publicLine,
    ) {}

    public static function generateEd25519(string $comment = ''): self
    {
        /** @var PhpseclibPrivateKey $key */
        $key = EC::createKey('Ed25519');

        return self::wrap($key, $comment);
    }

    /**
     * @throws InvalidPrivateKey
     */
    public static function load(#[SensitiveParameter] string $text, #[SensitiveParameter] ?string $passphrase = null, string $comment = ''): self
    {
        $text = self::normalize($text);

        if ($text === '' || strlen($text) > self::MAX_TEXT_LENGTH || ! str_contains($text, 'PRIVATE KEY')) {
            throw InvalidPrivateKey::unsupported();
        }

        $encrypted = self::isEncrypted($text);
        $passphrase = $passphrase === '' ? null : $passphrase;

        if ($encrypted && $passphrase === null) {
            throw InvalidPrivateKey::passphraseRequired();
        }

        try {
            $key = $encrypted ? PublicKeyLoader::loadPrivateKey($text, (string) $passphrase) : PublicKeyLoader::loadPrivateKey($text);
        } catch (Throwable) {
            throw $encrypted ? InvalidPrivateKey::wrongPassphrase() : InvalidPrivateKey::unsupported();
        }

        if ($key instanceof RSA\PrivateKey && $key->getLength() < self::MIN_RSA_BITS) {
            throw new InvalidPrivateKey('RSA keys must have at least '.self::MIN_RSA_BITS.' bits.', InvalidPrivateKey::UNSUPPORTED);
        }

        if (! $key instanceof RSA\PrivateKey && ! $key instanceof EC\PrivateKey) {
            throw InvalidPrivateKey::unsupported();
        }

        return self::wrap($key, $comment !== '' ? $comment : self::commentOf($text));
    }

    /**
     * Whether the key text is protected with a passphrase (OpenSSH cipher other
     * than "none", or an encrypted PEM/PKCS#8 key). Doesn't need the passphrase.
     */
    public static function isEncrypted(#[SensitiveParameter] string $text): bool
    {
        $text = self::normalize($text);

        if (str_contains($text, 'BEGIN OPENSSH PRIVATE KEY')) {
            $body = preg_replace('/-----[^-]+-----|\s+/', '', $text);
            $binary = base64_decode((string) $body, true);

            if ($binary === false || ! str_starts_with($binary, "openssh-key-v1\0")) {
                return false;
            }

            try {
                $cipher = (new WireReader(substr($binary, 15)))->string();
            } catch (InvalidHostKey) {
                return false;
            }

            return $cipher !== 'none';
        }

        return str_contains($text, 'BEGIN ENCRYPTED PRIVATE KEY') || str_contains($text, 'Proc-Type: 4,ENCRYPTED');
    }

    /**
     * The private key in OpenSSH format, unencrypted or encrypted with
     * $passphrase (bcrypt KDF; OpenSSH's default is 16 rounds, about 10 s to
     * open in pure PHP).
     */
    public function toOpenSsh(#[SensitiveParameter] ?string $passphrase = null, int $rounds = 16): string
    {
        $key = $passphrase === null || $passphrase === '' ? $this->key->withPassword(false) : $this->key->withPassword($passphrase);
        $options = $this->comment() !== '' ? ['comment' => $this->comment()] : [];

        if ($passphrase !== null && $passphrase !== '') {
            $options['rounds'] = max(1, $rounds);
        }

        return $key->toString('OpenSSH', $options);
    }

    public function fingerprint(): string
    {
        return HostKey::parse($this->publicLine)->fingerprint();
    }

    public function comment(): string
    {
        $parts = explode(' ', $this->publicLine, 3);

        return $parts[2] ?? '';
    }

    /**
     * For connectors: the phpseclib key object.
     */
    public function phpseclib(): PhpseclibPrivateKey
    {
        return $this->key;
    }

    /**
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['type' => $this->type, 'public' => $this->publicLine];
    }

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        throw new \LogicException('Private keys must not be serialized; export them with toOpenSsh() and encrypt the result.');
    }

    private static function wrap(PhpseclibPrivateKey $key, string $comment): self
    {
        $key = $key->withPassword(false);
        $public = trim($key->getPublicKey()->toString('OpenSSH'));
        [$type, $blob] = explode(' ', $public.' ', 3);
        $comment = preg_replace('/[^\x21-\x7e ]/', '', $comment) ?? '';
        $line = trim("{$type} {$blob} {$comment}");

        return new self($key, $type, $line);
    }

    private static function commentOf(string $text): string
    {
        if (! str_contains($text, 'BEGIN OPENSSH PRIVATE KEY')) {
            return '';
        }

        // Unencrypted OpenSSH keys carry the comment inside; phpseclib exposes it on load.
        try {
            $key = PublicKeyLoader::loadPrivateKey($text);
            $comment = method_exists($key, 'getComment') ? $key->getComment() : null;

            return is_string($comment) ? $comment : '';
        } catch (Throwable) {
            return '';
        }
    }

    private static function normalize(string $text): string
    {
        return trim(str_replace("\r\n", "\n", $text));
    }
}
