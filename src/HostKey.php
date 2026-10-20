<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect;

/**
 * An SSH host public key, compared by its SHA-256 fingerprint as OpenSSH
 * prints it ("SHA256:…", unpadded base64). The algorithm comes from the key
 * blob itself, so "rsa-sha2-512 AAAA…" (what a server signs with) and
 * "ssh-rsa AAAA…" are the same key.
 */
final readonly class HostKey
{
    public const MAX_LINE_LENGTH = 8192;

    /**
     * ECDSA key types, their curve names and uncompressed point lengths.
     *
     * @var array<string, array{0: string, 1: int}>
     */
    private const ECDSA = [
        'ecdsa-sha2-nistp256' => ['nistp256', 65],
        'ecdsa-sha2-nistp384' => ['nistp384', 97],
        'ecdsa-sha2-nistp521' => ['nistp521', 133],
    ];

    private function __construct(
        public string $algorithm,
        public string $blob,
    ) {}

    /**
     * Parse an OpenSSH public key line ("ssh-ed25519 AAAA… comment").
     *
     * @param  int  $minRsaBits  refuse RSA keys with a shorter modulus (0: any)
     *
     * @throws InvalidHostKey
     */
    public static function parse(string $line, int $minRsaBits = 0): self
    {
        $line = trim($line);

        if (strlen($line) > self::MAX_LINE_LENGTH) {
            throw new InvalidHostKey('That key is too long to be an SSH host key.');
        }

        $parts = preg_split('/\s+/', $line, 3);

        if ($parts === false || count($parts) < 2) {
            throw new InvalidHostKey('Expected a whole key line, starting with its type, like "ssh-ed25519 AAAA…".');
        }

        $blob = base64_decode($parts[1], true);

        if ($blob === false || $blob === '') {
            throw new InvalidHostKey('The key data is not valid base64.');
        }

        return self::fromBlob($blob, $parts[0], $minRsaBits);
    }

    /**
     * @param  string|null  $declared  The type the line or server declared, checked against the blob.
     * @param  int  $minRsaBits  refuse RSA keys with a shorter modulus (0: any)
     *
     * @throws InvalidHostKey
     */
    public static function fromBlob(string $blob, ?string $declared = null, int $minRsaBits = 0): self
    {
        $reader = new WireReader($blob);
        $algorithm = $reader->string();

        if ($declared !== null && $declared !== $algorithm
            && ! ($algorithm === 'ssh-rsa' && in_array($declared, ['rsa-sha2-256', 'rsa-sha2-512'], true))) {
            throw new InvalidHostKey('The key data does not match its type.');
        }

        if ($algorithm === 'ssh-ed25519') {
            if (strlen($reader->string()) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                throw new InvalidHostKey('The ed25519 key has the wrong length.');
            }
        } elseif ($algorithm === 'ssh-rsa') {
            $reader->string();
            $bits = self::bitLength($reader->string());

            if ($bits < $minRsaBits) {
                throw new InvalidHostKey("RSA host keys must be at least {$minRsaBits} bits. This one is {$bits}.");
            }
        } elseif (isset(self::ECDSA[$algorithm])) {
            [$curve, $pointLength] = self::ECDSA[$algorithm];
            $keyCurve = $reader->string();
            $point = $reader->string();

            if ($keyCurve !== $curve || strlen($point) !== $pointLength || $point[0] !== "\x04") {
                throw new InvalidHostKey('The ECDSA key is malformed.');
            }
        } else {
            throw new InvalidHostKey("Unsupported host key type \"{$algorithm}\": use ed25519, ECDSA or RSA.");
        }

        if (! $reader->atEnd()) {
            throw new InvalidHostKey('The key data has unexpected trailing bytes.');
        }

        return new self($algorithm, $blob);
    }

    public function fingerprint(): string
    {
        return self::fingerprintOf($this->blob);
    }

    public static function fingerprintOf(string $blob): string
    {
        return 'SHA256:'.rtrim(base64_encode(hash('sha256', $blob, true)), '=');
    }

    /**
     * Canonical "type base64" form, without a comment.
     */
    public function toLine(): string
    {
        return $this->algorithm.' '.base64_encode($this->blob);
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->blob, $other->blob);
    }

    public function matchesFingerprint(string $fingerprint): bool
    {
        return hash_equals($fingerprint, $this->fingerprint());
    }

    /**
     * The RSA modulus length in bits, or null for other key types.
     */
    public function rsaBits(): ?int
    {
        if ($this->algorithm !== 'ssh-rsa') {
            return null;
        }

        $reader = new WireReader($this->blob);
        $reader->string();
        $reader->string();

        return self::bitLength($reader->string());
    }

    /**
     * Bit length of an SSH mpint.
     */
    public static function bitLength(string $mpint): int
    {
        $magnitude = ltrim($mpint, "\x00");

        if ($magnitude === '') {
            return 0;
        }

        return (strlen($magnitude) - 1) * 8 + strlen(decbin(ord($magnitude[0])));
    }
}
