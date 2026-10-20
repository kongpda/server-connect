<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect;

use InvalidArgumentException;

/**
 * A private key that can't be used, with the reason as a code a UI can act on.
 */
final class InvalidPrivateKey extends InvalidArgumentException
{
    public const PASSPHRASE_REQUIRED = 'passphrase_required';

    public const WRONG_PASSPHRASE = 'wrong_passphrase';

    public const UNSUPPORTED = 'unsupported';

    public function __construct(string $message, public readonly string $reason)
    {
        parent::__construct($message);
    }

    public static function passphraseRequired(): self
    {
        return new self('This key is protected with a passphrase. Enter the passphrase.', self::PASSPHRASE_REQUIRED);
    }

    public static function wrongPassphrase(): self
    {
        return new self('The passphrase is wrong for this key.', self::WRONG_PASSPHRASE);
    }

    public static function unsupported(): self
    {
        return new self('This is not a supported private key. Paste an OpenSSH (BEGIN OPENSSH PRIVATE KEY) or PEM (BEGIN RSA/EC PRIVATE KEY) Ed25519, ECDSA or RSA private key.', self::UNSUPPORTED);
    }
}
