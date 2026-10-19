<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect;

use LogicException;
use SensitiveParameter;

/**
 * How to log in: a private key, or a password used once. Can't be serialized
 * or dumped, so it never lands in a queue payload, a log or an exception.
 */
final class Credentials
{
    private function __construct(
        private readonly ?PrivateKey $key,
        private readonly ?string $password,
    ) {}

    public static function key(PrivateKey $key): self
    {
        return new self($key, null);
    }

    public static function password(#[SensitiveParameter] string $password): self
    {
        return new self(null, $password);
    }

    public function isPassword(): bool
    {
        return $this->password !== null;
    }

    public function privateKey(): ?PrivateKey
    {
        return $this->key;
    }

    /**
     * The password; empty for key credentials.
     */
    public function passwordValue(): string
    {
        return (string) $this->password;
    }

    /**
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['type' => $this->isPassword() ? 'password' : 'key'];
    }

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        throw new LogicException('SSH credentials must not be serialized.');
    }
}
