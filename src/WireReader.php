<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect;

/**
 * Reads length-prefixed strings from the SSH wire format (RFC 4251).
 */
final class WireReader
{
    private int $offset = 0;

    public function __construct(private readonly string $data) {}

    /**
     * Read the next string and advance past it.
     *
     * @phpstan-impure
     *
     * @throws InvalidHostKey
     */
    public function string(): string
    {
        $header = substr($this->data, $this->offset, 4);

        if (strlen($header) !== 4) {
            throw new InvalidHostKey('The key data is truncated.');
        }

        $unpacked = unpack('N', $header);
        $length = is_array($unpacked) && is_int($unpacked[1] ?? null) ? $unpacked[1] : -1;

        if ($length < 0 || $length > strlen($this->data) - $this->offset - 4) {
            throw new InvalidHostKey('The key data is truncated.');
        }

        $value = substr($this->data, $this->offset + 4, $length);
        $this->offset += 4 + $length;

        return $value;
    }

    /**
     * Read a big-endian 32-bit integer and advance past it.
     *
     * @phpstan-impure
     *
     * @throws InvalidHostKey
     */
    public function uint32(): int
    {
        $bytes = substr($this->data, $this->offset, 4);

        if (strlen($bytes) !== 4) {
            throw new InvalidHostKey('The key data is truncated.');
        }

        $this->offset += 4;
        $unpacked = unpack('N', $bytes);

        return is_array($unpacked) && is_int($unpacked[1] ?? null) ? $unpacked[1] : 0;
    }

    public function atEnd(): bool
    {
        return $this->offset === strlen($this->data);
    }
}
