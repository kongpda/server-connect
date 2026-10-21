<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect;

/**
 * Where to connect: host, port and login, validated strictly. Nothing here is
 * ever parsed as an option: no leading "-", no whitespace or control
 * characters, no "@" smuggling a user into the host.
 */
final readonly class Target
{
    public function __construct(
        public string $host,
        public int $port,
        public string $user,
    ) {
        self::validateHost($host);
        self::validateUser($user);
        self::validatePort($port);
    }

    /**
     * @throws InvalidTarget
     */
    public static function validateHost(string $host): void
    {
        if ($host === '') {
            throw new InvalidTarget('Enter the server\'s host name or IP address.');
        }

        if (str_starts_with($host, '-')) {
            throw new InvalidTarget('The host must not start with "-".');
        }

        if (strlen($host) > 253 || preg_match('/\A[A-Za-z0-9._:\[\]-]+\z/', $host) !== 1) {
            throw new InvalidTarget('Use only letters, digits and . - _ : [ ] in the host (an IP address or a host name, without a user or port).');
        }

        // Brackets only around an IPv6 address; otherwise an IP or dot-separated labels.
        $bracketed = preg_match('/\A\[([^\[\]]+)\]\z/', $host, $match) === 1;
        $valid = $bracketed
            ? filter_var($match[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false
            : filter_var($host, FILTER_VALIDATE_IP) !== false || preg_match('/\A[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.?\z/', $host) === 1;

        if (! $valid) {
            throw new InvalidTarget('Enter only an IP address or a host name, without a user or port.');
        }
    }

    /**
     * @throws InvalidTarget
     */
    public static function validateUser(string $user): void
    {
        // Portable login names, plus "@" for directory logins (user@realm). The name lands in
        // messages, logs and pages, so no quotes, "$", non-ASCII or bidi characters.
        if (preg_match('/\A[A-Za-z0-9._][A-Za-z0-9._@-]{0,63}\z/', $user) !== 1) {
            throw new InvalidTarget('Use a plain login name such as root or deploy: letters, digits and . _ - @, not starting with "-".');
        }
    }

    /**
     * @throws InvalidTarget
     */
    public static function validatePort(int $port): void
    {
        if ($port < 1 || $port > 65535) {
            throw new InvalidTarget('The SSH port must be between 1 and 65535.');
        }
    }

    /**
     * The host without IPv6 brackets.
     */
    public function bareHost(): string
    {
        return trim($this->host, '[]');
    }

    public function __toString(): string
    {
        $host = str_contains($this->bareHost(), ':') ? '['.$this->bareHost().']' : $this->host;

        return "{$this->user}@{$host}".($this->port === 22 ? '' : ":{$this->port}");
    }
}
