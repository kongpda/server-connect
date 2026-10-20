<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect;

final readonly class CommandResult
{
    public function __construct(
        public ?int $exitCode,
        public string $output,
        public bool $timedOut = false,
        // The output went over the session's limit; only its start is kept.
        public bool $truncated = false,
    ) {}

    public function successful(): bool
    {
        return ! $this->timedOut && $this->exitCode === 0;
    }
}
