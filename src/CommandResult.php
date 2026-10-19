<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect;

final readonly class CommandResult
{
    public function __construct(
        public ?int $exitCode,
        public string $output,
        public bool $timedOut = false,
    ) {}

    public function successful(): bool
    {
        return ! $this->timedOut && $this->exitCode === 0;
    }
}
