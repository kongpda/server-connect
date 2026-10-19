<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Monitor;

/**
 * Host metrics read over SSH without an agent. null means "couldn't read".
 */
final readonly class Metrics
{
    public function __construct(
        public ?float $cpuPercent,
        public ?float $load1,
        public ?int $memoryTotalMb,
        public ?int $memoryUsedMb,
        public ?float $diskTotalGb,
        public ?float $diskFreeGb,
        public ?int $uptimeSeconds,
    ) {}

    /**
     * @return array<string, int|float|null>
     */
    public function toArray(): array
    {
        return [
            'cpu_percent' => $this->cpuPercent,
            'load_1' => $this->load1,
            'memory_total_mb' => $this->memoryTotalMb,
            'memory_used_mb' => $this->memoryUsedMb,
            'disk_total_gb' => $this->diskTotalGb,
            'disk_free_gb' => $this->diskFreeGb,
            'uptime_seconds' => $this->uptimeSeconds,
        ];
    }
}
