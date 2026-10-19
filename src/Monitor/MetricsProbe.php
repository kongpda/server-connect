<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Monitor;

use Kongpda\ServerConnect\Session;
use Kongpda\ServerConnect\Shell\Shims;
use Kongpda\ServerConnect\SshException;

/**
 * Agentless metrics: CPU from two /proc/stat samples a second apart,
 * memory, root disk, load and uptime, in one read-only round trip.
 */
final class MetricsProbe
{
    public const MARKER = 'server-connect:metrics';

    private const BODY = <<<'SH'
echo @@STAT1@@; head -1 /proc/stat 2>/dev/null
sleep 1
echo @@STAT2@@; head -1 /proc/stat 2>/dev/null
echo @@MEM@@; grep -E '^(MemTotal|MemAvailable):' /proc/meminfo 2>/dev/null
echo @@DISK@@; df -Pk / 2>/dev/null | awk 'NR==2 {print $2, $4}'
echo @@LOAD@@; cat /proc/loadavg 2>/dev/null
echo @@UPTIME@@; cat /proc/uptime 2>/dev/null
echo @@END@@
SH;

    public static function script(): string
    {
        return Shims::script(self::MARKER, self::BODY, strict: false);
    }

    /**
     * @throws SshException
     */
    public static function run(Session $session): Metrics
    {
        return self::parse($session->run('sh -s', self::script(), null, 20)->output);
    }

    public static function parse(string $raw): Metrics
    {
        $sections = [];
        $current = null;

        foreach (explode("\n", $raw) as $line) {
            if (preg_match('/^@@([A-Z0-9]+)@@$/', trim($line), $match) === 1) {
                $current = $match[1];
                $sections[$current] = '';
            } elseif ($current !== null) {
                $sections[$current] .= $line."\n";
            }
        }

        $cpu = self::cpuPercent($sections['STAT1'] ?? '', $sections['STAT2'] ?? '');
        $total = preg_match('/MemTotal:\s+(\d+)/', $sections['MEM'] ?? '', $m) === 1 ? intdiv((int) $m[1], 1024) : null;
        $available = preg_match('/MemAvailable:\s+(\d+)/', $sections['MEM'] ?? '', $m) === 1 ? intdiv((int) $m[1], 1024) : null;
        $disk = preg_split('/\s+/', trim($sections['DISK'] ?? '')) ?: [];
        $load = preg_split('/\s+/', trim($sections['LOAD'] ?? '')) ?: [];
        $uptime = preg_split('/\s+/', trim($sections['UPTIME'] ?? '')) ?: [];

        return new Metrics(
            cpuPercent: $cpu,
            load1: isset($load[0]) && is_numeric($load[0]) ? (float) $load[0] : null,
            memoryTotalMb: $total,
            memoryUsedMb: $total !== null && $available !== null ? $total - $available : null,
            diskTotalGb: isset($disk[0]) && ctype_digit($disk[0]) ? round((int) $disk[0] / 1048576, 1) : null,
            diskFreeGb: isset($disk[1]) && ctype_digit($disk[1]) ? round((int) $disk[1] / 1048576, 1) : null,
            uptimeSeconds: isset($uptime[0]) && is_numeric($uptime[0]) ? (int) $uptime[0] : null,
        );
    }

    private static function cpuPercent(string $first, string $second): ?float
    {
        $a = self::jiffies($first);
        $b = self::jiffies($second);

        if ($a === null || $b === null) {
            return null;
        }

        $total = array_sum($b) - array_sum($a);
        $idle = ($b[3] + ($b[4] ?? 0)) - ($a[3] + ($a[4] ?? 0));

        return $total > 0 ? round(100 * ($total - $idle) / $total, 1) : null;
    }

    /**
     * @return list<int>|null
     */
    private static function jiffies(string $line): ?array
    {
        $parts = preg_split('/\s+/', trim($line)) ?: [];

        if (($parts[0] ?? '') !== 'cpu' || count($parts) < 5) {
            return null;
        }

        return array_map('intval', array_slice($parts, 1));
    }
}
