<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Monitor;

use Kongpda\ServerConnect\Facts\Probe;
use Kongpda\ServerConnect\Session;
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

    /**
     * No shims: the body needs neither sudo nor docker, and the docker check
     * would run `docker ps` (and `sudo -n docker ps`, logged) on every poll.
     */
    public static function script(): string
    {
        return '# '.self::MARKER."\nexec 2>&1\n".self::BODY."\n";
    }

    /**
     * @throws SshException
     */
    public static function run(Session $session): Metrics
    {
        $result = $session->run('sh -s', self::script(), null, 20);

        if ($result->timedOut) {
            throw new SshException('Reading the server\'s metrics timed out.', SshException::TIMEOUT);
        }

        // A cut-off answer would read as "unknown" for every metric, hiding the failure.
        if ($result->truncated || preg_match('/^@@END@@$/m', $result->output) !== 1) {
            throw new SshException('The server\'s answer to the metrics probe was cut off or stopped part way.', SshException::DROPPED);
        }

        return self::parse($result->output);
    }

    /**
     * Lenient: a missing or garbled section is null. run() is the one that
     * refuses an answer without its end marker.
     */
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
        $total = preg_match('/MemTotal:\s+(\d{1,15})\b/', $sections['MEM'] ?? '', $m) === 1 ? intdiv((int) $m[1], 1024) : null;
        $available = preg_match('/MemAvailable:\s+(\d{1,15})\b/', $sections['MEM'] ?? '', $m) === 1 ? intdiv((int) $m[1], 1024) : null;
        $disk = preg_split('/\s+/', trim($sections['DISK'] ?? '')) ?: [];
        $load = preg_split('/\s+/', trim($sections['LOAD'] ?? '')) ?: [];
        $uptime = preg_split('/\s+/', trim($sections['UPTIME'] ?? '')) ?: [];

        return new Metrics(
            cpuPercent: $cpu,
            load1: Probe::decimal($load[0] ?? null),
            memoryTotalMb: $total,
            memoryUsedMb: $total !== null && $available !== null && $available <= $total ? $total - $available : null,
            diskTotalGb: Probe::gigabytes($disk[0] ?? null),
            diskFreeGb: Probe::gigabytes($disk[1] ?? null),
            uptimeSeconds: Probe::seconds($uptime[0] ?? null),
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

        if ($total <= 0 || $idle < 0 || $idle > $total) {
            return null;
        }

        return round(100 * ($total - $idle) / $total, 1);
    }

    /**
     * @return list<int>|null
     */
    private static function jiffies(string $line): ?array
    {
        $parts = preg_split('/\s+/', trim($line)) ?: [];

        // user nice system idle iowait irq softirq steal. The guest columns after
        // them are already counted in user and nice, so they're left out.
        $columns = array_slice($parts, 1, 8);

        if (($parts[0] ?? '') !== 'cpu' || count($columns) < 4 || preg_grep('/^\d{1,18}$/', $columns, PREG_GREP_INVERT) !== []) {
            return null;
        }

        return array_map('intval', $columns);
    }
}
