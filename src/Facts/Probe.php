<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Facts;

use InvalidArgumentException;
use Kongpda\ServerConnect\Session;
use Kongpda\ServerConnect\Shell\Shims;
use Kongpda\ServerConnect\SshException;

/**
 * Server facts in ONE read-only SSH round trip. Every command is read-only
 * and guarded on its own, so a missing tool blanks one field instead of
 * failing the probe. Sections are delimited by @@NAME@@ markers.
 */
final class Probe
{
    public const MARKER = 'server-connect:facts';

    private const BODY = <<<'SH'
echo @@OSREL@@; cat /etc/os-release 2>/dev/null
echo @@UNAME@@; uname -s 2>/dev/null; uname -m 2>/dev/null
echo @@NPROC@@; nproc 2>/dev/null
echo @@MEM@@; cat /proc/meminfo 2>/dev/null
echo @@DISK@@; df -Pk / 2>/dev/null | awk 'NR==2 {print $2, $4}'
echo @@LOAD@@; cat /proc/loadavg 2>/dev/null
echo @@UPTIME@@; cat /proc/uptime 2>/dev/null
echo @@VENDOR@@; cat /sys/class/dmi/id/sys_vendor 2>/dev/null
echo @@ID@@; id -u 2>/dev/null
echo @@SUDO@@; if [ "$(id -u)" -eq 0 ]; then echo root; elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then echo yes; else echo no; fi
echo @@SYSTEMD@@; [ -d /run/systemd/system ] && echo yes || echo no
echo @@CURL@@; command -v curl >/dev/null 2>&1 && echo yes || echo no
echo @@PKG@@; for p in apt-get dnf yum zypper pacman apk; do command -v $p >/dev/null 2>&1 && { echo $p; break; }; done
echo @@DOCKER@@; docker --version 2>/dev/null || echo none
echo @@DOCKERD@@; systemctl is-active docker 2>/dev/null || echo inactive
echo @@DACCESS@@; if ! command -v docker >/dev/null 2>&1; then echo unknown; elif $DOCKER ps -q >/dev/null 2>&1; then if [ "$DOCKER" = docker ]; then echo ok; else echo sudo; fi; elif systemctl is-active --quiet docker 2>/dev/null; then echo denied; else echo unknown; fi
echo @@REBOOT@@; test -f /var/run/reboot-required && echo yes || echo no
echo @@UFW@@; systemctl is-active ufw 2>/dev/null || echo inactive
echo @@FAIL2BAN@@; systemctl is-active fail2ban 2>/dev/null || echo inactive
echo @@UNATT@@; grep -hsq 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades && echo configured || echo none
echo @@SWAP@@; awk 'NR>1 {print $1}' /proc/swaps 2>/dev/null | head -1
echo @@SSHD@@; S=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd); $SUDO $S -T 2>/dev/null | grep -Ei '^(passwordauthentication|permitrootlogin) '
echo @@DPKG@@; if pgrep -x 'apt|apt-get|dpkg|aptitude' >/dev/null 2>&1 || pgrep -f '[b]in/unattended-upgrade( |$)' >/dev/null 2>&1; then echo locked; else echo free; fi
SH;

    /**
     * @param  array<string, string>  $extra  more read-only sections, NAME => shell snippet (NAME is [A-Z0-9_])
     */
    public static function script(array $extra = []): string
    {
        $sections = '';

        foreach ($extra as $name => $snippet) {
            if (preg_match('/^[A-Z][A-Z0-9_]{0,31}$/', $name) !== 1) {
                throw new InvalidArgumentException("Invalid probe section name \"{$name}\".");
            }

            $sections .= "echo @@X_{$name}@@; {$snippet}\n";
        }

        return Shims::script(self::MARKER, self::BODY."\n".$sections.'echo @@END@@', strict: false);
    }

    /**
     * @param  array<string, string>  $extra
     *
     * @throws SshException
     */
    public static function run(Session $session, array $extra = [], int $timeoutSeconds = 30): ServerFacts
    {
        $result = $session->run('sh -s', self::script($extra), null, $timeoutSeconds);

        if ($result->timedOut) {
            throw new SshException('Reading the server\'s facts timed out.', SshException::TIMEOUT);
        }

        return self::parse($result->output);
    }

    /**
     * @throws SshException when the output has no probe sections at all
     */
    public static function parse(string $raw): ServerFacts
    {
        $sections = self::sections($raw);

        if (! isset($sections['UNAME'])) {
            $message = trim(implode("\n", array_slice(explode("\n", trim($raw)), 0, 4)));

            throw new SshException($message === '' ? 'The server sent no answer to the facts probe.' : "The facts probe didn't run: {$message}", SshException::DROPPED);
        }

        $os = self::keyValues($sections['OSREL'] ?? '');
        $uname = array_values(array_filter(array_map('trim', explode("\n", $sections['UNAME']))));
        $memory = self::keyValues(str_replace(':', '=', $sections['MEM'] ?? ''));
        $kb = fn (string $key): ?int => isset($memory[$key]) && preg_match('/^(\d+)/', $memory[$key], $m) === 1 ? intdiv((int) $m[1], 1024) : null;
        $disk = preg_split('/\s+/', trim($sections['DISK'] ?? '')) ?: [];
        $load = preg_split('/\s+/', trim($sections['LOAD'] ?? '')) ?: [];
        $uptime = preg_split('/\s+/', trim($sections['UPTIME'] ?? '')) ?: [];
        $docker = trim($sections['DOCKER'] ?? 'none');
        $sshd = strtolower($sections['SSHD'] ?? '');
        $number = fn (?string $value): ?float => $value !== null && is_numeric($value) ? (float) $value : null;
        $first = fn (string $name): string => trim((string) strtok(($sections[$name] ?? '')."\n", "\n"));

        $extra = [];

        foreach ($sections as $name => $body) {
            if (str_starts_with($name, 'X_')) {
                $extra[substr($name, 2)] = trim($body);
            }
        }

        return new ServerFacts(
            kernel: $uname[0] ?? 'unknown',
            arch: $uname[1] ?? null,
            osId: isset($os['ID']) ? strtolower($os['ID']) : null,
            osVersion: $os['VERSION_ID'] ?? null,
            osName: $os['PRETTY_NAME'] ?? null,
            osLike: isset($os['ID_LIKE']) ? strtolower($os['ID_LIKE']) : null,
            provider: Provider::fromVendor($sections['VENDOR'] ?? ''),
            cpuCount: ctype_digit($first('NPROC')) ? (int) $first('NPROC') : null,
            memoryTotalMb: $kb('MemTotal'),
            memoryAvailableMb: $kb('MemAvailable'),
            swapTotalMb: $kb('SwapTotal'),
            diskTotalGb: isset($disk[0]) && ctype_digit($disk[0]) ? round((int) $disk[0] / 1048576, 1) : null,
            diskFreeGb: isset($disk[1]) && ctype_digit($disk[1]) ? round((int) $disk[1] / 1048576, 1) : null,
            load1: $number($load[0] ?? null),
            load5: $number($load[1] ?? null),
            load15: $number($load[2] ?? null),
            uptimeSeconds: isset($uptime[0]) && is_numeric($uptime[0]) ? (int) $uptime[0] : null,
            isRoot: $first('ID') === '0',
            sudo: in_array($first('SUDO'), ['root', 'yes'], true) ? $first('SUDO') : 'no',
            systemd: $first('SYSTEMD') === 'yes',
            curl: $first('CURL') === 'yes',
            packageManager: $first('PKG') !== '' ? $first('PKG') : null,
            dockerInstalled: $docker !== 'none' && $docker !== '',
            dockerVersion: preg_match('/version ([0-9][^,\s]*)/i', $docker, $m) === 1 ? $m[1] : null,
            dockerActive: $first('DOCKERD') === 'active',
            dockerAccess: in_array($first('DACCESS'), ['ok', 'sudo', 'denied'], true) ? $first('DACCESS') : 'unknown',
            rebootRequired: $first('REBOOT') === 'yes',
            ufwActive: $first('UFW') === 'active',
            fail2banActive: $first('FAIL2BAN') === 'active',
            unattendedUpgrades: $first('UNATT') === 'configured',
            swapPresent: $first('SWAP') !== '',
            sshdPasswordAuth: preg_match('/^passwordauthentication (yes|no)/m', $sshd, $m) === 1 ? $m[1] === 'yes' : null,
            sshdRootLogin: preg_match('/^permitrootlogin (\S+)/m', $sshd, $m) === 1 ? $m[1] : null,
            dpkgLocked: $first('DPKG') === 'locked',
            extra: $extra,
        );
    }

    /**
     * @return array<string, string>
     */
    private static function sections(string $raw): array
    {
        $sections = [];
        $current = null;

        foreach (explode("\n", str_replace("\r", '', $raw)) as $line) {
            if (preg_match('/^@@([A-Z0-9_]+)@@$/', trim($line), $match) === 1) {
                $current = $match[1];
                $sections[$current] = '';

                continue;
            }

            if ($current !== null) {
                $sections[$current] .= $line."\n";
            }
        }

        unset($sections['END']);

        return $sections;
    }

    /**
     * @return array<string, string>
     */
    private static function keyValues(string $text): array
    {
        $values = [];

        foreach (explode("\n", $text) as $line) {
            if (preg_match('/^([A-Za-z0-9_()]+)=\s*(.*)$/', trim($line), $match) === 1) {
                $values[$match[1]] = trim($match[2], " \"'");
            }
        }

        return $values;
    }
}
