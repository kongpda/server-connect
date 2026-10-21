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
echo @@PRODUCT@@; cat /sys/class/dmi/id/product_name 2>/dev/null
echo @@VIRT@@; V=$(systemd-detect-virt 2>/dev/null); echo "${V:-unknown}"
echo @@ID@@; id -u 2>/dev/null
echo @@SUDO@@; if [ "$(id -u)" -eq 0 ]; then echo root; elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then echo yes; else echo no; fi
echo @@SYSTEMD@@; [ -d /run/systemd/system ] && echo yes || echo no
echo @@CURL@@; command -v curl >/dev/null 2>&1 && echo yes || echo no
echo @@PKG@@; for p in apt-get dnf yum zypper pacman apk; do command -v $p >/dev/null 2>&1 && { echo $p; break; }; done
echo @@DOCKER@@; docker --version 2>/dev/null || echo none
echo @@DOCKERD@@; systemctl is-active docker 2>/dev/null || echo inactive
echo @@DACCESS@@; if ! command -v docker >/dev/null 2>&1; then echo unknown; elif $DOCKER ps -q >/dev/null 2>&1; then if [ "$DOCKER" = docker ]; then echo ok; else echo sudo; fi; elif systemctl is-active --quiet docker 2>/dev/null; then echo denied; else echo unknown; fi
echo @@REBOOT@@; K=$(ls -d /boot/vmlinuz-[0-9]* 2>/dev/null | sed 's|^/boot/vmlinuz-||' | sort -V | tail -1); if test -f /var/run/reboot-required || { [ -n "$K" ] && [ "$K" != "$(uname -r)" ]; }; then echo yes; else echo no; fi
echo @@UFW@@; grep -qsi '^ENABLED=yes' /etc/ufw/ufw.conf && echo active || echo inactive
echo @@FAIL2BAN@@; systemctl is-active fail2ban 2>/dev/null || echo inactive
echo @@UNATT@@; grep -hsqE '^[[:space:]]*APT::Periodic::Unattended-Upgrade[[:space:]]+"1"' /etc/apt/apt.conf.d/20auto-upgrades && echo configured || echo none
echo @@SWAP@@; awk 'NR>1 {print $1}' /proc/swaps 2>/dev/null | head -1
echo @@SSHD@@; S=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd); $SUDO $S -T 2>/dev/null | grep -Ei '^(passwordauthentication|permitrootlogin) '
echo @@DPKG@@; if pgrep -x 'apt|apt-get|dpkg|aptitude' >/dev/null 2>&1 || pgrep -f '[b]in/unattended-upgrade( |$)' >/dev/null 2>&1; then echo locked; else echo free; fi
SH;

    /**
     * @param  array<string, string>  $extra  more read-only sections, NAME => shell snippet (NAME is [A-Z0-9_]).
     *                                        Their output comes back in ServerFacts::$extra as the server sent it:
     *                                        escape it before showing it.
     */
    public static function script(array $extra = []): string
    {
        $sections = '';

        foreach ($extra as $name => $snippet) {
            // @phpstan-ignore function.alreadyNarrowedType (a list passed by mistake has int keys)
            if (! is_string($name) || preg_match('/^[A-Z][A-Z0-9_]{0,31}$/', $name) !== 1) {
                throw new InvalidArgumentException('Invalid probe section name "'.$name.'"; use NAME => snippet.');
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

        if ($result->truncated) {
            throw new SshException('The server\'s answer to the facts probe was too long, so it was cut off.', SshException::DROPPED);
        }

        return self::parse($result->output);
    }

    /**
     * @throws SshException when the output has no probe sections, or stops before the end
     */
    public static function parse(string $raw): ServerFacts
    {
        $sections = self::sections($raw);

        if (! isset($sections['UNAME'])) {
            // The server's own words, short and printable: it may send anything.
            $message = trim(implode("\n", array_slice(explode("\n", trim(substr($raw, 0, 2000))), 0, 4)));
            $message = mb_substr((string) preg_replace('/[\x00-\x09\x0b-\x1f\x7f]/', '', $message), 0, 200);

            throw new SshException($message === '' ? 'The server sent no answer to the facts probe.' : "The facts probe didn't run: {$message}", SshException::DROPPED);
        }

        // Without the end marker, missing sections would read as "no sudo", "no ufw" and so on.
        if (! array_key_exists('END', $sections)) {
            throw new SshException('The server\'s answer to the facts probe stopped part way.', SshException::DROPPED);
        }

        unset($sections['END']);
        $os = self::keyValues($sections['OSREL'] ?? '');
        $uname = array_values(array_filter(array_map('trim', explode("\n", $sections['UNAME']))));
        $memory = self::keyValues(str_replace(':', '=', $sections['MEM'] ?? ''));
        $kb = fn (string $key): ?int => isset($memory[$key]) && preg_match('/^(\d{1,15})\b/', $memory[$key], $m) === 1 ? intdiv((int) $m[1], 1024) : null;
        $disk = preg_split('/\s+/', trim($sections['DISK'] ?? '')) ?: [];
        $load = preg_split('/\s+/', trim($sections['LOAD'] ?? '')) ?: [];
        $uptime = preg_split('/\s+/', trim($sections['UPTIME'] ?? '')) ?: [];
        $docker = trim($sections['DOCKER'] ?? 'none');
        $sshd = strtolower($sections['SSHD'] ?? '');
        $number = fn (?string $value): ?float => self::decimal($value);
        $first = fn (string $name): string => trim((string) strtok(($sections[$name] ?? '')."\n", "\n"));

        $extra = [];

        foreach ($sections as $name => $body) {
            if (str_starts_with($name, 'X_')) {
                $extra[substr($name, 2)] = trim($body);
            }
        }

        return new ServerFacts(
            kernel: self::text($uname[0] ?? null) ?? 'unknown',
            arch: self::text($uname[1] ?? null),
            osId: self::text(isset($os['ID']) ? strtolower($os['ID']) : null),
            osVersion: self::text($os['VERSION_ID'] ?? null),
            osName: self::text($os['PRETTY_NAME'] ?? null),
            osLike: self::text(isset($os['ID_LIKE']) ? strtolower($os['ID_LIKE']) : null),
            provider: Provider::fromDmi($sections['VENDOR'] ?? '', $sections['PRODUCT'] ?? ''),
            cpuCount: ctype_digit($first('NPROC')) ? (int) $first('NPROC') : null,
            memoryTotalMb: $kb('MemTotal'),
            memoryAvailableMb: $kb('MemAvailable'),
            swapTotalMb: $kb('SwapTotal'),
            diskTotalGb: self::gigabytes($disk[0] ?? null),
            diskFreeGb: self::gigabytes($disk[1] ?? null),
            load1: $number($load[0] ?? null),
            load5: $number($load[1] ?? null),
            load15: $number($load[2] ?? null),
            uptimeSeconds: self::seconds($uptime[0] ?? null),
            isRoot: $first('ID') === '0',
            sudo: in_array($first('SUDO'), ['root', 'yes'], true) ? $first('SUDO') : 'no',
            systemd: $first('SYSTEMD') === 'yes',
            curl: $first('CURL') === 'yes',
            packageManager: in_array($first('PKG'), ['apt-get', 'dnf', 'yum', 'zypper', 'pacman', 'apk'], true) ? $first('PKG') : null,
            dockerInstalled: $docker !== 'none' && $docker !== '',
            dockerVersion: preg_match('/version ([0-9][0-9A-Za-z.+~-]{0,63})/i', $docker, $m) === 1 ? $m[1] : null,
            dockerActive: $first('DOCKERD') === 'active',
            dockerAccess: in_array($first('DACCESS'), ['ok', 'sudo', 'denied'], true) ? $first('DACCESS') : 'unknown',
            rebootRequired: $first('REBOOT') === 'yes',
            ufwActive: $first('UFW') === 'active',
            fail2banActive: $first('FAIL2BAN') === 'active',
            unattendedUpgrades: $first('UNATT') === 'configured',
            swapPresent: $first('SWAP') !== '',
            sshdPasswordAuth: preg_match('/^passwordauthentication (yes|no)/m', $sshd, $m) === 1 ? $m[1] === 'yes' : null,
            sshdRootLogin: preg_match('/^permitrootlogin (yes|no|prohibit-password|without-password|forced-commands-only)$/m', $sshd, $m) === 1 ? $m[1] : null,
            dpkgLocked: $first('DPKG') === 'locked',
            extra: $extra,
            virtualization: preg_match('/^[a-z0-9_-]{1,32}$/', $first('VIRT')) === 1 && $first('VIRT') !== 'unknown' ? $first('VIRT') : null,
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

        return $sections;
    }

    /**
     * A plain, bounded, non-negative decimal: a server may send "1e999"
     * (INF, which json_encode refuses), "-5" or "NAN".
     *
     * @internal
     */
    public static function decimal(?string $value): ?float
    {
        return $value !== null && preg_match('/^\d{1,12}(?:\.\d{1,9})?$/', $value) === 1 ? (float) $value : null;
    }

    /**
     * @internal
     */
    public static function seconds(?string $value): ?int
    {
        $seconds = self::decimal($value);

        return $seconds === null ? null : (int) $seconds;
    }

    /**
     * Kilobytes (df -Pk) as gigabytes.
     *
     * @internal
     */
    public static function gigabytes(?string $kilobytes): ?float
    {
        return $kilobytes !== null && preg_match('/^\d{1,15}$/', $kilobytes) === 1 ? round((int) $kilobytes / 1048576, 1) : null;
    }

    /**
     * A short, printable string from the server, or null: it may send
     * anything, and these fields end up in logs and pages.
     */
    private static function text(?string $value): ?string
    {
        $value = trim(mb_substr((string) preg_replace('/[\x00-\x1f\x7f]/', '', mb_scrub((string) $value)), 0, 100));

        return $value === '' ? null : $value;
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
