<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Shell;

/**
 * POSIX sh preludes for app-authored scripts.
 *
 * - $SUDO is empty for root and `sudo -n` otherwise, so a missing sudo
 *   rule fails at once instead of hanging on a password prompt.
 * - $DOCKER is `docker`, or `sudo -n docker` when only sudo can reach the socket.
 * - $APT is non-interactive, keeps existing config files and waits up to
 *   5 minutes for the dpkg lock (first-boot updates) instead of failing.
 * - sc_wait_dpkg waits up to 5 minutes for other package jobs to finish.
 */
final class Shims
{
    public const SUDO = "SUDO=''; if [ \"\$(id -u)\" -ne 0 ]; then SUDO='sudo -n'; fi\n";

    public const DOCKER_READ = "DOCKER='docker'; if command -v docker >/dev/null 2>&1 && ! docker ps -q >/dev/null 2>&1 && [ \"\$(id -u)\" -ne 0 ] && sudo -n docker ps -q >/dev/null 2>&1; then DOCKER='sudo -n docker'; fi\n";

    public const APT = "APT=\"\$SUDO env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -y -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold\"\n";

    public const DPKG_WAIT = "sc_wait_dpkg(){ n=0; while { pgrep -x 'apt|apt-get|dpkg|aptitude' >/dev/null 2>&1 || pgrep -f '[b]in/unattended-upgrade( |\$)' >/dev/null 2>&1; } && [ \$n -lt 60 ]; do [ \$n -eq 0 ] && echo 'Waiting for another package job (for example first-boot updates) to finish…'; n=\$((n+1)); sleep 5; done; }\n";

    /**
     * Every shim, in dependency order ($APT uses $SUDO).
     */
    public static function prelude(): string
    {
        return self::SUDO.self::DOCKER_READ.self::APT.self::DPKG_WAIT;
    }

    /**
     * Quote a value for a POSIX shell: 'it'\''s'.
     */
    public static function quote(string $value): string
    {
        return "'".str_replace("'", "'\\''", $value)."'";
    }

    /**
     * A script for `sh -s`: marker line, strict mode, stderr into stdout, the shims, then the body.
     *
     * The body is one { … } group with stdin from /dev/null: sh reads the whole
     * group before running it, and a command in it that reads stdin (an
     * installer, apt, ssh) can't swallow the rest of the script.
     */
    public static function script(string $marker, string $body, bool $strict = true): string
    {
        return "# {$marker}\n".($strict ? "set -eu\n" : '')."exec 2>&1\n".self::prelude()."{\n{$body}\n} </dev/null\n";
    }
}
