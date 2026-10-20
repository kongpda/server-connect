<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect;

use Closure;

/**
 * Builds the host key check a connector runs before authenticating:
 * trust on first use (the caller pins what it sees) or a pinned fingerprint
 * that must match.
 */
final class HostKeyPolicy
{
    /**
     * The returned check is stateful: on first use it calls $onFirstUse once
     * and then accepts only that key, so a second connection made with the
     * same check (KeyInstaller makes two) can't be answered by another server.
     *
     * @param  string|null  $pinnedFingerprint  null on first use
     * @param  Closure(HostKey): void  $onFirstUse  pin the key (it is called before authentication)
     * @return Closure(HostKey): void
     */
    public static function pinned(?string $pinnedFingerprint, Closure $onFirstUse): Closure
    {
        return function (HostKey $presented) use (&$pinnedFingerprint, $onFirstUse): void {
            if ($pinnedFingerprint === null) {
                $onFirstUse($presented);
                $pinnedFingerprint = $presented->fingerprint();

                return;
            }

            if (! $presented->matchesFingerprint($pinnedFingerprint)) {
                throw new HostKeyChanged($presented, $pinnedFingerprint);
            }
        };
    }

    /**
     * Accept only this exact fingerprint (for "replace the pinned key with the one I verified").
     *
     * @return Closure(HostKey): void
     */
    public static function expect(string $fingerprint): Closure
    {
        return self::pinned($fingerprint, fn () => null);
    }
}
