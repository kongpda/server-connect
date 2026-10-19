<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Recipes;

enum SafetyLevel: string
{
    /** Reads only; safe to run at any time. */
    case ReadOnly = 'read_only';

    /** Changes the server in a routine, reversible way (installs a package). */
    case Mutating = 'mutating';

    /** Can lock you out or interrupt service (firewall, sshd, reboot): confirm first. */
    case HighRisk = 'high_risk';

    public function needsConfirmation(): bool
    {
        return $this === self::HighRisk;
    }
}
