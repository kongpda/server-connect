<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect;

use RuntimeException;

/**
 * A connection problem, with a message written for the person who owns the
 * server: what happened and what to do. Never carries a password or key.
 */
class SshException extends RuntimeException
{
    public const UNREACHABLE = 'unreachable';

    public const AUTHENTICATION = 'authentication';

    public const HOST_KEY_CHANGED = 'host_key_changed';

    public const REFUSED_TARGET = 'refused_target';

    public const TIMEOUT = 'timeout';

    public const DROPPED = 'dropped';

    public function __construct(string $message, public readonly string $reason = self::UNREACHABLE)
    {
        parent::__construct($message);
    }
}
