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
    /** No connection: DNS, a refused or filtered port, or a handshake that timed out. */
    public const UNREACHABLE = 'unreachable';

    /** The server refused the password or key, or no password was given. */
    public const AUTHENTICATION = 'authentication';

    public const HOST_KEY_CHANGED = 'host_key_changed';

    public const REFUSED_TARGET = 'refused_target';

    /** A command (a probe, the key install) ran past its own time limit. */
    public const TIMEOUT = 'timeout';

    /** The connection closed, or the server's answer was cut off or garbled. */
    public const DROPPED = 'dropped';

    /** Logged in with the password, but installing or then using the key failed. */
    public const INSTALL_FAILED = 'install_failed';

    public function __construct(string $message, public readonly string $reason = self::UNREACHABLE)
    {
        parent::__construct($message);
    }
}
