<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect;

/**
 * The server presented a different host key than the pinned one. Thrown
 * before authentication, so no password or key was offered to it.
 */
final class HostKeyChanged extends SshException
{
    public function __construct(public readonly HostKey $presented, public readonly string $pinnedFingerprint)
    {
        parent::__construct(
            "This server's SSH host key has changed since it was trusted: it was {$pinnedFingerprint}, now it is {$presented->fingerprint()}. "
            .'That happens when a server is rebuilt or reinstalled, and it is also exactly what someone intercepting the connection looks like. '
            .'Check the new fingerprint on the server or in your provider\'s console (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub), and replace the pinned key only if it matches.',
            self::HOST_KEY_CHANGED,
        );
    }
}
