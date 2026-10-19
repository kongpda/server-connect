<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect;

use Closure;

/**
 * Opens SSH sessions. Phpseclib\PhpseclibConnector talks to real servers;
 * Testing\FakeConnector scripts them for tests.
 */
interface Connector
{
    /**
     * Connect to $address (an IP from TargetGuard, so DNS can't change between
     * the check and the connection), show the host key to $verifyHostKey before
     * anything is sent (it throws to refuse), then log in.
     *
     * @param  Closure(HostKey): void  $verifyHostKey  see HostKeyPolicy
     *
     * @throws SshException
     */
    public function connect(Target $target, string $address, Credentials $credentials, Closure $verifyHostKey): Session;

    /**
     * Read the host key the server presents now, without logging in (like
     * ssh-keyscan). For "verify and replace the pinned key".
     *
     * @throws SshException
     */
    public function scanHostKey(Target $target, string $address): HostKey;
}
