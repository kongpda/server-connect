<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect;

use Closure;

interface Session
{
    /**
     * Run an app-authored command. $stdin is written to it and then closed,
     * so secrets travel there instead of on the command line (where `ps`
     * shows them). $onOutput gets output chunks as they arrive. The timeout is
     * wall-clock for the whole command.
     *
     * @param  (Closure(string): void)|null  $onOutput
     *
     * @throws SshException when the connection drops
     */
    public function run(string $command, string $stdin = '', ?Closure $onOutput = null, int $timeoutSeconds = 60): CommandResult;

    public function disconnect(): void;
}
