<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Phpseclib;

use Closure;
use Kongpda\ServerConnect\CommandResult;
use Kongpda\ServerConnect\Session;
use Kongpda\ServerConnect\SshException;
use phpseclib3\Exception\InsufficientSetupException;
use phpseclib3\Net\SSH2;
use Throwable;

final class PhpseclibSession implements Session
{
    /**
     * How long one read waits before the wall-clock deadline is checked again.
     */
    private const READ_TIMEOUT_SECONDS = 2;

    public function __construct(private readonly SSH2 $ssh, private readonly string $where) {}

    public function run(string $command, string $stdin = '', ?Closure $onOutput = null, int $timeoutSeconds = 60): CommandResult
    {
        $deadline = microtime(true) + $timeoutSeconds;
        $output = '';
        $timedOut = false;

        try {
            $this->ssh->setTimeout(self::READ_TIMEOUT_SECONDS);

            if ($this->ssh->exec($command, false) === false) {
                throw new SshException("{$this->where} refused to run a command.", SshException::DROPPED);
            }

            if ($stdin !== '') {
                $this->ssh->write($stdin, SSH2::CHANNEL_EXEC);
            }

            $this->ssh->sendEOF(SSH2::CHANNEL_EXEC);

            while (true) {
                try {
                    $chunk = $this->ssh->read('', SSH2::READ_NEXT, SSH2::CHANNEL_EXEC);
                } catch (InsufficientSetupException) {
                    break; // the channel is closed
                }

                if ($chunk === true) {
                    if (! $this->ssh->isTimeout()) {
                        break; // the command finished
                    }

                    if (microtime(true) >= $deadline) {
                        $timedOut = true;
                        $this->ssh->reset(SSH2::CHANNEL_EXEC);
                        break;
                    }

                    continue;
                }

                if (! is_string($chunk)) {
                    break;
                }

                $output .= $chunk;

                if ($onOutput !== null && $chunk !== '') {
                    $onOutput($chunk);
                }
            }

            // stderr arrives interleaved through read() (phpseclib isn't in quiet mode), so
            // getStdError() would only repeat it.

            $exit = $this->ssh->getExitStatus();
        } catch (SshException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new SshException("The connection to {$this->where} dropped: ".mb_substr($exception->getMessage(), 0, 200), SshException::DROPPED);
        }

        return new CommandResult($timedOut ? null : (is_int($exit) ? $exit : null), $output, $timedOut);
    }

    public function disconnect(): void
    {
        try {
            $this->ssh->disconnect();
        } catch (Throwable) {
            // Already gone.
        }
    }
}
