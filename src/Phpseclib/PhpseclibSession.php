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

/**
 * A logged-in phpseclib connection. The credentials it was opened with are
 * already forgotten; it can't be serialized.
 */
final class PhpseclibSession implements Session
{
    public const DEFAULT_MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

    /**
     * The longest one read waits before the deadline is checked again.
     */
    private const READ_TIMEOUT_SECONDS = 2;

    public function __construct(
        private readonly SSH2 $ssh,
        private readonly string $where,
        private readonly int $maxOutputBytes = self::DEFAULT_MAX_OUTPUT_BYTES,
    ) {}

    public function run(string $command, string $stdin = '', ?Closure $onOutput = null, int $timeoutSeconds = 60): CommandResult
    {
        $deadline = microtime(true) + max(1, $timeoutSeconds);
        $output = '';
        $timedOut = false;
        $truncated = false;

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
                // Checked on every pass, so a command that keeps printing still times out.
                $remaining = $deadline - microtime(true);

                if ($remaining <= 0) {
                    $timedOut = true;
                    $this->ssh->reset(SSH2::CHANNEL_EXEC);
                    break;
                }

                $this->ssh->setTimeout(min(self::READ_TIMEOUT_SECONDS, $remaining));

                try {
                    $chunk = $this->ssh->read('', SSH2::READ_NEXT, SSH2::CHANNEL_EXEC);
                } catch (InsufficientSetupException) {
                    break; // the channel is closed
                }

                if ($chunk === true) {
                    if (! $this->ssh->isTimeout()) {
                        break; // the command finished
                    }

                    continue;
                }

                if (! is_string($chunk)) {
                    break;
                }

                $room = $this->maxOutputBytes - strlen($output);

                if (strlen($chunk) > $room) {
                    $truncated = true;
                    $output .= substr($chunk, 0, max(0, $room));
                } else {
                    $output .= $chunk;
                }

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

        return new CommandResult($timedOut ? null : (is_int($exit) ? $exit : null), $output, $timedOut, $truncated);
    }

    public function disconnect(): void
    {
        try {
            $this->ssh->disconnect();
        } catch (Throwable) {
            // Already gone.
        }
    }

    /**
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['where' => $this->where];
    }

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        throw new \LogicException('SSH sessions must not be serialized.');
    }
}
