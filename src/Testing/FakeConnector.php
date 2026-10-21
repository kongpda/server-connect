<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Testing;

use Closure;
use Kongpda\ServerConnect\CommandResult;
use Kongpda\ServerConnect\Connector;
use Kongpda\ServerConnect\Credentials;
use Kongpda\ServerConnect\HostKey;
use Kongpda\ServerConnect\Session;
use Kongpda\ServerConnect\SshException;
use Kongpda\ServerConnect\Target;

/**
 * A scripted SSH server for tests: its host key, which credentials it
 * accepts, and how it answers each script. Scripts are matched by their
 * marker comment ("# server-connect:facts", "# myapp:install", …), found in
 * the command or on stdin.
 */
final class FakeConnector implements Connector
{
    public string $hostKey;

    public ?string $unreachable = null;

    /**
     * Public key lines the server accepts (null accepts any key).
     *
     * @var list<string>|null
     */
    public ?array $authorizedKeys = null;

    /**
     * @var list<string>
     */
    public array $passwords = [];

    /**
     * @var array<string, Closure(string, string): (CommandResult|array{0: string, 1: int})>
     */
    public array $scripts = [];

    /**
     * @var list<array{address: string, port: int, user: string, auth: string}>
     */
    public array $connections = [];

    /**
     * @var list<array{command: string, stdin: string, script: string|null}>
     */
    public array $commands = [];

    public function __construct(?string $hostKey = null)
    {
        $this->hostKey = $hostKey ?? self::randomHostKey();
    }

    public static function randomHostKey(): string
    {
        $public = sodium_crypto_sign_publickey(sodium_crypto_sign_keypair());

        return 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', strlen($public)).$public);
    }

    /**
     * Answer the script with this marker ("server-connect:facts").
     *
     * @param  (Closure(string, string): (CommandResult|array{0: string, 1: int}))|array{0: string, 1: int}  $answer  [output, exit code]
     */
    public function on(string $marker, Closure|array $answer): self
    {
        $this->scripts[$marker] = $answer instanceof Closure ? $answer : fn (): array => $answer;

        return $this;
    }

    public function connect(Target $target, string $address, Credentials $credentials, Closure $verifyHostKey): Session
    {
        if ($this->unreachable !== null) {
            throw new SshException($this->unreachable, SshException::UNREACHABLE);
        }

        $verifyHostKey(HostKey::parse($this->hostKey));

        $key = $credentials->privateKey();
        $accepted = $key === null
            ? in_array($credentials->passwordValue(), $this->passwords, true)
            : ($this->authorizedKeys === null || in_array(HostKey::parse($key->publicLine)->toLine(), array_map(fn (string $line): string => HostKey::parse($line)->toLine(), $this->authorizedKeys), true));

        if (! $accepted) {
            throw new SshException("The server refused the credentials for {$target->user}.", SshException::AUTHENTICATION);
        }

        $this->connections[] = ['address' => $address, 'port' => $target->port, 'user' => $target->user, 'auth' => $key === null ? 'password' : 'key'];

        $server = $this;

        return new class($server) implements Session
        {
            private bool $closed = false;

            public function __construct(private readonly FakeConnector $server) {}

            public function run(string $command, string $stdin = '', ?Closure $onOutput = null, int $timeoutSeconds = 60): CommandResult
            {
                // Like a real session, so code that runs after disconnect() fails in tests too.
                if ($this->closed) {
                    throw new SshException('The connection was already closed.', SshException::DROPPED);
                }

                return $this->server->answer($command, $stdin, $onOutput);
            }

            public function disconnect(): void
            {
                $this->closed = true;
            }
        };
    }

    public function scanHostKey(Target $target, string $address): HostKey
    {
        if ($this->unreachable !== null) {
            throw new SshException($this->unreachable, SshException::UNREACHABLE);
        }

        return HostKey::parse($this->hostKey);
    }

    /**
     * @param  (Closure(string): void)|null  $onOutput
     */
    public function answer(string $command, string $stdin, ?Closure $onOutput): CommandResult
    {
        $marker = preg_match('/#\s?([a-z0-9-]+:[a-z0-9_-]+)/', $command."\n".$stdin, $match) === 1 ? $match[1] : null;
        $this->commands[] = ['command' => $command, 'stdin' => $stdin, 'script' => $marker];

        $handler = $marker !== null ? ($this->scripts[$marker] ?? null) : null;
        $result = $handler === null ? ['', 0] : $handler($command, $stdin);
        $result = $result instanceof CommandResult ? $result : new CommandResult($result[1], $result[0]);

        if ($onOutput !== null) {
            foreach (preg_split('/(?<=\n)/', $result->output) ?: [] as $chunk) {
                if ($chunk !== '') {
                    $onOutput($chunk);
                }
            }
        }

        return $result;
    }

    /**
     * The markers of the scripts run so far, in order.
     *
     * @return list<string|null>
     */
    public function scriptsRun(): array
    {
        return array_map(fn (array $command): ?string => $command['script'], $this->commands);
    }
}
