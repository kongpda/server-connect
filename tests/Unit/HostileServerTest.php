<?php

use Kongpda\ServerConnect\Credentials;
use Kongpda\ServerConnect\HostKeyPolicy;
use Kongpda\ServerConnect\Phpseclib\PhpseclibConnector;
use Kongpda\ServerConnect\SshException;
use Kongpda\ServerConnect\Target;

/**
 * A local TCP server that runs $behaviour for one connection ($c).
 *
 * @return array{0: resource, 1: int}
 */
function hostileServer(string $behaviour): array
{
    $code = '$s = stream_socket_server("tcp://127.0.0.1:0"); echo stream_socket_get_name($s, false), "\n"; '
        .'$c = stream_socket_accept($s, 10); if (! $c) exit; '.$behaviour;
    $process = proc_open([PHP_BINARY, '-r', $code], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);

    if (! is_resource($process)) {
        throw new RuntimeException('The test server did not start.');
    }

    $port = (int) substr((string) strrchr(trim((string) fgets($pipes[1])), ':'), 1);

    return [$process, $port];
}

test('a server that never stops sending before its greeting is cut off at the connect timeout', function (string $behaviour) {
    [$process, $port] = hostileServer($behaviour);
    $started = microtime(true);

    try {
        (new PhpseclibConnector(connectTimeoutSeconds: 2))->connect(new Target('127.0.0.1', $port, 'root'), '127.0.0.1', Credentials::password('x'), HostKeyPolicy::pinned(null, fn () => null));
        $this->fail('connected to a hostile server');
    } catch (SshException $exception) {
        expect($exception->reason)->toBe(SshException::UNREACHABLE)
            ->and(microtime(true) - $started)->toBeLessThan(4);
    } finally {
        proc_terminate($process);
        proc_close($process);
    }
})->with([
    'banner flood' => ['while (@fwrite($c, str_repeat("x", 200)."\n")) {}'],
    'slow drip' => ['while (@fwrite($c, "x")) { usleep(100000); }'],
    'silence' => ['sleep(10);'],
]);
