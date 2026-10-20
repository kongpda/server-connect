<?php

/*
| `composer install && vendor/bin/pest`. scripts/test-ssh also runs the
| integration tests against a real sshd.
*/

$autoloaders = [
    __DIR__.'/../vendor/autoload.php',
];

foreach ($autoloaders as $autoloader) {
    if (is_file($autoloader)) {
        require $autoloader;
        break;
    }
}

spl_autoload_register(function (string $class): void {
    $prefix = 'Kongpda\\ServerConnect\\';

    if (str_starts_with($class, $prefix)) {
        $path = __DIR__.'/../src/'.str_replace('\\', '/', substr($class, strlen($prefix))).'.php';

        if (is_file($path)) {
            require $path;
        }
    }
});

function keyFixture(string $name): string
{
    return (string) file_get_contents(__DIR__.'/fixtures/'.$name);
}

/**
 * Syntax-check a POSIX sh script with `sh -n`.
 */
function shellSyntaxOk(string $script): bool
{
    $process = proc_open(['sh', '-n'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);

    if (! is_resource($process)) {
        return false;
    }

    fwrite($pipes[0], $script);
    fclose($pipes[0]);
    stream_get_contents($pipes[1]);
    $errors = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);

    return proc_close($process) === 0 && $errors === '';
}
