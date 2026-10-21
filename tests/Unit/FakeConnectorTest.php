<?php

use Kongpda\ServerConnect\Credentials;
use Kongpda\ServerConnect\SshException;
use Kongpda\ServerConnect\Target;
use Kongpda\ServerConnect\Testing\FakeConnector;

test('a fake session refuses to run after disconnect, like a real one', function () {
    // Otherwise a use-after-disconnect bug passes every test and only fails in production.
    $server = (new FakeConnector)->on('myapp:hello', ["hi\n", 0]);
    $server->passwords = ['pw'];
    $session = $server->connect(new Target('203.0.113.1', 22, 'root'), '203.0.113.1', Credentials::password('pw'), fn () => null);

    expect($session->run("# myapp:hello\necho hi")->output)->toBe("hi\n");

    $session->disconnect();

    expect(fn () => $session->run("# myapp:hello\necho hi"))
        ->toThrow(fn (SshException $e) => expect($e->reason)->toBe(SshException::DROPPED));
});
