# Security policy

server-connect opens SSH connections to servers that users of your app point
it at, so it treats the network, the server and the person adding it as
possibly hostile. The README's [Security model](README.md#security-model)
says what the package protects against and what stays your app's job.

## Reporting a vulnerability

Please report it privately through GitHub: open the repository's **Security**
tab and choose **Report a vulnerability**. Don't open a public issue.

Include what an attacker controls (the server, the network, a pasted key or
host name), what they gain, and a way to reproduce it. You'll get an answer
within a week. Fixes are released as a new version and listed in
[CHANGELOG.md](CHANGELOG.md).

## Supported versions

Only the latest minor release gets security fixes before 1.0.

## Test fixtures

`tests/fixtures` holds private keys made only for the tests. They protect
nothing, so secret-scanner alerts about them can be dismissed.
