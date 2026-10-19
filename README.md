# kongpda/server-connect

Connect to Linux servers over SSH from PHP without the usual sharp edges.
It is framework-light (PHP 8.3+, phpseclib v3, ext-sodium) and has an optional
Laravel service provider. Proofr uses it to connect VPSes as CI runners. It
holds no app logic (no models, queues or UI), so other apps can reuse it.

The hardening follows DeployDesk's Rust server layer (`ssh.rs`, `keysetup.rs`,
`facts.rs`, `monitor.rs`, `shim.rs`, `recipes.rs`) and deplr's host key and
key readers.

## What it does

| Piece | What for |
| --- | --- |
| `Target` | Validates host, port and user strictly. Rejects a leading `-`, whitespace, control characters and `user@` smuggled into the host, so nothing can be read as an ssh option. |
| `TargetGuard` | SSRF guard. It resolves the host once and refuses loopback, unspecified, link-local (cloud metadata), multicast and the app's own addresses. You then connect to the IP it returns, so DNS can't change between check and connect. Private ranges are allowed (VPS LANs, tailnets). |
| `HostKey`, `HostKeyPolicy`, `HostKeyChanged` | Host keys are trust-on-first-use: the key is pinned, then enforced. The check runs **before** authentication. A mismatch throws `HostKeyChanged`, which carries the presented key and the pinned fingerprint, so a UI can show "old vs new" and offer an explicit replace (`HostKeyPolicy::expect($verifiedFingerprint)`). Fingerprints match `ssh-keygen -l` (`SHA256:…`). Ed25519 is the preferred host key algorithm, so the same key is pinned every time. |
| `PrivateKey` | Loads OpenSSH and PEM keys (Ed25519, ECDSA, RSA ≥ 2048), passphrase-protected or not, and generates Ed25519 keys. Errors carry a reason code: `passphrase_required`, `wrong_passphrase` or `unsupported`. `isEncrypted()` works without the passphrase. Keys never print or serialize; export them on purpose with `toOpenSsh(?passphrase)`. |
| `Credentials` | A key, or a password used once. Both are hidden from `var_dump` and refuse to serialize, so they can't leak into a queue payload. |
| `Connector` / `Session` | The interface, implemented by `Phpseclib\PhpseclibConnector`. Connect times out after 8 s and keepalive runs every 5 s. `run()` has a wall-clock timeout, writes stdin and then EOF, merges stderr into the output, returns the exit code, and can stream output to a callback. |
| `KeyInstaller` | Logs in with a password once and installs a public key using a fixed script that reads the key from **stdin**. The script sets `umask 077` and `~/.ssh` 0700 / `authorized_keys` 0600, repairs a missing final newline, adds the key only once, runs `restorecon` and prints an OK marker. It then proves that logging in with the key works. |
| `Facts\Probe` | One read-only round trip delimited by markers. It collects OS, arch, CPU, memory, disk, load, uptime, root/sudo, systemd, curl, package manager, Docker (version, active, access), reboot-required, ufw, fail2ban, unattended-upgrades, swap, sshd settings, the dpkg lock and the cloud provider (from DMI `sys_vendor`). You can add read-only sections of your own. |
| `Monitor\MetricsProbe` | Agentless metrics: CPU % from two `/proc/stat` samples, plus memory, disk, load and uptime. |
| `Shell\Shims` | The prelude every script gets. `$SUDO` is empty for root and `sudo -n` otherwise, so it never hangs on a prompt. `$DOCKER` falls back to `sudo -n docker`. `$APT` is non-interactive, keeps existing config files and waits for the dpkg lock. `sc_wait_dpkg` waits for first-boot updates to finish. |
| `Recipes` | A closed set of server-prep scripts, invoked by **id only**. They take declared, pattern-checked params and have a safety level (`read_only`, `mutating`, `high_risk`). Ids: `essentials`, `docker`, `swap`, `ufw` (always allows the SSH port in use), `fail2ban`, `unattended-upgrades`, `harden-ssh`, `apt-upgrade` and `reboot`. `prepareSequence()` gives the order for a "Prepare server" stepper. |
| `Testing\FakeConnector` | A scripted SSH server for tests. You set its host key, the keys and passwords it accepts and how it answers each script, matched by the marker comment on the script's first line. |

## Use

```php
use Kongpda\ServerConnect\{Credentials, HostKey, HostKeyPolicy, PrivateKey, Target, TargetGuard};
use Kongpda\ServerConnect\Facts\Probe;
use Kongpda\ServerConnect\Phpseclib\PhpseclibConnector;

$target = new Target('203.0.113.10', 22, 'deploy');
$address = (new TargetGuard(allowLocal: false, ownHosts: ['ci.example.com']))->resolve($target->host);
$key = PrivateKey::load($storedKeyText);              // or PrivateKey::load($text, $passphrase)

$verify = HostKeyPolicy::pinned($pinnedFingerprint, function (HostKey $first) {
    // first connection: store $first->toLine() and $first->fingerprint()
});

$session = (new PhpseclibConnector())->connect($target, $address, Credentials::key($key), $verify);
$facts = Probe::run($session);
$result = $session->run('sh -s', $script, fn (string $chunk) => print $chunk, timeoutSeconds: 900);
$session->disconnect();
```

Secrets never go on a remote command line, where `ps` would show them to other
users. Send them on stdin, as part of a script for `sh -s`.

## Laravel

The service provider is auto-discovered. It binds `Connector` to phpseclib and
builds `TargetGuard` from `config/server-connect.php` (`connect_timeout`,
`keepalive`, `allow_local`, `own_hosts`), always counting `APP_URL`'s host as
one of your own. Publish the config with
`php artisan vendor:publish --tag=server-connect-config`. In tests, bind a
`FakeConnector` instance.

## Notes

- Passphrase-protected OpenSSH keys use bcrypt-pbkdf. In pure PHP a key made
  with the default 16 rounds takes several seconds to decrypt. Decrypt it once
  and keep it (for example re-encrypted with your app key) instead of
  decrypting it for every connection.
- The package doesn't store anything. Pinning, key storage and passphrase
  caching belong to your app.

## Tests

```sh
vendor/bin/pest                  # unit tests (FakeConnector, sh -n on every script)
scripts/test-ssh                 # (Proofr repo) the integration tests against a real sshd in Docker
SERVER_CONNECT_SSHD=127.0.0.1:2222 SERVER_CONNECT_SSHD_PASSWORD=… vendor/bin/pest tests/Integration
```
