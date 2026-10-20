# kongpda/server-connect

Connect to Linux servers over SSH from PHP without the usual sharp edges:
a VPS at any provider, a VM you run yourself, or any other Linux box you can
reach on SSH. It is framework-light (PHP 8.3+, phpseclib v3, ext-sodium) and
has an optional Laravel service provider. It holds no app logic (no models,
queues or UI).

Used by [Proofr](https://github.com/kongpda/proofr) and
[Deplr](https://github.com/kongpda/deplr). It assumes the server at the other
end may be hostile: see [Security model](#security-model).

## Install

It isn't on Packagist yet, so add its repository before requiring it:

```sh
composer config repositories.server-connect vcs https://github.com/kongpda/server-connect
composer require kongpda/server-connect:^0.3
```

## Where it connects

Anything that runs sshd and that the machine running your app can reach:

| Target | How |
| --- | --- |
| A VPS or cloud VM (Hetzner, DigitalOcean, AWS, Vultr…) | Its public IP or DNS name. |
| A VM on your own network (Proxmox, ESXi, a home lab) | Its LAN address (10/8, 172.16/12, 192.168/16), with `allowPrivate` on. |
| A VM on your own machine (Multipass, UTM, VirtualBox, Parallels, VMware, Lima) | Its host-only or bridged address, usually 192.168.x.x, when the app runs on the same machine. A VM that is only reachable through a port forward on `127.0.0.1` needs `allowLocal` (see below). |
| A machine behind NAT, reached from an app in the cloud | Put both on a tailnet (Tailscale or Headscale, 100.64/10) or a WireGuard network and connect to that address, with `allowPrivate` on. An app with a pull-mode agent can skip inbound SSH entirely. |

`TargetGuard` decides which addresses are allowed:

| Addresses | Allowed? |
| --- | --- |
| Public addresses | Yes. |
| Private networks: 10/8, 172.16/12, 192.168/16, 100.64/10 (CGNAT, tailnets), fc00::/7 (ULA), fec0::/10 | Only with `allowPrivate` (Laravel: `SERVER_CONNECT_ALLOW_PRIVATE=true`). |
| Loopback, this machine's interface addresses, `APP_URL`'s host and `ownHosts` | Only with `allowLocal` (`SERVER_CONNECT_ALLOW_LOCAL=true`). |
| Link-local (169.254/16, cloud metadata), multicast, unspecified, reserved, 192.0.0/24, 198.18/15, 64:ff9b:1::/48, 100::/64 | Never. |

IPv4 addresses wrapped in IPv6 (mapped, translated, compatible, NAT64, 6to4)
are judged as IPv4. **In a multi-tenant app leave both off.** Otherwise a user
can point SSH at your internal network (other servers, metadata services such
as 100.100.100.200 or fd00:ec2::254) and use the error messages to scan it.
Turn `allowPrivate` on for a self-hosted, single-team install that needs to
reach VMs on its own LAN or tailnet; `allowLocal` only for development.

`Facts\Probe` tells you what kind of machine you reached: `provider` names the
cloud, or the hypervisor of a VM you run yourself (`qemu`, `virtualbox`,
`vmware`, `parallels`), and `virtualization` is `systemd-detect-virt`'s answer
(`none` on bare metal, `kvm`, `lxc`, `docker`…), with `isVirtualMachine()` and
`isContainer()` helpers. In a container, Docker, swap and firewall recipes
usually need the host's help, so check `isContainer()` before offering them.

## What it does

| Piece | What for |
| --- | --- |
| `Target` | Validates host, port and user strictly. Rejects a leading `-`, whitespace, control characters and `user@` smuggled into the host, so nothing can be read as an ssh option. |
| `TargetGuard` | Resolves the host once and refuses addresses as described above. Connect to the IP it returns, so DNS can't change between check and connect. Always pass the address it returns to `connect()`, never the host name. |
| `HostKey`, `HostKeyPolicy`, `HostKeyChanged` | The host key check runs **before** authentication. `HostKeyPolicy::expect($fingerprint)` accepts only a fingerprint the user checked out of band (the safest). `HostKeyPolicy::pinned($fingerprint, $onFirstUse)` pins on first use, then enforces it; the check it returns remembers the first key, so a second connection with it must reach the same server. A mismatch throws `HostKeyChanged` with the presented key and the pinned fingerprint, so a UI can show old vs new. Fingerprints match `ssh-keygen -l` (`SHA256:…`). RSA host keys must be 2048–16384 bits with a normal exponent. |
| `PrivateKey` | Loads OpenSSH and PEM keys (Ed25519, ECDSA, RSA ≥ 2048), passphrase-protected or not, and generates Ed25519 keys. Errors carry a reason code: `passphrase_required`, `wrong_passphrase` or `unsupported`. `isEncrypted()` works without the passphrase. Passphrase-protected OpenSSH keys may use at most 64 bcrypt rounds, and encrypted PKCS#8 keys are refused, because the key text sets the work factor. Keys never print or serialize; export them on purpose with `toOpenSsh(?passphrase)`. |
| `Credentials` | A key, or a password. Both are hidden from `var_dump` and refuse to serialize. |
| `Connector` / `Session` | The interface, implemented by `Phpseclib\PhpseclibConnector`. The TCP connect and handshake share one 8 s timeout, and keepalive runs every 5 s. Once logged in, the connection forgets the password or key, and the session refuses to serialize. `run()` has a wall-clock timeout that holds even while output keeps coming, writes stdin and then EOF, merges stderr into the output, returns the exit code, and can stream output to a callback. It keeps at most 4 MB of output (`truncated` is set beyond that; the callback still sees all of it). |
| `KeyInstaller` | Logs in with a password once and installs a public key using a fixed script that reads the key from **stdin**. The script sets `umask 077` and `~/.ssh` 0700 / `authorized_keys` 0600, repairs a missing final newline, adds the key only once, runs `restorecon` and prints an OK marker. It then proves that logging in with the key works. |
| `Facts\Probe` | One read-only round trip delimited by markers. It collects OS, arch, CPU, memory, disk, load, uptime, root/sudo, systemd, curl, package manager, Docker (version, active, access), reboot-required, ufw, fail2ban, unattended-upgrades, swap, sshd settings, the dpkg lock, the cloud provider or local hypervisor (from DMI `sys_vendor` and `product_name`) and the virtualization type (`systemd-detect-virt`). You can add read-only sections of your own. |
| `Monitor\MetricsProbe` | Agentless metrics: CPU % from two `/proc/stat` samples, plus memory, disk, load and uptime. |
| `Shell\Shims` | The prelude every script gets. `$SUDO` is empty for root and `sudo -n` otherwise, so it never hangs on a prompt. `$DOCKER` falls back to `sudo -n docker`. `$APT` is non-interactive, keeps existing config files and waits for the dpkg lock. `sc_wait_dpkg` waits for first-boot updates to finish. |
| `Recipes` | A closed set of server-prep scripts, invoked by **id only**. They take declared, pattern-checked params and have a safety level (`read_only`, `mutating`, `high_risk`). Ids: `essentials`, `docker`, `swap`, `ufw` (always allows the ports sshd listens on and the one this connection uses), `fail2ban`, `unattended-upgrades`, `harden-ssh` (refuses until the login user has an SSH key), `apt-upgrade` and `reboot`. `prepareSequence()` gives the order for a "Prepare server" stepper. |
| `Testing\FakeConnector` | A scripted SSH server for tests. You set its host key, the keys and passwords it accepts and how it answers each script, matched by the marker comment on the script's first line. Scripts without a handler return exit 0 and no output, so never bind it outside tests. |

## Use

```php
use Kongpda\ServerConnect\{Credentials, HostKey, HostKeyPolicy, PrivateKey, Target, TargetGuard};
use Kongpda\ServerConnect\Facts\Probe;
use Kongpda\ServerConnect\Phpseclib\PhpseclibConnector;

$target = new Target('203.0.113.10', 22, 'deploy');
$address = (new TargetGuard(ownHosts: ['ci.example.com']))->resolve($target->host);
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
users. Send them on stdin, as part of a script for `sh -s`. `Probe::script()`
and recipes run your extra snippets verbatim: never put user input in them.

## Laravel

The service provider is auto-discovered. It binds `Connector` to phpseclib and
builds `TargetGuard` from `config/server-connect.php` (`connect_timeout`,
`keepalive`, `min_rsa_bits`, `max_output_bytes`, `allow_local`,
`allow_private`, `own_hosts`), always counting `APP_URL`'s host as one of your
own. If your app has its own egress policy, add the package to
`extra.laravel.dont-discover` and bind `Connector` yourself. Publish the config with
`php artisan vendor:publish --tag=server-connect-config`. In tests, bind a
`FakeConnector` instance.

## Security model

The package assumes the network and the server can be hostile, and that the
person adding a server may be trying to attack the app that runs it.

What it does for you:

- **Before authentication.** The host key is checked before any credential is
  sent. Only modern algorithms are offered: curve25519 or ECDH key exchange,
  ChaCha20-Poly1305, AES-GCM or AES-CTR with SHA-2 MACs, and Ed25519, ECDSA or
  SHA-2 RSA host keys. No SHA-1, no group exchange, no CBC.
- **A hostile server can't hold a worker.** The greeting must arrive within
  the connect timeout and the first 8 KB. RSA host keys with a huge modulus or
  exponent are refused before their signature is checked. Commands have a
  wall-clock timeout and an output cap that covers stderr too. If closing a
  timed-out command takes more than 5 s, the connection is dropped.
- **A pasted key can't hold a worker.** Key derivation rounds are capped, and
  only OpenSSH, PEM and PKCS#8 key text is read (PuTTY keys set their own
  Argon2 cost).
- **Secrets stay out of places they leak from.** `PrivateKey`, `Credentials`
  and sessions don't print or serialize, the connection forgets credentials
  after login, login errors never echo phpseclib's messages, and
  `KeyInstaller` sends the key on stdin.

What stays your app's job:

- **Store private keys encrypted, with a key that isn't your web app key**
  (envelope encryption, a KMS, or at least a separate key file), and bind the
  ciphertext to its owner so it can't be swapped between rows.
- **Never store passwords.** Use them once, in the request, to install a key
  (`KeyInstaller`). Don't put them, or passphrases, in queue payloads, caches,
  logs or flashed form input.
- **Prefer a verified fingerprint over trust on first use** when a password
  is about to be sent: a man in the middle on the first connection would get
  it.
- **Run connections in queued jobs with a timeout.** DNS lookups, some
  handshake stalls, and a server that floods SSH control messages (which
  phpseclib handles internally, out of this package's reach) aren't covered by
  this package's timeouts.
- **Keep `allowPrivate` and `allowLocal` off** in a multi-tenant app.
- **Remove the key from `authorized_keys`** when a server is removed, or tell
  the user how.
- A command that times out has its channel closed, but the remote process may
  keep running. Wrap long commands in `timeout`.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Tests

```sh
composer test                    # unit tests (FakeConnector, sh -n on every script)
composer lint                    # pint
composer analyse                 # phpstan, level 7
scripts/test-ssh                 # the integration tests against a real sshd in Docker
SERVER_CONNECT_SSHD=127.0.0.1:2222 SERVER_CONNECT_SSHD_PASSWORD=… vendor/bin/pest tests/Integration
```

## Releasing

Add the changes to [CHANGELOG.md](CHANGELOG.md), then create a GitHub release
with a `vX.Y.Z` tag on `main`; Composer reads versions from tags. Before 1.0,
a minor version may break the API. Apps pick up a new version with
`composer update kongpda/server-connect`.
