# Changelog

## 0.4.0

Fixes from a second review: work limits phpseclib left open, recipes that
could lock you out of a server, and server output that could mislead or
crash the caller. Check the "Changed" list before upgrading.

### Changed

- `Probe::parse()` throws `SshException` (`dropped`) when the output has no
  `@@END@@` marker. Before, it returned facts with the missing parts read
  as "no".
- `MetricsProbe::run()` throws `SshException` (`timeout`) on a timeout.

### Fixed

- `PrivateKey::load()` read PuTTY keys, whose Argon2 cost comes from the key
  text, so a pasted key could hold a worker past the work-factor cap. Only
  OpenSSH, PEM (RSA/EC) and PKCS#8 text starting with its `-----BEGIN` line is
  accepted now.
- stderr didn't count toward memory use: phpseclib kept its own uncapped copy
  of it. That copy is now dropped as it arrives.
- A command that ended without an exit status (killed by a signal) reported
  the previous command's exit code, so it could look successful. It is now
  null.
- Closing a timed-out command could wait forever while the server kept
  sending. After 5 s the connection is dropped and the result still reports
  the timeout.
- `SERVER_CONNECT_ALLOW_PRIVATE` and `SERVER_CONNECT_ALLOW_LOCAL` turned on for
  any non-empty value, including `off` and `no`. Only true values (`true`,
  `1`, `on`, `yes`) turn them on now. If you published the config file,
  publish it again or make the same change.
- `Target` accepted a host with a trailing newline, and strings like
  `1.2.3.4:22` or `[example.com]`. It now accepts only an IP address, a
  bracketed IPv6 address or a host name.
- The `ufw` recipe set `default deny incoming` before allowing SSH, and
  allowed only the ports `sshd -T` reports. It now allows SSH first, including
  the port this connection reached on the server (`$SSH_CONNECTION`), which
  differs from sshd_config under socket activation. `fail2ban` watches the
  same ports.
- `harden-ssh` turned off passwords even when the login user had no SSH key,
  locking them out. It now refuses until a key is in one of their authorized
  keys files (unless `AuthorizedKeysCommand` is set).
- The `swap` recipe accepted sizes like `0999`, which sh reads as octal and
  aborts on. A resize that failed left the server with no swap; it now puts
  the old size back.
- A facts probe whose answer stopped part way (or went over the output cap)
  read the missing sections as "no sudo", "no ufw", "dpkg free". It now
  throws `SshException` (`dropped`). `MetricsProbe::run()` throws on a
  timeout instead of returning blanks.
- Numbers from a server like `1e999`, `NAN` or `-5` became `INF` or negative
  values, and `json_encode` of the facts threw. They now read as unknown
  (`null`), as does memory use when "available" is more than the total.
- The error for a probe that didn't run quoted the server's first lines
  uncapped. It now keeps at most 200 printable characters.
- CPU use counted guest time twice on hosts running VMs.
- Every metrics poll ran `docker ps`, and `sudo -n docker ps` (logged in the
  auth log). Metrics scripts no longer load the shell shims.
- A command in a recipe or probe that read stdin (an installer, apt) could
  swallow the rest of the script. Script bodies now run with stdin from
  `/dev/null`.
- `ufw`, `fail2ban`, `unattended-upgrades` and `apt-upgrade` failed with
  `env: command not found` style errors on servers without apt. They now say
  they need Debian or Ubuntu.
- The `ufw` recipe accepted a port range without a protocol, which ufw
  rejects. The range now needs `/tcp` or `/udp`.
- A connection that dropped during login was reported as an authentication
  failure. It's now `dropped`.
- `scripts/test-ssh` went on to run the tests when sshd never started. It
  now stops with sshd's log.

### Documented

- phpseclib signs with SHA-1 (`ssh-rsa`) when a server refuses an RSA client
  key's SHA-2 signature.
- Two workers pinning a new server's fingerprint at once: save the pin with a
  conditional write.

### Added

- `scripts/test-recipes` runs the firewall and SSH hardening recipes in a
  Debian container (also in CI).

## 0.3.0

Security hardening after a review that assumed a hostile server. Some
defaults changed, so check the "Changed" list before upgrading.

### Changed

- `TargetGuard` refuses private networks (10/8, 172.16/12, 192.168/16,
  100.64/10, fc00::/7, fec0::/10) unless `allowPrivate` is on (Laravel:
  `SERVER_CONNECT_ALLOW_PRIVATE=true`). It also always refuses 192.0.0/24,
  198.18/15, 64:ff9b:1::/48 and 100::/64, judges ::ffff:0:a.b.c.d as IPv4,
  and counts this machine's interface addresses as its own.
- `PhpseclibConnector` offers only curve25519/ECDH key exchange, AEAD or
  AES-CTR ciphers, SHA-2 MACs and Ed25519, ECDSA or SHA-2 RSA host keys.
  Servers older than OpenSSH 6.5 can't connect.
- RSA host keys must be 2048–16384 bits (`minRsaBits` is configurable) with
  an exponent of at most 32 bits.
- `PrivateKey::load()` refuses OpenSSH keys with more than 64 bcrypt rounds
  and encrypted PKCS#8 keys.
- A check from `HostKeyPolicy::pinned(null, …)` remembers the first key and
  enforces it afterwards, and `KeyInstaller` requires its second connection
  to reach the same server.
- The `ufw` and `fail2ban` recipes use the ports sshd listens on instead of
  the port the app connected to. `harden-ssh` no longer loosens a stricter
  `PermitRootLogin`.

### Fixed

- `run()` timed out only while the command was silent, and kept all output in
  memory. The deadline now holds while output keeps coming, and output is
  capped (4 MB by default; `CommandResult::$truncated`).
- The connect timeout didn't cover a server that sends endless text before
  its greeting or trickles data. TCP connect and handshake now share one
  deadline, and the greeting must arrive in the first 8 KB.
- The live connection kept the password or key for phpseclib's reconnects,
  where a dump or serialization could expose it. It is cleared after login,
  and sessions refuse to serialize.
- Timeouts of 0 or less meant "no timeout"; they are now at least 1 second.

### Added

- `allow_private`, `min_rsa_bits` and `max_output_bytes` settings.
- SECURITY.md, this changelog, and the README's security model.

## 0.2.0

- `HostKey::parse()` and `fromBlob()` take a minimum RSA size.
- Facts detect local VMs and containers (`virtualization`).
- The package became standalone.

## 0.1.0

- First release, extracted from Proofr.
