# Changelog

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
