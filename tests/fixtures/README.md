Test keys made with `ssh-keygen` (OpenSSH 9) for the test suite only. They protect nothing.
The passphrase-protected ones use the passphrase `correct horse` and `-a 2` KDF rounds, so
the pure-PHP bcrypt_pbkdf stays fast in tests (real keys use 16 rounds, about 10 s each).
