# Security

pasa is a password manager: a store of versioned, encrypted entries kept as
files, synced device to device over iroh. This is the threat model it is
built and reviewed against. Report a vulnerability privately (GitHub
security advisory on this repository), not in an issue.

## Who is trusted with what

| Party | Can | Cannot |
|---|---|---|
| Network, relay operator | see endpoint ids, timing, sizes; drop | read or alter versions; join a sync without the pairing secret |
| Someone with the store's files (a synced folder, a backup, a stolen disk) | delete or roll back versions on that copy (a sync restores them); try passwords offline against Argon2id | read an entry without the password (and the hardware key, if set) |
| A paired device | sync every version; wake our lane on any https relay | read without the store password; make us dial plain http |
| A device that pairing or `forget` removed | keep what it had | come back by introduction (forgotten stays forgotten); read versions under a key rotated after `revoke` |
| Local user on the same machine | nothing from argv: codes, secrets and queries go by stdin | read the store, the clipboard after 45 s (where the platform allows) |

## Cryptography

- Each version is an age file with its own random file key, sealed to the
  store key as an age scrypt recipient: the passphrase is the random
  256-bit store key, so the work factor is pinned at N=2 (`set_max_work_factor`)
  and a hostile file cannot force a costly open. Name, time, parent and size
  are inside the ciphertext; files are named by SHA-256 (128 bits), and
  bodies re-check their header, so entries cannot be swapped.
- The store key is sealed under a KEK: Argon2id, 256 MiB, t=4, p=1, with the
  YubiKey's HMAC-SHA1 answer (slot 2, touch required for new set-ups) or a
  FIDO2 hmac-secret as the Argon2 secret. Missing the key fails the unlock;
  it never falls back to the password alone. Argon2's memory is zeroized.
- Sync: iroh QUIC, TLS 1.3 with X25519MLKEM768 only (irnet), and a 256-bit
  pre-shared key bound to the TLS exporter (ALPN `pasa/7`, `pasa/6` for
  peers before 0.4.19).
- Pairing: pairir short codes (CPace, one online guess per code) or a QR
  sealed under a 99-bit password (Argon2id). Quick unlock (PIN) never
  leaves its device.
- Android updates: the APK's SHA-256 from the release, then Android's own
  signer and version checks.

## Platform defences

Linux: the network side runs as a separate process under Landlock (files;
seccomp blocks unix sockets where Landlock cannot). Android: FLAG_SECURE, overlays hidden, backups off, clips
marked sensitive and cleared after 45 s if still ours, store locked on
leaving (the picker too) and on waking past the lock time. Desktop: the
window is capture-protected, locks idle even minimized, and terminal
output escapes control characters.

## Known limits (accepted, with reason)

- Rollback on one copy: deleting the newest version files reverts an entry
  there until the next sync (the union design keeps every version); the
  CLI says so when git is set up.
- Quick unlock: a 4-6 digit PIN slows only a thief who also holds the
  YubiKey; a FIDO2 PIN (counted by the key) is the stronger choice.
- The YubiKey answer to the stored challenge is fixed until the password
  changes: one skim of the key gives that factor.
- Android: network code runs in the same process as unlocked keys (the
  desktop confines it); the clipboard cannot be read off screen, so it is
  cleared then regardless; Java strings are not zeroized.
- Landlock has no network rules on older kernels; macOS confines files only.
- Copies of plaintext in memory (forms, health checks) are not all wiped.
- Desktop tarballs are checked by SHA-256 only (no signature yet).
- Old peers (0.4.11-0.4.18) still send their quick file when they pair.

## Wire compatibility

Peers from v0.4.11 on still sync (CLAUDE.md): the ALPN, `swap`'s frames,
pairing payloads and QR text are unchanged in v0.5.0.
