# Plan

Toward the next release: everything below fixed and verified first;
per-device groups turned on only once their design holds. Reviews behind
each item: [pasa-security-reviews](https://github.com/cablab-ucf/pasa-security-reviews)
(2026-11-13, 2026-11-14).

## Now

1. **Per-device groups off** (done) (`group::ON = false`): `pasa group`, and
   the window's and phone's New group, Join a group, Add a device, refuse
   or are hidden. Linked stores with a password, and everything a group
   already holds, keep working.
2. **App updates on the phone** (done; the APK builds in CI; to try on a phone): on start, at most daily, the newest
   release's `apasa-vX.apk` (GitHub releases), its `.sha256` checked,
   installed by Android's package installer, which takes an update only
   signed by the installed app's key. Settings: Updates, on by default,
   said to ask GitHub. Desktop: NixOS module (done); elsewhere item 6.

## Groups, before they are on

3. **Admin-signed membership** (review 2026-11-14, open, critical: a
   removed member races a key fork back in; invitations it made outlive
   it). Design:
   - **Keys**: each device, per group, one seed it makes itself, never
     sent: X-Wing (to open envelopes), Ed25519 and ML-DSA-65 (to sign;
     both must verify). Its id: SHA-256 of the three public keys.
   - **Root**: the creator. The group's id is the root's id; joining pins
     it (sealed in `member`). Authority runs from it alone.
   - **Records** (`.pasa/members/ID`, `.pasa/removed/ID`): signed by an
     admin; an admin is the root, or one an admin's record names admin.
     Every record and envelope carries an epoch (the envelope count). A
     removal at epoch e voids its subject's signatures at e and after; a
     member may remove itself (leave).
   - **Envelopes**: the keys, sealed to each member (X-Wing), with epoch,
     the key before, and an admin's signature over all of it. A device
     takes a new key only from a valid admin's envelope built on a key it
     holds. Non-admins never make keys.
   - **Joining**: no key is handed. The joiner makes its seed, then puts
     its public keys in `v/`, sealed with the pairing secret (scrypt
     passphrase), which only it and the admin that paired it hold; that
     admin signs its record and seals the keys to it.
   - **Forks**: two valid admins at once merge to what neither removed. A
     removed admin's race is bounded to the time before a member hears of
     the removal; a removed non-admin has nothing to race with.
   - Built (tests: signed add/remove, a removed member's key and writes
     ignored, a removed admin's race and puppet voided, two admins at once,
     forged records, a stranger's request, a new password, leaving).
   - Then: an adversarial review again (fork races, puppet records,
     replayed envelopes, epochs, joins), a test for each, then `ON = true`.
4. **Two removals at once**: said today; with admins, resolved by one
   admin removing again.

## Hardening still open

5. **macOS sandbox profile, deny by default** (E12): needs a Mac to test;
   sync must never stop for it.
6. **Desktop updates outside NixOS**: releases signed with minisign (a
   key in the release environment), `pasa update` checks the signature,
   the file name and the version, as chatir does.
7. **Android: networking apart from open stores** (E13): an isolated
   process with ciphertext over a narrow channel; a design first.
8. **On a phone**: unlock cancelled or raced (E2), groups' screens, an
   update installed.

## Release

9. Merge `main`; `cargo fmt`, `clippy -D warnings`, tests; the APK and
   desktop builds locally; then one version for the lab's repos, merged,
   tagged once, built once (CLAUDE.md).
