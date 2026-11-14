# Plan

Toward the next release: everything below fixed and verified first;
per-device groups turned on only once their design holds. Reviews behind
each item: [pasa-security-reviews](https://github.com/cablab-ucf/pasa-security-reviews)
(2026-11-13, 2026-11-14).

## Now

1. **Per-device groups off** (`group::ON = false`): `pasa group`, and
   the window's and phone's New group, Join a group, Add a device, refuse
   or are hidden. Linked stores with a password, and everything a group
   already holds, keep working.
2. **App updates on the phone**: on start, at most daily, the newest
   release's `apasa-vX.apk` (GitHub releases), its `.sha256` checked,
   installed by Android's package installer, which takes an update only
   signed by the installed app's key. Settings: Updates, on by default,
   said to ask GitHub. Desktop: NixOS module (done); elsewhere item 6.

## Groups, before they are on

3. **Admin-signed membership**, the fix for the removed-member fork and
   the invitations it made (review 2026-11-14, open, critical):
   - Each member: X-Wing key (to read) and a signing key, Ed25519 with
     ML-DSA-65 (`ml-dsa`, RustCrypto), both must verify.
   - Admins: the creator, and members it makes admin. Member records and
     envelopes count only signed by an admin current in the signer's
     chain; a removed admin's signature, or one on a key not built on the
     receiver's, counts for nothing.
   - Removing a member removes those it added and has not seen claimed.
   - A key fork between admins is said, never merged on its own.
   - Then: an adversarial review again (the fork race, puppets, invite
     cascade, replay of old envelopes), tests for each, and `ON = true`.
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
