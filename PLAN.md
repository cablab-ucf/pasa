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

3. **Signed membership chain** (review 2026-11-14, then its design
   reviewed adversarially the same day: records any key holder could
   overwrite, backdated ranks, reusable pairing secrets; all replaced).
   - **Keys**: each device, per group, one seed it makes itself, never
     sent: X-Wing (to open envelopes), Ed25519 and ML-DSA-65 (to sign;
     both must verify). Its id: SHA-256 of the three public keys.
   - **Root**: the creator; joining pins its id (sealed in `member`).
   - **Envelopes**: the only authority. Each: epoch, the hash of the one
     before, the member list (name, role, rank epoch, adder, public keys),
     every key; signed by an admin of the one before; sealed to each
     member (X-Wing), and its body kept under that epoch's store key, so a
     device added later checks the whole chain from the root.
   - **Rules** (`follows`): the keys kept or one new; members unchanged
     but for those the signer outranks (or itself) removed or demoted, a
     member made admin at this epoch (ranked last), devices added by the
     signer at this epoch, never one the chain held before.
   - **Forks**: the higher admin's holds. A removal or demotion voids
     what its subject signed outside the removal's own past (forks before
     or after it); removals by the highest first.
   - **Joining**: an admin's one-time invitation (local); the joiner's
     public keys and the root, sealed with that pairing's secret; admitted
     once. **Leaving**: an admin, an envelope without it (the next admin
     makes a new key); a member, a signed request sealed to the admins.
   - **Retire notices** do not count in groups (any member could write
     one); the envelope chain says which key is newest.
   - Tests: signed add/remove; a non-admin's envelope; a removed admin's
     race and puppet; its fork from long ago; two admins at once; a
     stranger's and a member's requests; junk and a member's retire
     notice; a new password; leaving.
   - Then: one more adversarial review of the chain, then `ON = true`.
4. **Two changes at once** (done): the higher admin's holds; an admission
   set aside is made again at the next open (the invitation is kept until
   the device is in the chain).

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
