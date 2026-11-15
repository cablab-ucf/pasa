# Plan

Toward the next release: everything below fixed and verified first;
per-device groups turned on only once their design holds. Reviews behind
each item: [pasa-security-reviews](https://github.com/cablab-ucf/pasa-security-reviews)
(2026-11-13, 2026-11-14).

## Now

1. **Per-device groups apart** (done): out of this release, whole. Their
   design and eleven rounds of review are in this branch's history (to
   the commit "Groups: endorsed forks undone", `cc9deb3`) and in
   pasa-security-reviews, 2026-11-14. Linked stores with a password, one
   unlock and one merged list, ship.
2. **App updates on the phone** (done; the APK builds in CI; to try on a
   phone): on start, at most daily, the newest release's `apasa-vX.apk`
   (GitHub releases), its `.sha256` checked, installed by Android's
   package installer, which takes an update only signed by the installed
   app's key. Settings: Updates, on by default, said to ask GitHub.
   Desktop: NixOS module (done); elsewhere item 5.

## Groups, next (a PR of their own)

3. **Membership by a majority of admins, not ranks.** Twelve reviews of
   the ranked chain each found a fork race; a strict majority of the last
   envelope's admins, each signing one successor at most (ML-DSA-65, no
   threshold scheme: post-quantum, offline, signatures gathered as devices
   sync), leaves no forks to race: no ranks, fork choice, redo or lost
   keys. Per-device keys, X-Wing envelopes checked sealed to all, one-time
   invitations and leave requests carry over. Then reviews until a round
   finds nothing medium or above, then on.

## Hardening still open

4. **macOS sandbox profile, deny by default** (E12): needs a Mac to test;
   sync must never stop for it.
5. **Desktop updates outside NixOS**: releases signed with minisign (a
   key in the release environment), `pasa update` checks the signature,
   the file name and the version, as chatir does.
6. **Android: networking apart from open stores** (E13): an isolated
   process with ciphertext over a narrow channel; a design first.
7. **On a phone**: unlock cancelled or raced (E2), an
   update installed.

## Release

8. Merge `main`; `cargo fmt`, `clippy -D warnings`, tests; the APK and
   desktop builds locally; then one version for the lab's repos, merged,
   tagged once, built once (CLAUDE.md).
