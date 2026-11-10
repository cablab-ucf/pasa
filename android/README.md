# apasa

pasa on Android: a thin Compose UI over the same Rust (`apasa-jni`).
`Ui.kt` is the screens, free of Android so they render on a desk too;
`MainActivity.kt` is what they ask of the phone.

- First run: a password and, if wanted, a YubiKey make a new store;
  joining one from another device (its code, typed or scanned) is the
  small link in the corner.
- Then the desktop window's layout and words: entries by group with their
  user names, an entry's fields each with its copy, a form to edit them,
  a password generator, devices (pair, forget, sync) and settings.
- Unlock with the password and, if the store has one, a YubiKey over NFC
  (HMAC-SHA1 slot 2). Locks whenever the app leaves the screen.
- Copy password, user or TOTP (cleared after 45 s, marked sensitive).
  FLAG_SECURE, overlays hidden, no backup or device transfer.
- Wakes come through pushir, the phone's one connection shared with the
  group's other apps (`pushirGroup` = `center.cxn`, same signing key);
  whoever holds it hands them over unopened. The app also syncs on unlock,
  after each change, and when that connection comes back.

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cargo install --locked cargo-ndk
git submodule update --init
cd android && ./gradlew assembleDebug   # ANDROID_HOME, ANDROID_NDK_HOME (NDK 30)
```
