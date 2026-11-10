# apasa

pasa on Android: a thin Compose UI over the same Rust (`apasa-jni`).

- Join a device (`pasa pair phone` there: type the code, or scan its QR
  code), or start a store.
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
