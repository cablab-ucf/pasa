# apasa

pasa on Android: a thin Compose UI over the same Rust (`apasa-jni`).

- Join a device (`pasa pair phone` there: type the code, or scan its QR
  code), or start a store.
- Unlock with the password and, if the store has one, a YubiKey over NFC
  (HMAC-SHA1 slot 2). Locks whenever the app leaves the screen.
- Copy password, user or TOTP (cleared after 45 s, marked sensitive).
  FLAG_SECURE, overlays hidden, no backup or device transfer.
- Wakes come through irpush, the phone's one connection shared with the
  group's other apps (`irpushGroup` = `center.cxn`, same signing key);
  irpush hands them over unopened. The app also syncs on unlock and
  after each change.

```sh
rustup target add aarch64-linux-android x86_64-linux-android
git submodule update --init
cd android && ./gradlew assembleDebug   # ANDROID_HOME, ANDROID_NDK_HOME (NDK 26.3)
```
