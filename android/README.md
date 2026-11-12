# apasa

pasa on Android: a Compose UI (`Ui.kt`, free of Android, so it renders
on a desk too; `MainActivity.kt` is what it asks of the phone) over the
same Rust (`apasa-jni`).

- Unlock by password (and a YubiKey's slot 2 held to the phone or
  plugged in), or by quick unlock: a tap of the key and a PIN. Locks when
  the app leaves the screen.
- Copies are cleared after 45 s and marked sensitive; FLAG_SECURE,
  overlays hidden, no backup or device transfer.
- Wakes come through pushir: one connection shared by the apps of the
  group `pushirGroup` = `center.cxn` (same signing key), which hand
  messages over unopened. The app syncs on unlock, after each change and
  when that connection returns, and serves while on the screen.
- The network side runs in the app's process: an isolated process could
  not open sockets, so nothing keeps it from `key` (sealed) or an open
  store's memory.

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cargo install --locked cargo-ndk
git submodule update --init
cd android && ./gradlew assembleDebug   # ANDROID_HOME, ANDROID_NDK_HOME (NDK 30)
./gradlew installDebug -Ppasa.fast=true # a quick build to try a change
```
