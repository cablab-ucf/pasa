# pasa

A password store. Each change is one age file that never changes, so
copies merge by union: no conflicts, however long a device is offline.
[apasa](android/) is the Android app.

```sh
cargo install --locked --path .   # --features gui: the window; --no-default-features: no network
pasa init -y                      # password (+ YubiKey)
pasa gen mail/work -c             # new password, to the clipboard
pasa cp mail/work                 # to the clipboard, cleared after 45 s
pasa pick                         # choose with fzf, then cp
pasa mail/work otp                # one field
pasa tui                          # browse after one unlock; pasa gui: the window
nix run github:cablab-ucf/pasa    # the window (-- ARGS: pasa ARGS)
```

An entry is text as in `pass`: the password, then `key: value` lines
(`user`, `url`, `tags`, `expires`, ...) and any `otpauth://totp/` URI.
`pasa help` lists every command.

Releases: Linux x86-64 (glibc), macOS Apple silicon (`pasa.app`, signed
ad hoc: `xattr -dr com.apple.quarantine pasa.app`). Building on Linux
needs libudev, libclang, pcsc-lite and CMake (Debian: `libudev-dev
libclang-dev libpcsclite-dev cmake`); the flake brings them.

## NixOS

In `/etc/nixos/flake.nix` (with no `inputs.pasa.inputs.nixpkgs.follows`:
pasa builds on its own pin):

```nix
inputs.pasa.url = "github:cablab-ucf/pasa";
# nixosSystem's modules:
pasa.nixosModules.default
{ programs.pasa.enable = true; }   # serve = true: `pasa serve` per user
```

It installs the window, turns on `pcscd` (NFC readers), and daily runs
`nixos-rebuild switch --update-input pasa` on `/etc/nixos` (Nix's
`system.autoUpgrade`; `update = false` leaves it off). Only `pasa`
moves; the rest stays as `flake.lock` pins it. While the repository is
private, Nix needs a token that reads it, outside the store: in
`/etc/nix/nix.conf` (`nix.extraOptions`), `!include /etc/nix/github.conf`,
a root-only file holding `access-tokens = github.com=TOKEN`.

## Files

```
~/.pasa/key         store keys, sealed to the password (+ YubiKey)
~/.pasa/quick       optional: that key sealed to a YubiKey + PIN
~/.pasa/ctap        optional: that key sealed to security keys
~/.pasa/store/v/    versions: age files named by their hash
~/.pasa/store/.git  optional: git init ~/.pasa/store
~/.pasa/net/        pairings, this device's endpoint and lane
~/.pasa/stores      other stores chosen here, a path a line
```

A store is a folder: `pasa --dir DIR` (or `PASA_DIR`) uses one other than
`~/.pasa`, say one per person or purpose. The window's store menu and
`^T` in `pasa tui` switch to another, or to a new folder, by starting
pasa anew on it, so it asks for its own unlock and nothing of the last
one's stays; the phone keeps its stores side by side (Store, on the lock
screen).

Every file is an age file to a random 256-bit key (scrypt recipient,
N = 2): symmetric, so post-quantum, and `age -d` opens any version with
a key from `pasa keys`. A version is `ms parent size name`, the body and
padding; an entry is its newest version, the rest its history (`pasa
log`); size 0 deletes. Back up `~/.pasa` with anything.

With `store/.git`, pasa commits each new version and, while sync is on,
pushes (`git -C ~/.pasa/store push -u origin HEAD` once). Hooks never run, only versions are staged, and git's world holds
no key. A repository inside `v/` is never run or adopted, since the
network side can write there; to keep one you made:

```sh
mv ~/.pasa/store/v/.git ~/pasa-old.git && git init ~/.pasa/store
git -C ~/.pasa/store fetch ~/pasa-old.git HEAD && git -C ~/.pasa/store reset --soft FETCH_HEAD
```

`pasa edit` hands `$EDITOR` a file in a private directory in memory
(`$XDG_RUNTIME_DIR`, `/dev/shm`), removed afterwards; vim and nvim keep
no swap, undo or history. macOS has no such file system: use `pasa set`
(stdin) or the window.

`pasa health --pwned` asks haveibeenpwned with 5 hex digits of each
password's SHA-1 (padded answer), or a local copy named by `PASA_PWNED`.

## Keys

Each way in opens the store alone, so a store is as strong as its
weakest:

- **Password**, by Argon2id (256 MiB, 4 passes); with `-y`, a YubiKey's
  slot 2 HMAC-SHA1 answer is Argon2id's secret and both are needed
  (`ykman otp chalresp 2 SECRET` on two keys for a spare).
- **Security key** (`pasa ctap`): any FIDO2 key's `hmac-secret`, salted
  in WebAuthn's PRF form as the phone asks it, over USB or an NFC reader
  (PC/SC). No server, account or network; on macOS no Input Monitoring.
  The key agreement on the wire (P-256, AWS-LC) is not post-quantum, and
  what it carries opens nothing without the device's files.
- **Quick unlock** (`pasa quick`): a YubiKey's slot 2 and a PIN. With the
  device's files a PIN falls in days, so the password must be long. On a
  Mac without an NFC reader slot 2 needs `ykman` and Input Monitoring:
  use `ctap` there.

`passwd` changes this device's password and drops `quick` and `ctap`.
The Android build fails if its key code could reach the network
(`android/no-network.sh`).

## Sync

```sh
pasa pair phone --qr   # the QR code's password, then the code
pasa join home CODE    # or --scan: this computer's camera
pasa sync on | off     # off until turned on; pairing turns it on
pasa serve             # accept syncs (contrib/pasa-serve.service)
pasa listen            # sync when woken through pushir
pasa sync              # with every peer, now
```

Off, pasa opens no connection: no serving, listening, wakes or git
push. Check in about monthly; each device names the peers it has not
met for a month.

Pairing hands over the sealed key files (`key`, `quick`, `ctap`; one it
replaces stays as `key.old`), syncing the versions; neither asks for or
sees the password or a hardware key. A QR code's password is shown
before the code, never beside it. A short code meets once at the
[pairir](https://github.com/cablab-ucf/pairir) relay (CPace, then
X-Wing; one try, one minute).

Only ciphertext crosses the network, and received files must be
versions that match their names. On a computer the network side is a
child process that sees `store/v/` and `net/` alone (Landlock on Linux,
`sandbox-exec` on macOS); on Linux it also signals no other process and
opens no unix socket (Landlock scopes, seccomp), but `listen`'s to
pushir. Unconfined, it does not run (`PASA_UNCONFINED=1`: it does). The
process with the open store opens no socket, and no pasa process dumps
core or lets another of yours read its memory. On Android it is one
process.

| Layer | Holds if the others fall |
|---|---|
| iroh: TLS 1.3, X25519MLKEM768, raw public keys | |
| irnet: HPKE PSK mode over X-Wing, bound to the TLS session | TLS broken, one RNG rigged |
| each version an age file to a store key | everything above |

Relays see addresses, endpoint ids, when and how much. A wake is an
empty message sealed by [pushir](https://github.com/cablab-ucf/pushir):
lost or forged, it costs a sync.

## Revocation

`pasa revoke NAME` forgets the device and rotates the store key: entries
are sealed again to a new key that only pairing hands out, so pair your
other devices again from here. From then on the new key alone writes and
history is frozen (the SHA-256 of every file then held): what the
revoked device seals under the old key is ignored. Devices still on the
old key stop writing when they hear of it.

What it already read, it keeps: change those passwords at their
services. `pasa health` (Health in the window) lists each entry whose
password or one-time code it read, under any name. Any device that opens the store can revoke, a bad one too, but
that only forks the store: the others keep everything, revoke it in
turn, and pair again from a device you trust.

A store rotated before 0.4.14 shows no history from before the rotation
(`age -d` still opens it).

## Migrating

```sh
kdbx2pasa A.kdbx [B.kdbx ...] [-k KEYFILE] | pasa load   # from KeePass, with history
pasa dump | pasa2kdbx OUT.kdbx                         # to KeePassXC: KDBX4, Argon2id
contrib/migrate.sh                                     # from pasa 0.1
```

Databases that went apart merge into one history. Both pipes carry
plaintext: run them on the machine itself.

License: GPL-3.0-or-later.
