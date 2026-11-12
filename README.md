# pasa

A small password store. Each change is one age file that never changes, so
copies merge by union: no conflicts, however long a device is offline.

```sh
cargo install --locked --path .   # --no-default-features: no network at all
pasa init -y                      # password + YubiKey (-y optional)
pasa gen mail/work -c             # new password, to the clipboard
pasa cp mail/work                 # clipboard, cleared after 45 s if unchanged
pasa pick                         # choose with fzf, then as cp (pick user: that field)
pasa mail/work otp                # a field: pass, user, otp, ...
```

```sh
pasa tui                          # one unlock: type to filter, Enter copies
pasa gui                          # the same in a window (--features gui)
nix run github:cablab-ucf/pasa          # NixOS, macOS: the window (-- ARGS: pasa ARGS), nothing to install
```

`pasa help` lists every command. An entry is text as in `pass`: the
password, then `key: value` lines and any `otpauth://totp/` URI.
[apasa](android/) is the Android app.

## Desktop

One binary is the command line, the terminal browser and the window. A
release has it for Linux (x86-64, glibc) and macOS (Apple silicon, with
`pasa.app`); elsewhere, and on NixOS, build it: the flake's `pasa-gui`
(default) or `pasa-cli` (no window libraries), or `cargo install --locked
--path . --features gui`. Built on Linux it needs libudev, libclang and
pcsc-lite (Debian: `libudev-dev libclang-dev libpcsclite-dev`); the flake
brings them. `pasa.app` is
signed ad hoc, by no Apple account:
after a download, `xattr -dr com.apple.quarantine pasa.app`.

The window is laid out as the Android app is: a first run asks for the
password and, if wanted, a YubiKey, with joining another device's store in
the corner; then groups, entries with their user names, the chosen entry's
fields each with its copy, a form to edit them, a password generator,
devices (pair, forget, sync) and settings (`~/.pasa/ui`: when to lock, the
theme). An entry is still the text `pass` reads: the form writes `user:`
and `url:` lines. Both also show an entry's history (each version, with a
way back) and its files.

Both also have: a `tags: a, b` line to filter by; an `expires:` date; any
other `name: value` line as a field of its own (the form's Advanced tab);
a search through names, users, addresses, tags and notes, with how many
of how many entries show; a table whose columns you choose (user, address,
tags, strength, expiry, files, last change, notes: right-click its
header); what can be done with an entry under a right-click or a long
press; the user names most entries have, to pick when making one; and when
an entry was made and changed.

A bar fills and turns from red to green as a typed password's bits grow
(under 40 poor, under 65 weak, under 100 good). The bits are the cheapest
way to spell it from the 10,000 commonest passwords by rank, the 7,776
words of EFF's list at 13 bits each, and single characters: an estimate,
only a generated password's bits being known (`src/words/README`).

A health check lists weak, shared and expired passwords, and the store in
numbers (`pasa health`, `pasa stats`). `--pwned`, or the button, also
finds those breaches hold. With `PASA_PWNED` naming a local copy of
haveibeenpwned's list, ordered by hash as its downloader writes it (tens
of gigabytes: for a desk, not a phone), that file answers and nothing
leaves. Without it the site is asked: of each password only the first 5
hex digits of its SHA-1 leave the machine, and the answer is padded.
Nothing is asked unless you ask.

A file kept with an entry (`pasa attach NAME FILE`, or dropped on the
window) is an entry of its own, `NAME/.files/FILE`, hidden from listings:
it syncs, keeps its history, and goes when its entry is removed or moved.

`pasa gen NAME -w` makes a password to say aloud: made-up words of two
syllables, 22 bits each (four: 88), `SnouldengThollglirPeemtaimCerdul`
or, with `-d`, `blongder-hilfloum-gainghung-paircairn`; `-l` writes
a e i o s t as 4 3 1 0 5 7. A password reads back as one sequence of
syllables only, so the bits counted are the bits there.

Both browsers lock when left alone (5 minutes; the window's is a setting),
sync as the command line does, and copy through `wl-copy`, `xclip` or
`pbcopy`. Ctrl+Q closes the window; on Wayland without server-side frames
(GNOME) it draws its own. The window needs
libxkbcommon, libGL and Wayland or X11, as any does (the flake brings them).

## Files

```
~/.pasa/key      store keys, sealed to the password (+ YubiKey); paired, as it is
~/.pasa/v/       versions: age files, named by their hash; synced, as they are
~/.pasa/net/     what the network side sees beside v/: pairings (transport key, endpoint,
                 lane), this device's endpoint key and lane
```

Nothing else is written: no index, no cache. A listing opens every
version (10,000 entries: ~0.2 s, after the ~0.65 s unlock).

Every sealed file is a standard age file whose passphrase is a random
256-bit key (age's scrypt recipient at N = 2: the key needs no
stretching). Symmetric, so post-quantum; pasa implements no crypto, and
`age -d` opens any version with a key from `pasa keys`.

A version holds `ms parent size name`, the body and padding (to a power
of two, then 64 KiB steps). An entry is its newest version, the rest its
history (`pasa log`); size 0 deletes. A version names the one it followed:
two devices changing an entry apart show up in `pasa ls` until an edit
follows the winner. A file alone tells nothing: not its entry, not its
history. Back up `~/.pasa` with anything.

`git init --bare ~/.pasa/git` and pasa commits each new version of `v/`
there, and pushes if a remote is set (`git --git-dir ~/.pasa/git remote
add origin URL`, then `git ... push -u` once): a remote holds what `serve`
does, ciphertext, and learns when you change things. The repository lies
beside `v/`, never in it, since the network side may write in `v/`: no
hook or config of its can run where the keys are. Hooks never run, and
only versions are committed (a name of 32 hex digits, an age file), not
whatever else lies in `v/`. One made in `v/` before (`v/.git`) moves
there by itself, its hooks dropped and its config cut to its remotes and
branches. A version deleted from `v/` is then named by `pasa ls` and
restored by `git --git-dir ~/.pasa/git --work-tree ~/.pasa/v checkout .`.

## Keys

- **Store keys**: 256 random bits each (hedged with the password, RFC
  8937), newest first; never derived.
- **Their lock**: Argon2id (256 MiB, 4 passes) of the password, with the
  YubiKey's HMAC-SHA1 answer to a random challenge as Argon2's secret: both
  factors needed. The password is per device (`passwd` changes this one);
  each `passwd` takes a fresh challenge. Program two YubiKeys with one
  secret (`ykman otp chalresp 2 SECRET`).
- **Security keys: CTAP2** (`pasa ctap`, or the apps' settings; brought
  along by pairing, never synced): a security key of any make (a YubiKey
  is one) opens the store beside the password, by CTAP2's `hmac-secret`.
  CTAP2 is the half of FIDO2 between a device and a key; the half between
  a browser and a server (WebAuthn) is not used, and there is no server,
  account or network in it: it works offline, and "pasa" on the key is a
  name, not an address.
  The key makes a secret that never leaves it and answers HMAC-SHA-256 of
  the store's salt under it, the salt in WebAuthn's PRF form
  (SHA-256("WebAuthn PRF", 0, salt)), as Yubico's kit on the phone asks
  it: a key added on one device opens the store on those it pairs (keys
  added on a computer before, asked the salt as it is, still open it
  there). On a computer pasa speaks CTAP2 itself, over USB
  (authenticator-rs, Firefox's): nothing to install, and nothing a
  system guards as a keyboard (macOS asks no Input Monitoring), or held
  to an NFC reader (PC/SC: pcsc-lite's `pcscd` on Linux,
  `services.pcscd.enable` on NixOS; macOS's own), a key's CTAP2 then
  carried in ISO 7816 APDUs. `ctap`
  holds, a line a key, the credential and the key the password opens
  sealed to that answer. A key is added whenever the store is open, so a
  spare can come later. With a PIN on the
  key, the key counts the wrong tries (8, then it locks). The exchange on
  the cable is CTAP2's (P-256, AES-256, HMAC-SHA-256), not post-quantum;
  what it carries opens nothing without the device's files. A new password
  takes the keys off.
  That no connection is made is checked, not only said: on Android, every
  build runs `android/no-network.sh`, which fails if the app's key code or
  any class of Yubico's library names one that could open a connection;
  on the desktop, authenticator-rs depends on no network crate
  (`cargo tree -p authenticator`) and its source names no socket.
- **Quick unlock** (`pasa quick`, or the apps' settings; brought along by
  pairing, never synced): `quick` holds the key the password derives, sealed to Argon2id
  of a PIN with the YubiKey's answer as its secret. A tap and the PIN then
  open the store; so does the password alone, which must therefore be
  long. The key alone opens nothing; the device's storage with the key
  leaves only the PIN to guess, at Argon2id's pace: days for six digits.
  `passwd` ends it. A computer asks slot 2 itself of a YubiKey held to an
  NFC reader, or by its smart-card side plugged in where the key allows
  it; else through `ykman`, which reaches it by the key's keyboard side:
  macOS opens that only to apps given Input Monitoring, so on a Mac add
  the YubiKey as a security key instead.
- **Transport keys, endpoints, lanes**: what `serve` holds; none opens
  a version or the key file.

## Sync

```sh
pasa pair phone --qr   # here: the QR code's password, then the code; serves until phone has synced
pasa join home CODE    # there (the apps scan it): the QR code's password; then it syncs
pasa join home --scan  # the same, the code read by this computer's camera
pasa sync on | off     # sync with the paired devices, or stay offline (off until turned on; pairing turns it on)
pasa serve             # accept syncs; wake listening peers on news
pasa listen            # sync when woken, through pushir's daemon (laptops)
pasa sync              # with every peer, all at once (also after each change)
```

**Offline by default.** Each device has a switch, off until turned on
(pairing turns it on): `pasa sync on|off`, the window's Devices or its
status bar, `^S` in `pasa tui`, the phone's Devices. Off, nothing of the
store goes online: no serving (`pasa serve` and its service wait, and
start or stop within seconds of the switch), no listening, no sync after
a change. Offline is the norm; check in about once a month. Each device
keeps when each other last synced with it, and says which it has not met
for a month: in the window's status bar and Devices, `pasa peers`, on a
terminal's commands, and above the phone's list.

Pairing hands over the keys; syncing, the store. Neither opens either:
the store's password and hardware key are never asked for, typed or
seen while devices pair or sync, only afterwards, on each device alone.

**Pairing** sends the key file as it is, sealed to the password (and
YubiKey), and the hardware keys' files if there are any (`quick`, `ctap`:
sealed to them), with this device's endpoint and a fresh transport key for the
two. The device that has the keys shows a QR code (offline: a phone's
camera, a computer's by `join --scan` or the window's "Scan with the
camera" (in-process: AVFoundation, V4L2; nothing to install), a picture
of it dropped on the window, or `join` with its text takes it; frames
stay in memory), under a password of its own, typed or two
made-up words, shown before the code and never beside it; or a short
code to type (`pair` without `--qr`, for a device with no camera), which
meets once at the relay under [pairir](https://github.com/cablab-ucf/pairir)
(CPace, then X-Wing, inside post-quantum TLS), one try, one minute. The
device that takes it holds those files from then on (a key file it had
that differed is kept as `key.old`; its own hardware keys' files, which
opened that one alone, go).

**Syncing** sends versions, age files to the store key, as they are; the
new device syncs at once, before anything is unlocked. It runs in a
process of its own that sees `v/` and `net/` alone: never `key`, the
rest of `~/.pasa` or of the computer. On Linux it confines itself by
Landlock before it opens a socket (a kernel without Landlock: it says so
and runs unconfined); on macOS its parent starts it inside the system
sandbox (`sandbox-exec`), which keeps it out of `/Users`, `/Volumes` and
the temporary directories but for `v/` and `net/`. The process that
holds the store open (the window, a command) opens no socket. The window
serves while it is open, the Android app while it is on the screen; each
sync tells the other device where this one serves, so after the first,
either dials. A device not met yet, or not reached in 15 s, is said, not
waited on.

| Layer | Holds if the others fall |
|---|---|
| iroh: TLS 1.3, X25519MLKEM768, raw public keys, no CA | |
| irnet's PSK channel: HPKE PSK mode over X-Wing, bound to the TLS session | TLS broken, one RNG rigged |
| every version an age file to a store key | everything above |

`serve` (`contrib/pasa-serve.service` confines it) reads and writes age
files, its endpoint key and the pairings: taking it over yields
ciphertext. One process serves a store at a time (a lock on the endpoint
key): the window and a daemon would take each other's place at the
relay. Dialers use throwaway endpoints. Received files must match
their names, be asked for, and be under 16 MiB; strays in `v/` are
ignored.

A wake (after a change here, or Sync now; never otherwise) is an empty
message to a peer's lane, through [pushir](https://github.com/cablab-ucf/pushir), which
seals it: the relay sees a mailbox and 1024 random-looking bytes. It says
"sync" and nothing else, so one lost, repeated or forged by a peer costs a
sync at most; a device also syncs when its connection comes back. Every
peer of a device holds its lane's secret, so `forget` and `revoke` make a
new one, which the peers that stay get at their next sync (`listen` moves
to it within a quarter of an hour, the Android app when it next starts).

`revoke NAME` (Revoke in Devices) ends the pairing and rotates the store key: every entry is
sealed again to a new key. Keys travel by pairing alone, so pair the
other devices again from here; what follows the rotation opens there
only then. Forget it on every device it paired with. It keeps what it
had: change the passwords it held. `forget NAME` ends a pairing alone.

## Migrating

```sh
kdbx2pasa A.kdbx [B.kdbx ...] [-k KEYFILE] | pasa load   # KeePass
pasa dump | pasa2kdbx OUT.kdbx          # to KeePass, KeePassXC
contrib/migrate.sh                      # pasa 0.1 (age 1.3+)
```

`kdbx2pasa` brings every entry with its history, each version dated as
KeePass dated it, its attachments, tags and expiry, and `.kdbx.json` (the
first database, whole); what is in the recycle bin stays out. Several databases
are copies of one that went apart (sync conflicts): an entry is the same
by its id in each, and its versions from all of them make one history by
time, each once, the newest being the entry. `pasa load` keeps a tar
member's date as its version's.

`pasa2kdbx` writes each entry as it is now (not its history) to a new
KDBX4 file, never over one that is there: groups by name; title, user,
address, password, one-time code (`otp`, as KeePassXC keeps it), tags,
expiry, every other field, notes, date, and its files as attachments.
It is sealed under a password asked for there, by Argon2id (256 MiB, 4
passes; KeePass's default is 1 MiB) and AES-256. Both ways the entries
cross the pipe as text: run them on the machine itself.

`pasa pick` gives fzf the names alone (no secret, no preview); it copies
the chosen entry's field as `cp` does.

License: GPL-3.0-or-later.
