# pasa

A small password store. Each change is one age file that never changes, so
copies merge by union: no conflicts, however long a device is offline.

```sh
cargo install --locked --path .   # --no-default-features: no network at all
pasa init -y                      # password + YubiKey (-y optional)
pasa gen mail/work -c             # new password, to the clipboard
pasa cp mail/work                 # clipboard, cleared after 45 s if unchanged
pasa mail/work otp                # a field: pass, user, otp, ...
```

`pasa help` lists every command. An entry is text as in `pass`: the
password, then `key: value` lines and any `otpauth://totp/` URI.
[apasa](android/) is the Android app.

## Files

```
~/.pasa/v/       versions: age files, named by their hash; synced
~/.pasa/key      store keys, sealed to the password (+ YubiKey); handed to new devices
~/.pasa/dev      this device's hand-over keys, sealed the same; never leaves
~/.pasa/peers    pairings: transport key, endpoint, lane, device id
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

`git init ~/.pasa/v` and pasa commits each new version there, and pushes
if a remote is set (`git push -u` once): a remote holds what `serve` does,
ciphertext, and learns when you change things. A version deleted from
`v/` is then named by `pasa ls` and restored by `git checkout .`.

## Keys

- **Store keys**: 256 random bits each (hedged with the password, RFC
  8937), newest first; never derived.
- **Their lock**: Argon2id (256 MiB, 4 passes) of the password, with the
  YubiKey's HMAC-SHA1 answer to a random challenge as Argon2's secret: both
  factors needed. The password is per device (`passwd` changes this one);
  each `passwd` takes a fresh challenge. Program two YubiKeys with one
  secret (`ykman otp chalresp 2 SECRET`).
- **Transport keys, endpoint, lanes, device id**: what `serve` holds;
  none opens a version or a hand-over.

## Sync

```sh
pasa pair phone        # here: a code and pairing password (--qr: offline)
pasa join home CODE    # there
pasa serve             # accept syncs; wake listening peers on news
pasa listen            # sync when woken, through pushir's daemon (laptops)
pasa sync              # with every peer that serves, all at once (also after each change)
```

Pairing hands over, through [pairir](https://github.com/cablab-ucf/pairir),
this device's endpoint, fresh transport and hand-over keys, and the key
file, still sealed to the password and YubiKey: the only way store keys
travel, but for hand-overs below. Both sides unlock to pair, so the
hand-over key goes straight into `dev`: it is never on disk unsealed.

| Layer | Holds if the others fall |
|---|---|
| iroh: TLS 1.3, X25519MLKEM768, raw public keys, no CA | |
| irnet's PSK channel: HPKE PSK mode over X-Wing, bound to the TLS session | TLS broken, one RNG rigged |
| every version an age file to a store key | everything above |

`serve` (`contrib/pasa-serve.service` confines it) reads and writes age
files, its endpoint key and the pairings: taking it over yields
ciphertext. Dialers use throwaway endpoints. Received files must match
their names, be asked for, and be under 16 MiB; strays in `v/` are
ignored.

A wake (after a change here, never otherwise) is an empty message to a
peer's lane, through [pushir](https://github.com/cablab-ucf/pushir), which
seals it: the relay sees a mailbox and 1024 random-looking bytes. It says
"sync" and nothing else, so one lost, repeated or forged by a peer costs a
sync at most; a device also syncs when its connection comes back. Every
peer of a device holds its lane's secret, so `forget` and `revoke` make a
new one, which the peers that stay get at their next sync (`listen` moves
to it within a quarter of an hour, the Android app when it next starts).

`revoke NAME` ends the pairing, marks the device's id revoked and rotates
the store key: every entry is sealed again to a new key, which reaches the
other peers at their next sync as an age file to their pairing's hand-over
key, with the revoked ids, so none passes it on. Revoke on every device it
paired with. It keeps what it had: change the passwords it held.
`forget NAME` ends a pairing alone.

## Migrating

```sh
kdbx2pasa Passwords.kdbx | pasa load   # KeePass: history, attachments, .kdbx.json
contrib/migrate.sh                      # pasa 0.1 (age 1.3+)
```

License: GPL-3.0-or-later.
