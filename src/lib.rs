//! A store: `key`, `dev` and `v/`. Every file sealed here is a standard
//! age file to a random 256-bit key used as its passphrase (age's own
//! scrypt recipient, at N = 2: the key needs no stretching). Symmetric,
//! so post-quantum; `age -d` opens any of them; pasa implements no crypto.
//!
//! - `v/NAME`: one version of one entry, named by its hash: `ms parent
//!   size name\n`, the body, padding. Files never change, so copies merge
//!   by union. Size 0 deletes.
//! - `key`: the store keys, newest first; `dev`: this device's hand-over
//!   keys (one per pairing).
//!   Both sealed to Argon2id(password, YubiKey response); `dev` never
//!   leaves the device.

#![forbid(unsafe_code)]

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail, ensure};
use argon2::{Algorithm::Argon2id, Argon2, Params, Version::V0x13};
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, Read, Write};
use std::sync::{
    LazyLock, Mutex, atomic::AtomicUsize, atomic::Ordering::Relaxed,
};
use std::{fs, path::Path, path::PathBuf, time::SystemTime};
use zeroize::Zeroizing;

#[cfg(feature = "sync")]
pub mod sync;

pub type Secret = Zeroizing<Vec<u8>>;
pub const MAX: usize = 16 << 20;
const KDF: (u32, u32) = if cfg!(test) { (8, 1) } else { (256 << 10, 4) };

pub fn rand<const N: usize>() -> [u8; N] {
    let mut b = [0; N];
    getrandom::fill(&mut b).expect("os randomness");
    b
}

/// OS randomness hashed with a secret it never saw (RFC 8937).
fn hedged(secret: &[u8]) -> Secret {
    let h = Sha256::new().chain_update(rand::<32>()).chain_update(secret);
    Zeroizing::new(h.finalize().to_vec())
}

fn pass(k: &[u8]) -> SecretString {
    SecretString::from(HEXLOWER.encode(k))
}

/// The age identity of a random key: files at N = 2 only, so no file can
/// make us run a costly scrypt.
fn identity(k: &[u8]) -> age::scrypt::Identity {
    let mut i = age::scrypt::Identity::new(pass(k));
    i.set_max_work_factor(1);
    i
}

fn recipient(k: &[u8]) -> age::scrypt::Recipient {
    let mut r = age::scrypt::Recipient::new(pass(k));
    r.set_work_factor(1);
    r
}

/// Any one of several keys (age stops at the first passphrase that fails).
struct AnyOf<'a>(&'a [age::scrypt::Identity]);

impl age::Identity for AnyOf<'_> {
    fn unwrap_stanza(
        &self,
        s: &age_core::format::Stanza,
    ) -> Option<Result<age_core::format::FileKey, age::DecryptError>> {
        self.0.iter().find_map(|i| i.unwrap_stanza(s)?.ok()).map(Ok)
    }
}

fn encrypt(r: &age::scrypt::Recipient, pt: &[u8]) -> Result<Vec<u8>> {
    let e = age::Encryptor::with_recipients(std::iter::once(
        r as &dyn age::Recipient,
    ))?;
    let mut out = vec![];
    let mut w = e.wrap_output(&mut out)?;
    w.write_all(pt)?;
    w.finish()?;
    Ok(out)
}

fn reader<'a, R: Read + 'a>(
    ids: &[age::scrypt::Identity],
    ct: R,
) -> Result<impl Read + 'a> {
    let d = age::Decryptor::new_buffered(std::io::BufReader::new(ct))?;
    Ok(d.decrypt(std::iter::once(&AnyOf(ids) as &dyn age::Identity))?)
}

/// `pt` sealed to key `k`.
pub(crate) fn seal(k: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    encrypt(&recipient(k), pt)
}

/// What `seal` sealed to `k`.
pub(crate) fn open(k: &[u8], ct: &[u8]) -> Option<Secret> {
    let mut out = Zeroizing::new(vec![]);
    reader(&[identity(k)], ct).ok()?.read_to_end(&mut out).ok()?;
    Some(out)
}

/// A version's file name: 128 bits of its SHA-256.
pub fn name_of(b: &[u8]) -> String {
    HEXLOWER.encode(&Sha256::digest(b)[..16])
}

pub fn is_name(n: &str) -> bool {
    n.len() == 32 && n.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn home() -> PathBuf {
    let h = || std::env::home_dir().unwrap_or_default().join(".pasa");
    std::env::var_os("PASA_DIR").map_or_else(h, PathBuf::from)
}

/// Whole or not at all, owner-only, durable.
pub fn write(p: &Path, b: &[u8]) -> Result<()> {
    let dir = p.parent().context("no directory")?;
    fs::create_dir_all(dir)?;
    let tmp = p.with_extension(HEXLOWER.encode(&rand::<4>()));
    let mut o = fs::OpenOptions::new();
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.write(true).create_new(true).open(&tmp)?;
    f.write_all(b)?;
    f.sync_all()?;
    fs::rename(tmp, p)?;
    let _ = fs::File::open(dir).and_then(|d| d.sync_all());
    Ok(())
}

/// The YubiKey challenge in a key file, if it has one.
pub fn challenge(key: &[u8]) -> Option<&[u8]> {
    (key.get(32) == Some(&1)).then(|| &key[..32])
}

/// Argon2id(password, salt), with the YubiKey's response as its secret.
fn kek(pw: &[u8], salt: &[u8], yk: Option<&[u8]>) -> Result<Secret> {
    let e = anyhow::Error::msg;
    let p = Params::new(KDF.0, KDF.1, 1, Some(32)).map_err(e)?;
    let a = Argon2::new_with_secret(yk.unwrap_or(&[]), Argon2id, V0x13, p);
    let mut k = Zeroizing::new(vec![0; 32]);
    a.map_err(e)?.hash_password_into(pw, salt, &mut k).map_err(e)?;
    Ok(k)
}

/// A plaintext's padded length: a power of two to 64 KiB, then 64 KiB
/// steps; what a file's size tells is bounded.
fn padded(n: usize) -> usize {
    match n.max(256).next_power_of_two() {
        p if p <= 64 << 10 => p,
        _ => n.div_ceil(64 << 10) * (64 << 10),
    }
}

/// One version's head.
#[derive(Clone)]
pub struct Version {
    pub ms: u64,
    pub size: usize,
    pub name: String,
    /// The version of this entry it followed ("-": none).
    pub parent: String,
    /// Its file in `v/`.
    pub file: String,
}

impl Version {
    fn line(&self) -> String {
        format!("{} {} {} {}", self.ms, self.parent, self.size, self.name)
    }

    fn parse(l: &str, file: &str) -> Option<Version> {
        let mut w = l.splitn(4, ' ');
        let (ms, parent, size) =
            (w.next()?.parse().ok()?, w.next()?, w.next()?.parse().ok()?);
        let name = w.next()?.into();
        (parent == "-" || is_name(parent)).then(|| Version {
            ms,
            size,
            name,
            parent: parent.into(),
            file: file.into(),
        })
    }
}

/// `v/` as read: heads by file, `v/`'s mtime then, and what a lookup or a
/// new version needs without a pass over every head: each entry's newest
/// version (its time and file) and the latest time of all.
#[derive(Default)]
struct Index {
    heads: HashMap<String, Version>,
    mtime: Option<SystemTime>,
    tips: HashMap<String, (u64, String)>,
    last: u64,
}

impl Index {
    fn tip(&mut self, v: &Version) {
        let t = (v.ms, v.file.clone());
        match self.tips.get_mut(&v.name) {
            Some(old) if *old >= t => {}
            Some(old) => *old = t,
            None => drop(self.tips.insert(v.name.clone(), t)),
        }
        self.last = self.last.max(v.ms);
    }
}

pub struct Store {
    pub dir: PathBuf,
    /// Store keys, newest first: older ones open history.
    keys: Vec<Secret>,
    ids: Vec<age::scrypt::Identity>,
    newest: age::scrypt::Recipient,
    /// This device's hand-over key for each pairing.
    pub(crate) hands: BTreeMap<String, Secret>,
    kek: Secret,
    salt: Vec<u8>,
    /// The key file as read or last written: never overwrite a newer one.
    loaded: Mutex<Vec<u8>>,
    index: Mutex<Index>,
    /// Files the last listing found that no store key opens.
    pub unreadable: AtomicUsize,
}

impl Store {
    fn new(
        dir: &Path,
        keys: Vec<Secret>,
        dev: &[u8],
        kek: Secret,
        salt: Vec<u8>,
    ) -> Result<Store> {
        let hands = std::str::from_utf8(dev)?.lines().filter_map(|l| {
            let (n, k) = l.split_once(' ')?;
            Some((
                n.into(),
                Zeroizing::new(HEXLOWER.decode(k.as_bytes()).ok()?),
            ))
        });
        Ok(Store {
            dir: dir.into(),
            ids: keys.iter().map(|k| identity(k)).collect(),
            newest: recipient(keys.first().context("no store key")?),
            keys,
            hands: hands.collect(),
            kek,
            salt,
            loaded: Mutex::new(fs::read(dir.join("key")).unwrap_or_default()),
            index: Default::default(),
            unreadable: 0.into(),
        })
    }

    /// A new store key, hedged with the password.
    pub fn create(
        dir: &Path,
        pw: &[u8],
        yk: Option<(&[u8], &[u8])>,
    ) -> Result<Store> {
        ensure!(!dir.join("key").exists(), "{} holds a store", dir.display());
        let mut s =
            Store::new(dir, vec![hedged(pw)], b"", Default::default(), vec![])?;
        s.lock(pw, yk)?;
        Ok(s)
    }

    /// Open with the password and, if `key` asks, the YubiKey's response.
    pub fn open(dir: &Path, pw: &[u8], yk: Option<&[u8]>) -> Result<Store> {
        let f = fs::read(dir.join("key")).context("no store: pasa init")?;
        let salt = f.get(..32).context("not a pasa key file")?;
        Store::unsealed(dir, kek(pw, salt, yk)?)
            .context("wrong password or key")
    }

    /// Open by a YubiKey's answer and the PIN, if [`quick_on`] set them:
    /// they open the key the password opens.
    ///
    /// [`quick_on`]: Store::quick_on
    pub fn open_quick(dir: &Path, pin: &[u8], yk: &[u8]) -> Result<Store> {
        let f = fs::read(dir.join("quick")).context("quick unlock is off")?;
        let (head, sealed) =
            f.split_at_checked(33).context("not a quick file")?;
        let k = kek(pin, &head[..32], Some(yk))?;
        let kek = open(&k, sealed).context("wrong PIN or key")?;
        Store::unsealed(dir, kek)
            .context("quick unlock is out of date: use the password")
    }

    /// Let this device open the store by a YubiKey's answer to `challenge`
    /// and a PIN (empty: none), beside the password: `quick` holds the key
    /// the password opens, sealed to them. With the device's storage and
    /// the YubiKey a PIN is guessed in days, so the password, which opens
    /// the store alone, must be long.
    pub fn quick_on(
        &self,
        pin: &[u8],
        challenge: &[u8],
        yk: &[u8],
    ) -> Result<()> {
        ensure!(challenge.len() == 32, "a challenge is 32 bytes");
        let k = kek(pin, challenge, Some(yk))?;
        let head = [challenge, &[!pin.is_empty() as u8]].concat();
        let quick = [&head[..], &seal(&k, &self.kek)?].concat();
        write(&self.dir.join("quick"), &quick)
    }

    /// The salt security keys are asked with on this device: made at the
    /// first key, the same for every one after.
    pub fn fido_salt(&self) -> Vec<u8> {
        fido(&self.dir).map_or_else(|| rand::<32>().to_vec(), |f| f.salt)
    }

    /// Let the security key with credential `cred` open the store on this
    /// device, with its PIN or not: the key the password opens is sealed
    /// to `secret`, the key's answer (32 bytes, never leaving the key but
    /// so) to `salt` ([`Store::fido_salt`]). A key is added at any time
    /// the store is open; the others stay.
    pub fn fido_add(
        &self,
        salt: &[u8],
        cred: &[u8],
        pin: bool,
        secret: &[u8],
    ) -> Result<()> {
        ensure!(salt.len() == 32 && secret.len() == 32, "32 bytes each");
        ensure!(fido(&self.dir).is_none_or(|f| f.salt == salt), "another salt");
        let at = self.dir.join("fido");
        let old = fs::read_to_string(&at).unwrap_or_default();
        let mut lines: Vec<String> =
            old.lines().skip(1).map(Into::into).collect();
        lines.retain(|l| fido_line(l).is_some_and(|k| k.0 != cred));
        let hex = |b: &[u8]| HEXLOWER.encode(b);
        let sealed = seal(secret, &self.kek)?;
        lines.insert(0, hex(salt));
        lines.push(format!("{} {} {}", hex(cred), pin as u8, hex(&sealed)));
        write(&at, (lines.join("\n") + "\n").as_bytes())
    }

    /// Open by the answer of the security key with credential `cred`.
    pub fn open_fido(dir: &Path, cred: &[u8], secret: &[u8]) -> Result<Store> {
        let f =
            fs::read_to_string(dir.join("fido")).context("no security key")?;
        let mut keys = f.lines().skip(1).filter_map(fido_line);
        let key =
            keys.find(|k| k.0 == cred).context("not a key of this store")?;
        let kek = open(secret, &key.2)
            .context("the key's answer does not open it")?;
        Store::unsealed(dir, kek)
            .context("the security key is out of date: use the password")
    }

    /// With the key the password gives.
    fn unsealed(dir: &Path, kek: Secret) -> Result<Store> {
        let f = fs::read(dir.join("key")).context("no store: pasa init")?;
        let (salt, sealed) =
            f.split_at_checked(33).context("not a pasa key file")?;
        let keys = open(&kek, sealed).context("the key does not open it")?;
        ensure!(
            !keys.is_empty() && keys.len() % 32 == 0,
            "not a pasa key file"
        );
        let keys =
            keys.chunks(32).map(|k| Zeroizing::new(k.to_vec())).collect();
        let dev = fs::read(dir.join("dev")).ok().and_then(|d| open(&kek, &d));
        Store::new(dir, keys, &dev.unwrap_or_default(), kek, salt.to_vec())
    }

    /// Seal the keys to `pw` and a YubiKey's (challenge, response).
    pub fn lock(
        &mut self,
        pw: &[u8],
        yk: Option<(&[u8], &[u8])>,
    ) -> Result<()> {
        let salt = yk.map_or(rand::<32>().to_vec(), |c| c.0.to_vec());
        self.salt = [&salt[..], &[yk.is_some() as u8]].concat();
        self.kek = kek(pw, &salt, yk.map(|c| c.1))?;
        self.save()?;
        // What quick unlock held opens the old lock only.
        let _ = fs::remove_file(self.dir.join("quick"));
        let _ = fs::remove_file(self.dir.join("fido"));
        Ok(())
    }

    /// Write `key` and `dev` under a lock, unless `key` changed since we
    /// read it (another process rotated or relocked: unlock again).
    pub(crate) fn save(&self) -> Result<()> {
        fs::create_dir_all(&self.dir)?;
        let mut lock = fs::OpenOptions::new();
        let lock = lock
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join("key.lock"))?;
        // One writer at a time, across processes. Android's std has no file
        // lock; an app there is one process, and `loaded` orders its threads.
        match lock.lock() {
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {}
            locked => locked?,
        }
        let mut loaded = self.loaded.lock().unwrap();
        let now = fs::read(self.dir.join("key")).unwrap_or_default();
        ensure!(
            now == *loaded,
            "the key file changed since this unlock: unlock again"
        );
        let hands = self
            .hands
            .iter()
            .map(|(n, k)| format!("{n} {}\n", HEXLOWER.encode(k)));
        let dev = Zeroizing::new(hands.collect::<String>().into_bytes());
        write(&self.dir.join("dev"), &seal(&self.kek, &dev)?)?;
        let keys: Secret = Zeroizing::new(
            self.keys.iter().flat_map(|k| k.iter().copied()).collect(),
        );
        let key = [&self.salt[..], &seal(&self.kek, &keys)?].concat();
        write(&self.dir.join("key"), &key)?;
        *loaded = key;
        Ok(())
    }

    #[cfg(any(test, feature = "sync"))]
    pub(crate) fn keys(&self) -> &[Secret] {
        &self.keys
    }

    /// The store keys, as `age -d` asks for them (passphrases).
    pub fn passphrases(&self) -> Zeroizing<String> {
        Zeroizing::new(
            self.keys.iter().map(|k| HEXLOWER.encode(k) + "\n").collect(),
        )
    }

    /// Add keys a rotation made elsewhere (newest first): whether any was new.
    pub(crate) fn add_keys(&mut self, ks: &[u8]) -> Result<bool> {
        let new: Vec<_> = ks
            .chunks(32)
            .filter(|k| !self.keys.iter().any(|m| &m[..] == *k))
            .collect();
        for k in new.iter().rev() {
            self.keys.insert(0, Zeroizing::new(k.to_vec()));
            self.ids.insert(0, identity(k));
        }
        if !new.is_empty() {
            self.newest = recipient(&self.keys[0]);
            self.save()?;
        }
        Ok(!new.is_empty())
    }

    /// A new store key, first; every entry sealed again to it. History
    /// stays under the keys it was written to.
    pub fn rotate(&mut self) -> Result<()> {
        let e = self
            .entries()?
            .into_values()
            .map(|v| Ok((v.name.clone(), self.body(&v)?)));
        let e = e.collect::<Result<Vec<_>>>()?;
        self.add_keys(&rand::<32>())?;
        e.iter().try_for_each(|(n, b)| self.put(n, b))
    }

    fn version(&self, file: &str) -> Result<impl Read + use<'_>> {
        reader(&self.ids, fs::File::open(self.dir.join("v").join(file))?)
    }

    fn head(&self, file: &str) -> Option<Version> {
        let mut l = String::new();
        std::io::BufReader::new(self.version(file).ok()?)
            .read_line(&mut l)
            .ok()?;
        Version::parse(l.strip_suffix('\n')?, file)
    }

    /// `v/` as it is now: new files' heads read, gone ones dropped. Files
    /// no store key opens are counted in [`Store::unreadable`].
    fn index(&self) -> Result<std::sync::MutexGuard<'_, Index>> {
        let mut x = self.index.lock().unwrap();
        let v = self.dir.join("v");
        let mtime = fs::metadata(&v).and_then(|m| m.modified()).ok();
        if x.mtime.is_some() && x.mtime == mtime {
            return Ok(x);
        }
        let names = fs::read_dir(&v)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok());
        let names: HashSet<String> = names.filter(|n| is_name(n)).collect();
        x.heads.retain(|f, _| names.contains(f));
        let mut bad = 0;
        let new: Vec<&String> =
            names.iter().filter(|n| !x.heads.contains_key(*n)).collect();
        for n in new {
            match self.head(n) {
                Some(h) => drop(x.heads.insert(n.clone(), h)),
                None => bad += 1,
            }
        }
        self.unreadable.store(bad, Relaxed);
        x.mtime = mtime;
        (x.tips, x.last) = Default::default();
        let heads = std::mem::take(&mut x.heads);
        heads.values().for_each(|v| x.tip(v));
        x.heads = heads;
        Ok(x)
    }

    /// Every version's head, oldest first.
    pub fn versions(&self) -> Result<Vec<Version>> {
        let mut out: Vec<Version> =
            self.index()?.heads.values().cloned().collect();
        out.sort_by(|a, b| {
            (a.ms, &a.name, &a.file).cmp(&(b.ms, &b.name, &b.file))
        });
        Ok(out)
    }

    pub fn body(&self, v: &Version) -> Result<Secret> {
        let mut b = Zeroizing::new(vec![]);
        self.version(&v.file)?
            .read_to_end(&mut b)
            .context("damaged version")?;
        let at =
            b.iter().position(|&c| c == b'\n').context("damaged version")? + 1;
        ensure!(b.len() >= at + v.size, "damaged version");
        Ok(Zeroizing::new(b[at..at + v.size].to_vec()))
    }

    /// Each entry's newest version, deleted ones left out.
    pub fn entries(&self) -> Result<BTreeMap<String, Version>> {
        let mut m: BTreeMap<_, _> =
            self.versions()?.into_iter().map(|v| (v.name.clone(), v)).collect();
        m.retain(|_, v| v.size > 0);
        Ok(m)
    }

    /// The names of the files attached to entry `name`.
    pub fn files(&self, name: &str) -> Result<Vec<String>> {
        let at = format!("{name}{FILES}");
        let all = self.entries()?.into_keys();
        Ok(all.filter_map(|n| n.strip_prefix(&at).map(String::from)).collect())
    }

    /// Delete entry `name` and what is attached to it.
    pub fn remove(&self, name: &str) -> Result<()> {
        for f in self.files(name)? {
            self.put(&format!("{name}{FILES}{f}"), b"")?;
        }
        self.put(name, b"")
    }

    /// Entry `from` and what is attached to it, as `to`.
    pub fn rename(&self, from: &str, to: &str) -> Result<()> {
        ensure!(self.get(to).is_err(), "{to} exists");
        for f in self.files(from)? {
            let body = self.get(&format!("{from}{FILES}{f}"))?;
            self.put(&format!("{to}{FILES}{f}"), &body)?;
        }
        self.put(to, &self.get(from)?)?;
        self.remove(from)
    }

    /// When entry `name` was made and last changed, in milliseconds.
    pub fn times(&self, name: &str) -> Result<Option<(u64, u64)>> {
        let ms = self.versions()?.into_iter().filter(|v| v.name == name);
        let ms: Vec<u64> = ms.map(|v| v.ms).collect();
        Ok(ms.first().copied().zip(ms.last().copied()))
    }

    /// Weak (under 65 bits by [`strength`]), shared and expired passwords.
    pub fn health(&self) -> Result<Health> {
        let mut by: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let (mut h, today) = (Health::default(), today());
        for (name, f) in self.forms()? {
            if !f.expires.is_empty() && f.expires < today {
                h.expired.push(name.clone());
            }
            if f.pass.is_empty() {
                continue;
            }
            match strength(&f.pass) {
                b if b < 65 => h.weak.push((name.clone(), b)),
                _ => {}
            }
            by.entry(f.pass).or_default().push(name);
        }
        h.reused = by.into_values().filter(|n| n.len() > 1).collect();
        Ok(h)
    }

    /// Every listed entry as its form.
    fn forms(&self) -> Result<Vec<(String, Form)>> {
        let shown = |n: &String| !n.split('/').any(|c| c.starts_with('.'));
        let names = self.entries()?.into_keys().filter(shown);
        let form = |n: String| {
            let f = Form::parse(&String::from_utf8_lossy(&self.get(&n)?));
            Ok((n, f))
        };
        names.map(form).collect()
    }

    /// The store in numbers: what each counts, and the count.
    pub fn stats(&self) -> Result<Vec<(&'static str, String)>> {
        let (forms, h) = (self.forms()?, self.health()?);
        let versions = self.versions()?;
        let files = versions.iter().filter(|v| v.name.contains(FILES));
        let files = files.map(|v| &v.name).collect::<HashSet<_>>().len();
        let bits: Vec<u32> =
            forms.iter().map(|f| strength(&f.1.pass)).collect();
        let graded = |lo: u32, hi: u32| {
            bits.iter().filter(|b| (lo..hi).contains(b)).count()
        };
        let count =
            |f: fn(&Form) -> bool| forms.iter().filter(|e| f(&e.1)).count();
        let groups: HashSet<&str> = forms
            .iter()
            .filter_map(|f| Some(f.0.rsplit_once('/')?.0))
            .collect();
        let unique: HashSet<&str> = forms.iter().map(|f| &*f.1.pass).collect();
        let size =
            fs::read_dir(self.dir.join("v")).into_iter().flatten().flatten();
        let size: u64 =
            size.filter_map(|e| Some(e.metadata().ok()?.len())).sum();
        let date = |ms: Option<u64>| {
            let at = std::time::UNIX_EPOCH
                + std::time::Duration::from_millis(ms.unwrap_or(0));
            humantime::format_rfc3339_seconds(at).to_string()[..10].to_string()
        };
        let n = |n: usize| n.to_string();
        let mean = bits.iter().sum::<u32>() / bits.len().max(1) as u32;
        Ok(vec![
            ("Entries", n(forms.len())),
            ("Groups", n(groups.len())),
            ("Versions kept", n(versions.len())),
            ("Attached files", n(files)),
            ("Size on disk", format!("{} KiB", size / 1024)),
            ("First change", date(versions.first().map(|v| v.ms))),
            ("Last change", date(versions.last().map(|v| v.ms))),
            ("Different passwords", n(unique.len())),
            (
                "Entries sharing a password",
                n(h.reused.iter().map(Vec::len).sum()),
            ),
            ("Average strength", format!("{mean} bits")),
            ("Excellent (100 bits and up)", n(graded(100, u32::MAX))),
            ("Good (65 to 99)", n(graded(65, 100))),
            ("Weak (40 to 64)", n(graded(40, 65))),
            ("Poor (under 40)", n(graded(0, 40))),
            ("With a one-time code", n(count(|f| !f.otp.is_empty()))),
            ("With an expiry date", n(count(|f| !f.expires.is_empty()))),
            ("Expired", n(h.expired.len())),
        ])
    }

    /// Entry `name`'s versions and their bodies, newest first.
    pub fn history(&self, name: &str) -> Result<Vec<(u64, Secret)>> {
        let mut vs = self.versions()?;
        vs.retain(|v| v.name == name);
        vs.iter().rev().map(|v| Ok((v.ms, self.body(v)?))).collect()
    }

    /// Entries whose newest version did not follow the one before it: two
    /// devices changed them apart. The other change is in `pasa log`.
    pub fn conflicts(&self) -> Result<Vec<String>> {
        let mut last: BTreeMap<String, (String, bool)> = BTreeMap::new();
        for v in self.versions()? {
            let split = last.get(&v.name).is_some_and(|p| p.0 != v.parent);
            last.insert(v.name.clone(), (v.file, split));
        }
        Ok(last.into_iter().filter(|(_, (_, c))| *c).map(|(n, _)| n).collect())
    }

    /// An entry's body: its newest version, found without sorting the rest.
    pub fn get(&self, name: &str) -> Result<Secret> {
        let x = self.index()?;
        let v = x.tips.get(name).and_then(|t| x.heads.get(&t.1));
        let v = v.filter(|v| v.size > 0);
        let v = v.with_context(|| format!("{name}: not in store"))?.clone();
        drop(x);
        self.body(&v)
    }

    /// A new version of `name` (empty: deleted): after every version seen,
    /// following the newest of `name`.
    pub fn put(&self, name: &str, body: &[u8]) -> Result<()> {
        let mut x = self.index()?;
        let parent = x.tips.get(name).map_or("-".into(), |t| t.1.clone());
        let now = std::time::UNIX_EPOCH.elapsed()?.as_millis() as u64;
        let ms = now.max(x.last + 1);
        self.keep(&mut x, name, body, ms, parent)
    }

    /// A version of `name` as it was at `at` (milliseconds): an import's.
    /// It takes its place among the others by time and follows the one
    /// before it; dated in the newest one's second, it follows that one.
    /// The same text in the same second is not kept twice.
    pub fn put_at(&self, name: &str, body: &[u8], at: u64) -> Result<()> {
        let mut x = self.index()?;
        let named = |v: &&Version| v.name == name;
        let mut of: Vec<Version> =
            x.heads.values().filter(named).cloned().collect();
        of.sort_by(|a, b| (a.ms, &a.file).cmp(&(b.ms, &b.file)));
        for v in &of {
            if v.ms / 1000 == at / 1000
                && v.size == body.len()
                && *self.body(v)? == *body
            {
                return Ok(());
            }
        }
        let ms = match of.last() {
            Some(tip) if tip.ms / 1000 == at / 1000 => tip.ms + 1,
            _ => at,
        };
        let before = of.iter().rfind(|v| v.ms < ms);
        let parent = before.map_or("-".into(), |v| v.file.clone());
        self.keep(&mut x, name, body, ms, parent)
    }

    fn keep(
        &self,
        x: &mut Index,
        name: &str,
        body: &[u8],
        ms: u64,
        parent: String,
    ) -> Result<()> {
        ensure!(!name.is_empty() && !name.contains(['\n', '\r']), "bad name");
        ensure!(name.len() <= 255, "name over 255 bytes");
        ensure!(padded(body.len() + 320) <= MAX, "over {MAX} bytes");
        let mut v = Version {
            ms,
            size: body.len(),
            name: name.into(),
            parent,
            file: String::new(),
        };
        let mut pt = Zeroizing::new(format!("{}\n", v.line()).into_bytes());
        pt.extend_from_slice(body);
        let n = padded(pt.len());
        pt.resize(n, 0);
        let ct = encrypt(&self.newest, &pt)?;
        v.file = name_of(&ct);
        write(&self.dir.join("v").join(&v.file), &ct)?;
        x.mtime =
            fs::metadata(self.dir.join("v")).and_then(|m| m.modified()).ok();
        x.tip(&v);
        x.heads.insert(v.file.clone(), v);
        Ok(())
    }
}

/// Quick unlock on this device, if it is on: the YubiKey's challenge, and
/// whether a PIN goes with its answer.
pub fn quick(dir: &Path) -> Option<(Vec<u8>, bool)> {
    let f = fs::read(dir.join("quick")).ok()?;
    Some((f.get(..32)?.to_vec(), *f.get(32)? == 1))
}

/// The security keys (FIDO2, CTAP2 `hmac-secret`) that open the store on
/// this device, beside the password: the salt each is asked with, and
/// for each its credential and whether its PIN goes with it. The file
/// `fido`: the salt, then a line a key (credential, PIN, the key the
/// password opens sealed to that key's secret), all hex.
pub struct Fido {
    pub salt: Vec<u8>,
    pub keys: Vec<(Vec<u8>, bool)>,
}

/// One line of `fido`: credential, PIN, sealed.
fn fido_line(l: &str) -> Option<(Vec<u8>, bool, Vec<u8>)> {
    let mut p = l.split(' ');
    let hex = |p: Option<&str>| HEXLOWER.decode(p?.as_bytes()).ok();
    Some((hex(p.next())?, p.next()? == "1", hex(p.next())?))
}

pub fn fido(dir: &Path) -> Option<Fido> {
    let f = fs::read_to_string(dir.join("fido")).ok()?;
    let salt = HEXLOWER.decode(f.lines().next()?.as_bytes()).ok()?;
    let keys = f.lines().skip(1).filter_map(fido_line);
    let keys: Vec<_> = keys.map(|(c, pin, _)| (c, pin)).collect();
    (salt.len() == 32 && !keys.is_empty()).then_some(Fido { salt, keys })
}

/// The security key with credential `cred` opens nothing here any more;
/// `None`: none does.
pub fn fido_off(dir: &Path, cred: Option<&[u8]>) -> Result<()> {
    let at = dir.join("fido");
    let f = fs::read_to_string(&at).unwrap_or_default();
    let keep = |l: &&str| {
        cred.is_some() && fido_line(l).is_none_or(|k| Some(&k.0[..]) != cred)
    };
    let kept: Vec<&str> = f.lines().filter(keep).collect();
    match kept.len() {
        0 | 1 => fs::remove_file(at).or_else(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(e.into()),
        }),
        _ => write(&at, (kept.join("\n") + "\n").as_bytes()),
    }
}

/// One of `abc`, each as likely as the next.
fn pick(abc: &[u8]) -> char {
    let fair = 256 - 256 % abc.len();
    loop {
        let b = rand::<1>()[0] as usize;
        if b < fair {
            break abc[b % abc.len()] as char;
        }
    }
}

pub fn generate(len: usize, symbols: bool) -> String {
    let mut abc: Vec<u8> =
        (b'a'..=b'z').chain(b'A'..=b'Z').chain(b'0'..=b'9').collect();
    if symbols {
        abc.extend(b"!#$%&*+-=?@^_~.,:;");
    }
    (0..len).map(|_| pick(&abc)).collect()
}

/// `pass`: line 1; `otp`: the code of an otpauth://totp/ URI; else
/// `key: value`.
pub fn field(body: &str, f: &str) -> Option<String> {
    let mut l = body.lines();
    match f {
        "pass" => l.next().map(Into::into),
        "otp" => {
            let u =
                l.find_map(|l| l.find("otpauth://totp/").map(|i| &l[i..]))?;
            totp(u, std::time::UNIX_EPOCH.elapsed().ok()?.as_secs())
        }
        _ => l.skip(1).find_map(|l| {
            Some(l.strip_prefix(f)?.strip_prefix(':')?.trim().into())
        }),
    }
}

// A syllable is an onset, a vowel and a coda: 5 + 3 + 3 bits. The
// consonants between two vowels split into a coda and an onset one way
// only (tested), so a password reads back as one sequence: the bits
// counted are the bits there.
const ONSETS: [&str; 32] = [
    "b", "c", "d", "f", "g", "h", "j", "k", "p", "s", "t", "v", "bl", "br",
    "ch", "cl", "cr", "dr", "fl", "fr", "gl", "gr", "pl", "pr", "sh", "sk",
    "sl", "sn", "sp", "st", "th", "tr",
];
const VOWELS: [&str; 8] = ["a", "e", "i", "o", "u", "ai", "ee", "ou"];
const CODAS: [&str; 8] = ["", "n", "m", "l", "r", "ng", "rn", "ll"];

/// The symbols that may stand between speakable words: sixteen, none a
/// letter's 1337 form.
pub const SEPS: &str = "-_.!#%&*+=?^~,:;";

/// A password to say aloud: `words` made-up words of two syllables, 22
/// bits each (four: 88). Between two words stands one of `seps`, drawn
/// anew each time (snur-deslat_genres); none: SnurDeslatGenres. `leet`:
/// a e l o s t are, one time in two, @ 3 1 0 $ 7, which stand nowhere
/// else, so nothing is lost; a capital stays a letter.
pub fn speakable(words: usize, seps: &str, leet: bool) -> String {
    let word = |i| {
        let mut w = String::new();
        for _ in 0..2 {
            let r = u16::from_be_bytes(rand()) as usize;
            w += ONSETS[r & 31];
            w += VOWELS[r >> 5 & 7];
            w += CODAS[r >> 8 & 7];
        }
        let digit = |c| match "aelost".find(c) {
            Some(i) if leet && rand::<1>()[0] & 1 == 1 => b"@310$7"[i] as char,
            _ => c,
        };
        let mut w: String = match seps.is_empty() {
            true => w[..1].to_uppercase() + &w[1..],
            false => w,
        }
        .chars()
        .map(digit)
        .collect();
        if i > 0 && !seps.is_empty() {
            w.insert(0, pick(seps.as_bytes()));
        }
        w
    };
    (0..words).map(word).collect()
}

/// The bits of chance in [`speakable`]: its words', and its separators'.
pub fn speakable_bits(words: usize, seps: &str) -> u32 {
    let gaps = words.saturating_sub(1) as f64;
    22 * words as u32 + (gaps * (seps.len().max(1) as f64).log2()) as u32
}

/// Where an entry's attachments are: entries of their own, hidden from
/// listings, so they sync, keep their history and are deleted as any other.
pub const FILES: &str = "/.files/";

/// What a health check finds: entries whose password is weak, with its
/// bits; those sharing a password, group by group; those past their
/// `expires` date.
#[derive(Default, Clone, PartialEq, Debug)]
pub struct Health {
    pub weak: Vec<(String, u32)>,
    pub reused: Vec<Vec<String>>,
    pub expired: Vec<String>,
}

/// What a guesser tries before letters: the 10,000 commonest passwords, by
/// rank (SecLists, MIT), and the 7,776 words of EFF's long list (CC BY 3.0),
/// each with the bits it is worth.
static WORDS: LazyLock<HashMap<&'static str, f64>> = LazyLock::new(|| {
    let eff = include_str!("words/eff.txt").lines().map(|w| (w, 12.925));
    let rank = |(i, w)| (w, ((i + 2) as f64).log2());
    let common = include_str!("words/common.txt").lines().enumerate().map(rank);
    let mut m = HashMap::new();
    for (w, bits) in eff.chain(common) {
        let had = m.entry(w).or_insert(bits);
        *had = bits.min(*had);
    }
    m
});

/// A guess at the bits in a typed password: the cheapest way to spell it
/// from common passwords (by rank), dictionary words (13 bits; a capital
/// or 1337 costs a little more) and single characters (by the alphabets
/// used; one next to its neighbour, as in abc or 111, costs one bit). An
/// estimate: only a generated password's bits are known. Under 40 is
/// poor, under 65 weak, under 100 good.
pub fn strength(pw: &str) -> u32 {
    let cs: Vec<char> = pw.chars().collect();
    let has = |f: fn(&char) -> bool| cs.iter().any(f);
    let pool = [
        (has(char::is_ascii_lowercase), 26),
        (has(char::is_ascii_uppercase), 26),
        (has(char::is_ascii_digit), 10),
        (has(|c| c.is_ascii() && !c.is_ascii_alphanumeric()), 33),
        (has(|c| !c.is_ascii()), 64),
    ];
    let pool: u32 = pool.iter().filter(|p| p.0).map(|p| p.1).sum();
    let each = (pool.max(1) as f64).log2();
    let plain = |c: &char| match c {
        '4' | '@' => 'a',
        '3' => 'e',
        '1' | '!' => 'i',
        '0' => 'o',
        '5' | '$' => 's',
        '7' => 't',
        c => c.to_ascii_lowercase(),
    };
    let mut best = vec![0.0f64; cs.len() + 1];
    for i in 1..=cs.len() {
        let near = i >= 2 && (cs[i - 1] as i64 - cs[i - 2] as i64).abs() <= 1;
        best[i] = best[i - 1] + if near { 1.0 } else { each };
        for len in 3..=i.min(24) {
            let part = &cs[i - len..i];
            let low: String =
                part.iter().map(char::to_ascii_lowercase).collect();
            let word = WORDS.get(&*low).copied().or_else(|| {
                let undone: String = part.iter().map(plain).collect();
                WORDS.get(&*undone).map(|bits| bits + 2.0)
            });
            if let Some(bits) = word {
                let capital = part.iter().any(char::is_ascii_uppercase) as u8;
                best[i] = best[i].min(best[i - len] + bits + capital as f64);
            }
        }
    }
    best[cs.len()] as u32
}

/// Today as YYYY-MM-DD: what an `expires` date is held against.
pub fn today() -> String {
    let now = humantime::format_rfc3339_seconds(SystemTime::now());
    now.to_string()[..10].into()
}

/// How often a local copy of haveibeenpwned's passwords holds `pw`:
/// `file` is its `HASH:COUNT` lines ordered by hash, as its downloader
/// writes them. Nothing leaves the machine.
pub fn pwned_file(file: &Path, pw: &str) -> Result<u64> {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    let (sent, kept) = pwned_key(pw);
    let want = format!("{sent}{kept}");
    let mut f = BufReader::new(fs::File::open(file)?);
    let (mut lo, mut hi) = (0, f.get_ref().metadata()?.len());
    let mut line = String::new();
    // The line that starts at or after the middle: before or after `want`?
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        f.seek(SeekFrom::Start(mid))?;
        line.clear();
        if mid > 0 {
            f.read_line(&mut line)?;
            line.clear();
        }
        let at = f.stream_position()?;
        f.read_line(&mut line)?;
        match line.get(..40).map(|h| h.to_ascii_uppercase().cmp(&want)) {
            Some(std::cmp::Ordering::Equal) => {
                let n = line[40..].trim().trim_start_matches(':');
                return Ok(n.parse().unwrap_or(1));
            }
            Some(std::cmp::Ordering::Less) => lo = at + line.len() as u64,
            _ => hi = mid,
        }
    }
    Ok(0)
}

/// For haveibeenpwned's range search: the 5 hex digits of the password's
/// SHA-1 that are sent, and the 35 that are not.
pub fn pwned_key(pw: &str) -> (String, String) {
    use sha1::Digest;
    let h = data_encoding::HEXUPPER.encode(&sha1::Sha1::digest(pw.as_bytes()));
    (h[..5].into(), h[5..].into())
}

/// How many breaches' worth of `rest` the range's answer `text` lists.
pub fn pwned_count(rest: &str, text: &str) -> u64 {
    let hit =
        |l: &str| l.trim().strip_prefix(rest)?.strip_prefix(':')?.parse().ok();
    text.lines().find_map(hit).unwrap_or(0)
}

/// An entry's text as the fields a form shows: the password (line 1),
/// `user:`, `url:`, the otpauth URI's line, and every other line.
#[derive(Default, Clone, PartialEq, Debug)]
pub struct Form {
    pub pass: String,
    pub user: String,
    pub url: String,
    pub otp: String,
    /// The `tags:` line: names, commas between.
    pub tags: String,
    /// The `expires:` line: a date, YYYY-MM-DD.
    pub expires: String,
    /// Every other `key: value` line, as written.
    pub more: String,
    pub notes: String,
}

impl Form {
    pub fn parse(body: &str) -> Form {
        let mut l = body.lines();
        let mut f = Form {
            pass: l.next().unwrap_or_default().into(),
            ..Form::default()
        };
        // `key: value`, the key short, however it is spelt: what is in
        // the store already is read with a free hand ([`Form::problem`]
        // is strict with what is saved). `https://x` has no space there.
        let named = |l: &str| {
            l.split_once(':').is_some_and(|(k, v)| {
                k.starts_with(char::is_alphanumeric)
                    && k.chars().count() <= 32
                    && (v.is_empty() || v.starts_with(' '))
            })
        };
        let (mut notes, mut more, mut within) = (vec![], vec![], false);
        // After an empty line all is notes, as written: no line of
        // theirs is ever taken for a field.
        let mut head = true;
        for l in l {
            let key = |k: &str| {
                Some(l.strip_prefix(k)?.strip_prefix(':')?.trim().to_string())
            };
            let was = std::mem::take(&mut within);
            head &= !l.trim().is_empty();
            match (key("user"), key("url"), key("tags"), key("expires")) {
                _ if !head => notes.push(l),
                (Some(u), ..) if f.user.is_empty() => f.user = u,
                (_, Some(u), ..) if f.url.is_empty() => f.url = u,
                (_, _, Some(t), _) if f.tags.is_empty() => f.tags = t,
                (.., Some(e)) if f.expires.is_empty() => f.expires = e,
                _ if l.contains("otpauth://") && f.otp.is_empty() => {
                    f.otp = l[l.find("otpauth://").unwrap_or(0)..].trim().into()
                }
                // A field, or the rest of one that runs over lines.
                _ if named(l) || was && l.starts_with("  ") => {
                    more.push(l);
                    within = true;
                }
                _ => notes.push(l),
            }
        }
        f.more = more.join("\n");
        f.notes = notes.join("\n").trim_matches('\n').trim_end().into();
        f
    }

    /// Why this may not be saved as it is, if so: every part must read
    /// back as the part it was written as, and no other.
    pub fn problem(&self) -> Option<String> {
        let date = |d: &str| {
            let digits =
                d.split('-').all(|p| p.bytes().all(|b| b.is_ascii_digit()));
            d.len() == 10 && digits && d.split('-').count() == 3
        };
        if !self.otp.trim().is_empty()
            && !self.otp.trim().starts_with("otpauth://")
        {
            return Some(
                "One-time code: its address starts with otpauth://".into(),
            );
        }
        if !self.expires.trim().is_empty() && !date(self.expires.trim()) {
            return Some("Expires: a date as 2027-01-31".into());
        }
        let mut within = false;
        for (i, l) in self.more.lines().enumerate() {
            let at = format!("Other fields, line {}", i + 1);
            if std::mem::take(&mut within) && l.starts_with("  ")
                || l.is_empty()
            {
                within = !l.is_empty();
                continue;
            }
            let name = |k: &str| {
                k.starts_with(|c: char| c.is_ascii_alphabetic())
                    && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            };
            let Some((k, v)) = l.split_once(": ").filter(|(k, _)| name(k))
            else {
                return Some(format!(
                    "{at}: write it as name: value, the name of letters, \
                     digits and _, one space after the colon"
                ));
            };
            if v.is_empty() || v.starts_with(' ') || l.contains("otpauth://") {
                return Some(format!("{at}: one space, then the value"));
            }
            if ["user", "url", "tags", "expires", "otp"].contains(&k) {
                return Some(format!("{at}: {k} has a box of its own"));
            }
            within = true;
        }
        None
    }

    /// Its fields under their names, in the order they are shown.
    pub fn fields(&self) -> [(&'static str, &str); 8] {
        [
            ("Password", &self.pass),
            ("Username", &self.user),
            ("URL", &self.url),
            ("One-time code", &self.otp),
            ("Tags", &self.tags),
            ("Expires", &self.expires),
            ("Other fields", &self.more),
            ("Notes", &self.notes),
        ]
    }

    /// The entry's text again: what [`Form::parse`] reads back the same.
    pub fn text(&self) -> String {
        let one = |s: &str| s.replace(['\n', '\r'], " ");
        let mut t = one(&self.pass) + "\n";
        for (k, v) in [
            ("user: ", &self.user),
            ("url: ", &self.url),
            ("tags: ", &self.tags),
            ("expires: ", &self.expires),
            ("", &self.otp),
        ] {
            if !v.trim().is_empty() {
                t += &format!("{k}{}\n", one(v.trim()));
            }
        }
        for l in self.more.lines().filter(|l| !l.is_empty()) {
            t += &format!("{l}\n");
        }
        // An empty line, then the notes: read back as notes, whatever
        // they say.
        let notes = self.notes.trim_matches('\n').trim_end();
        if !notes.is_empty() {
            t += &format!("\n{notes}\n");
        }
        t
    }
}

/// RFC 6238.
pub fn totp(uri: &str, t: u64) -> Option<String> {
    use totp_lite::{Sha1, Sha256, Sha512, totp_custom as f};
    let q = |k: &str| {
        uri.split(['?', '&']).find_map(|p| p.strip_prefix(k)?.strip_prefix('='))
    };
    let key = q("secret")?.trim_end_matches('=').to_uppercase();
    let key = data_encoding::BASE32_NOPAD.decode(key.as_bytes()).ok()?;
    let p =
        q("period").map_or(Some(30), |p| p.parse().ok()).filter(|&p| p > 0)?;
    let d = q("digits")
        .map_or(Some(6), |d| d.parse().ok())
        .filter(|d| (1..10).contains(d))?;
    Some(match q("algorithm").unwrap_or("SHA1") {
        "SHA1" => f::<Sha1>(p, d, &key, t),
        "SHA256" => f::<Sha256>(p, d, &key, t),
        "SHA512" => f::<Sha512>(p, d, &key, t),
        _ => return None,
    })
}

/// A name `dump` can write as a relative path.
pub fn path_safe(name: &str) -> Result<()> {
    let bad = name.starts_with('/')
        || name.split('/').any(|c| c.is_empty() || c == "." || c == "..");
    if bad {
        bail!("{name}: not a safe path");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn dir(t: &str) -> PathBuf {
        let d = std::env::temp_dir()
            .join(format!("pasa-{t}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn versions_merge_by_union_and_rotate() {
        let d = dir("u");
        let mut s = Store::create(&d, b"pw", None).unwrap();
        assert!(Store::open(&d, b"no", None).is_err());
        s.put("mail", b"a\nuser: me\n").unwrap();
        s.put("mail", b"b\nuser: me\n").unwrap();
        s.put("bank", b"c").unwrap();
        s.put("bank", b"").unwrap();
        s.rotate().unwrap();
        drop(s);
        let s = Store::open(&d, b"pw", None).unwrap();
        assert_eq!(s.keys().len(), 2);
        assert_eq!(s.entries().unwrap().keys().collect::<Vec<_>>(), ["mail"]);
        let body = String::from_utf8(s.get("mail").unwrap().to_vec()).unwrap();
        assert_eq!(field(&body, "user").as_deref(), Some("me"));
        assert_eq!(field(&body, "pass").as_deref(), Some("b"));
        assert_eq!(s.versions().unwrap().len(), 5);
        assert!(s.conflicts().unwrap().is_empty());
        fs::write(d.join("v/0123456789abcdef0123456789abcdef"), b"not ours")
            .unwrap();
        drop(s);
        let mut s = Store::open(&d, b"pw", None).unwrap();
        assert_eq!(s.versions().unwrap().len(), 5);
        assert_eq!(s.unreadable.load(Relaxed), 1);
        s.lock(b"new", Some((&[9; 32], b"hmac"))).unwrap();
        let k = fs::read(d.join("key")).unwrap();
        assert_eq!(challenge(&k), Some(&[9; 32][..]));
        assert!(Store::open(&d, b"new", None).is_err(), "both factors");
        assert!(Store::open(&d, b"new", Some(b"hmac")).is_ok());
    }

    /// A stale process does not overwrite a newer key file.
    #[test]
    fn stale_key_files_are_refused() {
        let d = dir("stale");
        drop(Store::create(&d, b"pw", None).unwrap());
        let mut a = Store::open(&d, b"pw", None).unwrap();
        let mut b = Store::open(&d, b"pw", None).unwrap();
        a.rotate().unwrap();
        assert!(b.lock(b"other", None).is_err());
        assert!(b.rotate().is_err());
        assert_eq!(Store::open(&d, b"pw", None).unwrap().keys().len(), 2);
    }

    /// Two devices changed one entry apart: the newer wins, and is flagged
    /// until an edit follows it.
    #[test]
    fn concurrent_edits_are_flagged() {
        let d = dir("conflict");
        let s = Store::create(&d, b"pw", None).unwrap();
        s.put("x", b"1").unwrap();
        let o = d.join("other");
        let copy = |from: &Path, to: &Path| {
            for e in fs::read_dir(from.join("v")).unwrap().flatten() {
                fs::create_dir_all(to.join("v")).unwrap();
                fs::copy(e.path(), to.join("v").join(e.file_name())).unwrap();
            }
        };
        copy(&d, &o);
        fs::copy(d.join("key"), o.join("key")).unwrap();
        Store::open(&o, b"pw", None).unwrap().put("x", b"2").unwrap();
        s.put("x", b"3").unwrap();
        copy(&o, &d);
        // A sync may land within the mtime's granularity.
        s.index.lock().unwrap().mtime = None;
        assert_eq!(&s.get("x").unwrap()[..], b"3");
        assert_eq!(s.conflicts().unwrap(), ["x"]);
        s.put("x", b"4").unwrap();
        assert!(s.conflicts().unwrap().is_empty());
    }

    /// Stock age opens a version with its store key as the passphrase.
    #[test]
    fn versions_are_age_files() {
        let d = dir("age");
        let s = Store::create(&d, b"pw", None).unwrap();
        s.put("x", b"hunter2").unwrap();
        let v = &s.entries().unwrap()["x"];
        let ct = fs::read(d.join("v").join(&v.file)).unwrap();
        assert!(ct.starts_with(b"age-encryption.org/v1\n-> scrypt "));
        let pt = open(&s.keys()[0], &ct).unwrap();
        assert!(pt.starts_with(format!("{}\nhunter2", v.line()).as_bytes()));
        assert_eq!(pt.len(), 256, "padded");
    }

    #[test]
    fn speakable_passwords_keep_their_bits() {
        // Between two vowels stand a coda and an onset: no two such pairs
        // spell the same, so the syllables read back one way.
        let runs =
            CODAS.iter().flat_map(|c| ONSETS.iter().map(move |o| (c, o)));
        let runs: std::collections::HashSet<String> =
            runs.map(|(c, o)| format!("{c}{o}")).collect();
        assert_eq!(runs.len(), CODAS.len() * ONSETS.len());
        let vowel = |s: &&str| s.contains(['a', 'e', 'i', 'o', 'u']);
        assert!(!ONSETS.iter().chain(&CODAS).any(vowel));
        let mut seen = std::collections::HashSet::new();
        for (o, v, c) in ONSETS
            .iter()
            .flat_map(|o| VOWELS.iter().map(move |v| (o, v)))
            .flat_map(|(o, v)| CODAS.iter().map(move |c| (o, v, c)))
        {
            assert!(seen.insert(format!("{o}{v}{c}")));
        }
        assert_eq!(seen.len(), 1 << 11);
        let p = speakable(4, "-", false);
        assert_eq!(p.split('-').count(), 4);
        assert!(p.chars().all(|c| c == '-' || c.is_ascii_lowercase()));
        // Some letters as 1337, not all; what they become is no letter of
        // a syllable and no separator, so it reads back.
        let p = speakable(64, "", true);
        assert_eq!(p.chars().filter(|c| c.is_ascii_uppercase()).count(), 64);
        assert!(p.contains(['@', '3', '1', '0', '$', '7']));
        assert!(p.contains(['a', 'e', 'l', 'o', 's', 't']));
        assert!(!SEPS.contains(['@', '3', '1', '0', '$', '7']));
        // Any of the separators, and their bits.
        let p = speakable(64, SEPS, false);
        let seps: std::collections::HashSet<char> =
            p.chars().filter(|c| !c.is_ascii_lowercase()).collect();
        assert!(seps.len() > 8 && seps.iter().all(|c| SEPS.contains(*c)));
        assert_eq!(p.chars().filter(|c| SEPS.contains(*c)).count(), 63);
        assert_eq!(speakable_bits(4, ""), 88);
        assert_eq!(speakable_bits(4, "-_."), 88 + 4);
        assert_eq!(speakable_bits(5, SEPS), 110 + 16);
    }

    #[test]
    fn files_and_history() {
        let s = Store::create(&dir("files"), b"pw", None).unwrap();
        s.put("mail", b"one\n").unwrap();
        s.put("mail", b"two\n").unwrap();
        s.put(&format!("mail{FILES}key.pem"), &[0, 159, 255]).unwrap();
        assert_eq!(s.files("mail").unwrap(), ["key.pem"]);
        assert_eq!(*s.get("mail/.files/key.pem").unwrap(), [0, 159, 255]);
        let h = s.history("mail").unwrap();
        let bodies: Vec<&[u8]> = h.iter().map(|v| &v.1[..]).collect();
        assert_eq!(bodies, [&b"two\n"[..], b"one\n"]);
        s.rename("mail", "post").unwrap();
        assert_eq!(s.files("post").unwrap(), ["key.pem"]);
        s.remove("post").unwrap();
        assert!(s.entries().unwrap().is_empty());
    }

    #[test]
    fn quick_unlock_opens_what_the_password_opens() {
        let d = dir("quick");
        let mut s = Store::create(&d, b"a long master phrase", None).unwrap();
        s.put("mail", b"pw\n").unwrap();
        assert!(quick(&d).is_none());
        let (c, r) = ([7; 32], [9; 20]);
        s.quick_on(b"2468", &c, &r).unwrap();
        assert_eq!(quick(&d), Some((c.to_vec(), true)));
        let q = Store::open_quick(&d, b"2468", &r).unwrap();
        assert_eq!(*q.get("mail").unwrap(), *b"pw\n");
        assert!(Store::open_quick(&d, b"0000", &r).is_err());
        assert!(Store::open_quick(&d, b"2468", &[1; 20]).is_err());
        // The password still opens it alone; no PIN is a setting too.
        Store::open(&d, b"a long master phrase", None).unwrap();
        s.quick_on(b"", &c, &r).unwrap();
        assert_eq!(quick(&d), Some((c.to_vec(), false)));
        Store::open_quick(&d, b"", &r).unwrap();
        // A new password ends it.
        s.lock(b"another phrase", None).unwrap();
        assert!(quick(&d).is_none());
    }

    #[test]
    fn imports_keep_their_dates_and_order() {
        let s = Store::create(&dir("dated"), b"pw", None).unwrap();
        let day = 86_400_000;
        // Out of order, twice, and two in one second.
        for (at, body) in [
            (3 * day, "c"),
            (day, "a"),
            (2 * day, "b"),
            (day, "a"),
            (3 * day, "d"),
        ] {
            s.put_at("mail", body.as_bytes(), at).unwrap();
        }
        let h = s.history("mail").unwrap();
        let bodies: Vec<&[u8]> = h.iter().map(|v| &v.1[..]).collect();
        assert_eq!(bodies, [&b"d"[..], b"c", b"b", b"a"]);
        assert_eq!(h[3].0, day);
        assert_eq!(*s.get("mail").unwrap(), *b"d");
        // In order from the start: one line of versions, nothing flagged.
        let t = Store::create(&dir("dated2"), b"pw", None).unwrap();
        for (at, body) in [(day, "a"), (2 * day, "b"), (2 * day, "c")] {
            t.put_at("mail", body.as_bytes(), at).unwrap();
        }
        assert!(t.conflicts().unwrap().is_empty());
        assert_eq!(t.times("mail").unwrap().unwrap().0, day);
    }

    #[test]
    fn strength_and_breaches() {
        for (pw, most) in [
            ("password1", 20),
            ("aaaaaaaaaaaa", 16),
            ("abcdefgh", 12),
            ("Summer2024", 39),
            ("P@ssw0rd!", 25),
            ("correcthorse", 30),
        ] {
            assert!(strength(pw) <= most, "{pw}: {}", strength(pw));
        }
        assert_eq!(strength(""), 0);
        assert!(strength("k3Vq9xLp2mZt") >= 65);
        assert!(strength(&generate(24, true)) >= 100);
        assert!(strength(&speakable(4, "", false)) >= 65);
        // SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8.
        let (sent, kept) = pwned_key("password");
        assert_eq!(
            (&*sent, &*kept),
            ("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8")
        );
        let text = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:52256179\r\n";
        assert_eq!(pwned_count(&kept, text), 52256179);
        assert_eq!(pwned_count("FFFF", text), 0);
        let s = Store::create(&dir("health"), b"pw", None).unwrap();
        s.put("a", b"hunter2\nuser: x\n").unwrap();
        s.put("b", b"hunter2\n").unwrap();
        s.put("c", generate(24, true).as_bytes()).unwrap();
        let old = format!("{}\nexpires: 2020-01-01\n", generate(24, true));
        s.put("old", old.as_bytes()).unwrap();
        let h = s.health().unwrap();
        let weak: Vec<&str> = h.weak.iter().map(|w| &*w.0).collect();
        assert_eq!(
            (weak, h.reused),
            (vec!["a", "b"], vec![vec!["a".to_string(), "b".into()]])
        );
        assert_eq!(h.expired, ["old"]);
        let stats = s.stats().unwrap();
        let of = |k: &str| stats.iter().find(|r| r.0 == k).unwrap().1.clone();
        assert_eq!(
            (of("Entries"), of("Different passwords"), of("Expired")),
            ("4".into(), "3".into(), "1".into())
        );
        // A phrase of dictionary words is worth its words, not its letters.
        let phrase = strength("correct horse battery staple");
        assert!((40..80).contains(&phrase), "{phrase}");
        // A local copy of the breach list, ordered by hash.
        let (sent, kept) = pwned_key("hunter2");
        let row = |i: u128| {
            format!(
                "{:040X}:1",
                i.wrapping_mul(0x9E3779B97F4A7C15F39CC0605CEDC8)
            )
        };
        let mut rows: Vec<String> = (1..2000).map(row).collect();
        rows.push(format!("{sent}{kept}:7"));
        rows.sort();
        let list = s.dir.join("pwned");
        fs::write(&list, rows.join("\r\n") + "\r\n").unwrap();
        assert_eq!(pwned_file(&list, "hunter2").unwrap(), 7);
        assert_eq!(pwned_file(&list, "not there").unwrap(), 0);
        // The first and the last line are found too.
        for edge in [&rows[0], &rows[rows.len() - 1]] {
            let mut one = [edge.clone(), format!("{sent}{kept}:7")];
            one.sort();
            fs::write(&list, one.join("\r\n") + "\r\n").unwrap();
            assert_eq!(pwned_file(&list, "hunter2").unwrap(), 7);
        }
        let (made, changed) = s.times("a").unwrap().unwrap();
        assert!(made <= changed && s.times("nope").unwrap().is_none());
    }

    #[test]
    fn security_keys() {
        let d = dir("fido");
        let s = Store::create(&d, b"pw", None).unwrap();
        s.put("a", b"1").unwrap();
        assert!(fido(&d).is_none());
        // Two keys, the second added later: each opens it, with the salt
        // of the first; a wrong answer and a stranger do not.
        let salt = s.fido_salt();
        let (one, two) = ([1; 32], [2; 32]);
        s.fido_add(&salt, b"cred-one", true, &one).unwrap();
        assert_eq!(s.fido_salt(), salt);
        s.fido_add(&salt, b"cred-two", false, &two).unwrap();
        let f = fido(&d).unwrap();
        let keys =
            vec![(b"cred-one".to_vec(), true), (b"cred-two".to_vec(), false)];
        assert_eq!((f.salt, f.keys), (salt.clone(), keys));
        for (cred, secret) in [(&b"cred-one"[..], one), (b"cred-two", two)] {
            let o = Store::open_fido(&d, cred, &secret).unwrap();
            assert_eq!(&*o.get("a").unwrap(), b"1");
        }
        assert!(Store::open_fido(&d, b"cred-one", &two).is_err());
        assert!(Store::open_fido(&d, b"cred-none", &one).is_err());
        assert!(s.fido_add(&[9; 32], b"cred-x", false, &one).is_err());
        // Added again, a key is there once; taken off, the other stays.
        s.fido_add(&salt, b"cred-one", false, &one).unwrap();
        assert_eq!(fido(&d).unwrap().keys.len(), 2);
        fido_off(&d, Some(b"cred-one")).unwrap();
        assert!(Store::open_fido(&d, b"cred-one", &one).is_err());
        assert!(Store::open_fido(&d, b"cred-two", &two).is_ok());
        // A new password leaves a key behind: it says so, and is taken off.
        fido_off(&d, None).unwrap();
        assert!(fido(&d).is_none() && !d.join("fido").exists());
        fido_off(&d, None).unwrap();
    }

    #[test]
    fn forms_round_trip() {
        let t = "pw\nuser: ada\nfree line\nurl: https://x.org\ntags: work, mail\nexpires: 2030-01-31\nRecovery email: a@b.c\npin: 12\n  34\notpauth://totp/x?secret=JBSWY3DP\nlast\n";
        let f = Form::parse(t);
        assert_eq!(
            (&*f.pass, &*f.user, &*f.url),
            ("pw", "ada", "https://x.org")
        );
        assert_eq!(
            (&*f.otp, &*f.notes),
            ("otpauth://totp/x?secret=JBSWY3DP", "free line\nlast")
        );
        assert_eq!(f.tags, "work, mail");
        assert_eq!(
            (&*f.expires, &*f.more),
            ("2030-01-31", "Recovery email: a@b.c\npin: 12\n  34")
        );
        assert_eq!(Form::parse(&f.text()), f);
        assert_eq!(field(&f.text(), "user").as_deref(), Some("ada"));
        assert!(field(&f.text(), "otp").is_some());
        // A password is one line, whatever is typed; nothing else: only it.
        let bare = Form { pass: "a\nb".into(), ..Form::default() };
        assert_eq!(bare.text(), "a b\n");
        assert_eq!(Form::parse(""), Form::default());
        // What is saved reads back the same, part by part: notes are
        // notes whatever they say, and a field no parser would know as
        // one is refused, not moved.
        let notes =
            "user: eve\notpauth://totp/z?secret=AA\nkey: v\n\n  x\npin: 1";
        let more = "card_no: 1234\nq2: a: b\n  more of it";
        let f = Form { more: more.into(), notes: notes.into(), ..f };
        assert_eq!(f.problem(), None);
        assert_eq!(Form::parse(&f.text()), f);
        let bare = Form { notes: "todo: x".into(), ..Form::default() };
        assert_eq!(Form::parse(&bare.text()), bare);
        for bad in [
            "Card #: 1",
            "acct.no: 5",
            "key:value",
            "key:  v",
            "key:",
            "no colon",
            "2fa: x",
            "user: eve",
            "otp: x",
            "a b: c",
            "k: otpauth://totp/x",
            "  orphan",
        ] {
            let f = Form { more: bad.into(), ..Form::default() };
            assert!(f.problem().is_some(), "{bad}");
        }
        let odd = |f: Form| f.problem().is_some();
        assert!(odd(Form { otp: "JBSWY3DP".into(), ..Form::default() }));
        assert!(odd(Form { expires: "soon".into(), ..Form::default() }));
    }

    #[test]
    fn passwords() {
        assert_eq!(generate(30, true).len(), 30);
        assert_eq!(
            field("x\notpauth://totp/a?secret=JBSWY3DPEHPK3PXP", "otp")
                .unwrap()
                .len(),
            6
        );
        assert!(
            field("x\notpauth://hotp/a?secret=JBSWY3DPEHPK3PXP", "otp")
                .is_none()
        );
        let rfc =
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8";
        assert_eq!(totp(rfc, 59).unwrap(), "94287082");
        assert!(totp(&format!("{rfc}&period=0"), 59).is_none());
        assert!(
            path_safe("a/b").is_ok()
                && path_safe("../x").is_err()
                && path_safe("/x").is_err()
        );
    }
}
