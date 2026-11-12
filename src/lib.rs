//! `store/v/`: versions, named by hash, never changed, merged by union; each
//! an age file to a random 256-bit store key as scrypt passphrase (N = 2),
//! holding `ms parent size name\n`, body, padding (size 0 deletes). `key`:
//! store keys, newest first, sealed to Argon2id(password, YubiKey). Only the
//! newest key's versions are current; older keys' are history if frozen.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

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
pub mod confine;
#[cfg(feature = "sync")]
pub mod sync;

pub type Secret = Zeroizing<Vec<u8>>;
pub const MAX: usize = 16 << 20;
const KDF: (u32, u32) = if cfg!(test) { (8, 1) } else { (256 << 10, 4) };

pub fn rand<const N: usize>() -> [u8; N] {
    let mut b = [0; N];
    // No safe fallback without OS randomness.
    #[allow(clippy::expect_used)]
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

/// Opens N = 2 files only, so no file can make us run a costly scrypt.
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

/// Tries each key: age stops at the first scrypt passphrase that fails.
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

pub(crate) fn seal(k: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    encrypt(&recipient(k), pt)
}

pub(crate) fn open(k: &[u8], ct: &[u8]) -> Option<Secret> {
    let mut out = Zeroizing::new(vec![]);
    reader(&[identity(k)], ct).ok()?.read_to_end(&mut out).ok()?;
    Some(out)
}

pub fn name_of(b: &[u8]) -> String {
    HEXLOWER.encode(&Sha256::digest(b)[..16])
}

pub fn is_name(n: &str) -> bool {
    n.len() == 32 && n.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// In `store/`, where git holds only ciphertext; moves a legacy `v/` there.
pub fn versions(dir: &Path) -> PathBuf {
    let (v, old) = (dir.join("store").join("v"), dir.join("v"));
    if old.is_dir() {
        let _ = fs::create_dir_all(dir.join("store"));
        if fs::rename(&old, &v).is_err() {
            for e in fs::read_dir(&old).into_iter().flatten().flatten() {
                let _ = fs::rename(e.path(), v.join(e.file_name()));
            }
            let _ = fs::remove_dir(&old);
        }
    }
    v
}

static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// The store: `--dir` ([`set_home`]), else `PASA_DIR`, else `~/.pasa`.
pub fn home() -> PathBuf {
    let env = || std::env::var_os("PASA_DIR").map(PathBuf::from);
    DIR.get().cloned().or_else(env).unwrap_or_else(|| user(".pasa"))
}

/// Once, before [`home`] is asked.
pub fn set_home(dir: &str) {
    let _ = DIR.set(path(dir));
}

fn user(p: &str) -> PathBuf {
    std::env::home_dir().unwrap_or_default().join(p)
}

/// `~` expanded, made absolute.
pub fn path(s: &str) -> PathBuf {
    let p = match s.trim().strip_prefix('~') {
        Some(r) if r.is_empty() || r.starts_with('/') => {
            user(r.trim_start_matches('/'))
        }
        _ => PathBuf::from(s.trim()),
    };
    std::path::absolute(&p).unwrap_or(p)
}

/// `~/.pasa` and the stores chosen on this device (`~/.pasa/stores`, a path
/// a line), those here; and [`home`].
pub fn stores() -> Vec<PathBuf> {
    let t = fs::read_to_string(user(".pasa/stores")).unwrap_or_default();
    let mut all: Vec<PathBuf> = vec![];
    for p in [user(".pasa")].into_iter().chain(t.lines().map(PathBuf::from)) {
        if p.join("key").exists() && !all.contains(&p) {
            all.push(p);
        }
    }
    if !all.contains(&home()) {
        all.push(home());
    }
    all
}

pub fn remember(dir: &Path) -> Result<()> {
    let at = user(".pasa/stores");
    let t = fs::read_to_string(&at).unwrap_or_default();
    if dir == user(".pasa") || t.lines().any(|l| Path::new(l) == dir) {
        return Ok(());
    }
    write(&at, format!("{t}{}\n", dir.display()).as_bytes())
}

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

const OWN: &str = ".pasa/";

/// Notice of a retired key, sealed to that key: `RETIRED` + [`key_id`].
const RETIRED: &str = ".pasa/retired/";

/// Written by a rotation under its new key: SHA-256 of each file then trusted.
/// Older keys' versions count only if listed.
const HISTORY: &str = ".pasa/history";

pub const RETIRED_SAY: &str = "this device's store key was retired: if you \
    revoked a device, pair this one again from where you did; if not, \
    revoke here the device you suspect and pair the others from here";

fn key_id(k: &[u8]) -> String {
    HEXLOWER.encode(&Sha256::digest(k)[..16])
}

pub const NO_STORE: &str = "no store here: pasa init makes one; or pasa join \
    NAME CODE takes one from a device that has it (pasa pair NAME there)";

/// `key`: salt (the YubiKey challenge if byte 32 is 1), that byte, sealed keys.
pub fn challenge(key: &[u8]) -> Option<&[u8]> {
    (key.get(32) == Some(&1)).then(|| &key[..32])
}

fn kek(pw: &[u8], salt: &[u8], yk: Option<&[u8]>) -> Result<Secret> {
    let e = anyhow::Error::msg;
    let p = Params::new(KDF.0, KDF.1, 1, Some(32)).map_err(e)?;
    let a = Argon2::new_with_secret(yk.unwrap_or(&[]), Argon2id, V0x13, p);
    let mut k = Zeroizing::new(vec![0; 32]);
    a.map_err(e)?.hash_password_into(pw, salt, &mut k).map_err(e)?;
    Ok(k)
}

/// Bounds what a file's size reveals.
fn padded(n: usize) -> usize {
    match n.max(256).next_power_of_two() {
        p if p <= 64 << 10 => p,
        _ => n.div_ceil(64 << 10) * (64 << 10),
    }
}

#[derive(Clone)]
pub struct Version {
    pub ms: u64,
    pub size: usize,
    pub name: String,
    /// File of the version this followed, or "-".
    pub parent: String,
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

/// Cache of `v/`'s heads by file, refreshed when its mtime changes.
#[derive(Default)]
struct Index {
    /// Under the newest key: the store as it is.
    heads: HashMap<String, Version>,
    /// Under older keys, with their files' SHA-256: history if frozen.
    old: HashMap<String, (Version, [u8; 32])>,
    frozen: HashSet<[u8; 32]>,
    mtime: Option<SystemTime>,
    tips: HashMap<String, (u64, String)>,
    last: u64,
}

fn sorted<'a>(vs: impl Iterator<Item = &'a Version>) -> Vec<Version> {
    let mut out: Vec<Version> = vs.cloned().collect();
    out.sort_by(|a, b| (a.ms, &a.name, &a.file).cmp(&(b.ms, &b.name, &b.file)));
    out
}

impl Index {
    fn past(&self) -> impl Iterator<Item = &(Version, [u8; 32])> {
        self.old.values().filter(|(_, d)| self.frozen.contains(d))
    }

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
    v: PathBuf,
    /// Newest first; older ones open history.
    keys: Vec<Secret>,
    ids: Vec<age::scrypt::Identity>,
    newest: age::scrypt::Recipient,
    kek: Secret,
    salt: Vec<u8>,
    /// The key file as read or last written: never overwrite a newer one.
    loaded: Mutex<Vec<u8>>,
    index: Mutex<Index>,
    pub unreadable: AtomicUsize,
}

impl Store {
    fn new(
        dir: &Path,
        keys: Vec<Secret>,
        kek: Secret,
        salt: Vec<u8>,
    ) -> Result<Store> {
        Ok(Store {
            dir: dir.into(),
            v: versions(dir),
            ids: keys.iter().map(|k| identity(k)).collect(),
            newest: recipient(keys.first().context("no store key")?),
            keys,
            kek,
            salt,
            loaded: Mutex::new(fs::read(dir.join("key")).unwrap_or_default()),
            index: Default::default(),
            unreadable: 0.into(),
        })
    }

    pub fn create(
        dir: &Path,
        pw: &[u8],
        yk: Option<(&[u8], &[u8])>,
    ) -> Result<Store> {
        ensure!(!dir.join("key").exists(), "{} holds a store", dir.display());
        let mut s =
            Store::new(dir, vec![hedged(pw)], Default::default(), vec![])?;
        s.lock(pw, yk)?;
        Ok(s)
    }

    pub fn open(dir: &Path, pw: &[u8], yk: Option<&[u8]>) -> Result<Store> {
        let f = fs::read(dir.join("key")).context(NO_STORE)?;
        let salt = f.get(..32).context("not a pasa key file")?;
        Store::unsealed(dir, kek(pw, salt, yk)?)
            .context("wrong password or key")
    }

    pub fn open_quick(dir: &Path, pin: &[u8], yk: &[u8]) -> Result<Store> {
        let f = fs::read(dir.join("quick")).context("quick unlock is off")?;
        let (head, sealed) =
            f.split_at_checked(33).context("not a quick file")?;
        let k = kek(pin, &head[..32], Some(yk))?;
        let kek = open(&k, sealed).context("wrong PIN or key")?;
        Store::unsealed(dir, kek)
            .context("quick unlock is out of date: use the password")
    }

    /// `quick`: `challenge`, PIN flag, the KEK sealed to Argon2id(`pin`, `yk`).
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

    pub fn fido_salt(&self) -> Vec<u8> {
        fido(&self.dir).map_or_else(|| rand::<32>().to_vec(), |f| f.salt)
    }

    /// Seals the KEK to `secret`: the key's hmac-secret answer to `salt`.
    pub fn fido_add(
        &self,
        salt: &[u8],
        cred: &[u8],
        pin: bool,
        secret: &[u8],
    ) -> Result<()> {
        ensure!(salt.len() == 32 && secret.len() == 32, "32 bytes each");
        ensure!(fido(&self.dir).is_none_or(|f| f.salt == salt), "another salt");
        let at = self.dir.join("ctap");
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

    pub fn open_fido(dir: &Path, cred: &[u8], secret: &[u8]) -> Result<Store> {
        let f =
            fs::read_to_string(dir.join("ctap")).context("no security key")?;
        let mut keys = f.lines().skip(1).filter_map(fido_line);
        let key =
            keys.find(|k| k.0 == cred).context("not a key of this store")?;
        let kek = open(secret, &key.2)
            .context("the key's answer does not open it")?;
        Store::unsealed(dir, kek)
            .context("the security key is out of date: use the password")
    }

    fn unsealed(dir: &Path, kek: Secret) -> Result<Store> {
        let f = fs::read(dir.join("key")).context(NO_STORE)?;
        let (salt, sealed) =
            f.split_at_checked(33).context("not a pasa key file")?;
        let keys = open(&kek, sealed).context("the key does not open it")?;
        ensure!(
            !keys.is_empty() && keys.len() % 32 == 0,
            "not a pasa key file"
        );
        let keys =
            keys.chunks(32).map(|k| Zeroizing::new(k.to_vec())).collect();
        Store::new(dir, keys, kek, salt.to_vec())
    }

    /// `yk`: a YubiKey's (challenge, response); the challenge is the salt.
    pub fn lock(
        &mut self,
        pw: &[u8],
        yk: Option<(&[u8], &[u8])>,
    ) -> Result<()> {
        let salt = yk.map_or(rand::<32>().to_vec(), |c| c.0.to_vec());
        self.salt = [&salt[..], &[yk.is_some() as u8]].concat();
        self.kek = kek(pw, &salt, yk.map(|c| c.1))?;
        self.save()?;
        // quick and ctap hold the old KEK.
        let _ = fs::remove_file(self.dir.join("quick"));
        let _ = fs::remove_file(self.dir.join("ctap"));
        Ok(())
    }

    /// Refuses if another process rewrote `key` since it was read.
    pub(crate) fn save(&self) -> Result<()> {
        fs::create_dir_all(&self.dir)?;
        let mut lock = fs::OpenOptions::new();
        let lock = lock
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join("key.lock"))?;
        // Android's std has no file lock; one process there, `loaded` suffices.
        match lock.lock() {
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {}
            locked => locked?,
        }
        let mut loaded = self.loaded.lock().unwrap_or_else(|p| p.into_inner());
        let now = fs::read(self.dir.join("key")).unwrap_or_default();
        ensure!(
            now == *loaded,
            "the key file changed since this unlock: unlock again"
        );
        let keys: Secret = Zeroizing::new(
            self.keys.iter().flat_map(|k| k.iter().copied()).collect(),
        );
        let key = [&self.salt[..], &seal(&self.kek, &keys)?].concat();
        write(&self.dir.join("key"), &key)?;
        *loaded = key;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn keys(&self) -> &[Secret] {
        &self.keys
    }

    pub fn passphrases(&self) -> Zeroizing<String> {
        Zeroizing::new(
            self.keys.iter().map(|k| HEXLOWER.encode(k) + "\n").collect(),
        )
    }

    /// Keys a rotation made elsewhere, newest first; true if any was new.
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
            // Which versions are current depends on the newest key.
            *self.index.get_mut().unwrap_or_else(|p| p.into_inner()) =
                Index::default();
            self.save()?;
        }
        Ok(!new.is_empty())
    }

    /// Notice under the old key; [`HISTORY`] and entries under a new one.
    pub fn rotate(&mut self) -> Result<()> {
        let e = self.entries()?.into_values().map(|v| Ok((self.body(&v)?, v)));
        let e = e.collect::<Result<Vec<_>>>()?;
        let old = key_id(self.keys.first().context("no store key")?);
        self.put(&format!("{RETIRED}{old}"), b"retired")?;
        let x = self.index()?;
        let mut frozen: Vec<u8> = x.past().flat_map(|(_, d)| *d).collect();
        let now: Vec<String> = x.heads.keys().cloned().collect();
        drop(x);
        for f in now {
            frozen.extend(Sha256::digest(fs::read(self.v.join(f))?));
        }
        self.add_keys(&rand::<32>())?;
        self.put_on(HISTORY, &frozen, None)?;
        let mut e = e.iter();
        e.try_for_each(|(b, v)| self.put_on(&v.name, b, Some(v.file.clone())))
    }

    pub fn retired(&self) -> bool {
        let Some(k) = self.keys.first() else { return false };
        let at = format!("{RETIRED}{}", key_id(k));
        self.index().is_ok_and(|x| x.tips.contains_key(&at))
    }

    fn version(&self, file: &str) -> Result<impl Read + use<'_>> {
        reader(&self.ids, fs::File::open(self.v.join(file))?)
    }

    /// A version's head, and its file's SHA-256 if an older key opened it.
    fn head(&self, file: &str) -> Option<(Version, Option<[u8; 32]>)> {
        let line = |r| {
            let mut l = String::new();
            std::io::BufReader::new(r).read_line(&mut l).ok()?;
            Version::parse(l.strip_suffix('\n')?, file)
        };
        let (newest, older) = self.ids.split_first()?;
        let f = fs::File::open(self.v.join(file)).ok()?;
        if let Ok(r) = reader(std::slice::from_ref(newest), f) {
            return Some((line(Box::new(r) as Box<dyn Read>)?, None));
        }
        let b = fs::read(self.v.join(file)).ok()?;
        let r = reader(older, &b[..]).ok()?;
        Some((line(Box::new(r))?, Some(Sha256::digest(&b).into())))
    }

    fn index(&self) -> Result<std::sync::MutexGuard<'_, Index>> {
        let mut x = self.index.lock().unwrap_or_else(|p| p.into_inner());
        let v = self.v.clone();
        let mtime = fs::metadata(&v).and_then(|m| m.modified()).ok();
        // mtime granularity: a write in the same tick may not change it.
        let settled = |m: &SystemTime| {
            m.elapsed().is_ok_and(|e| e > std::time::Duration::from_secs(2))
        };
        if x.mtime.is_some()
            && x.mtime == mtime
            && mtime.as_ref().is_some_and(settled)
        {
            return Ok(x);
        }
        let names = fs::read_dir(&v)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok());
        let names: HashSet<String> = names.filter(|n| is_name(n)).collect();
        x.heads.retain(|f, _| names.contains(f));
        x.old.retain(|f, _| names.contains(f));
        let mut bad = 0;
        let known =
            |n: &&String| x.heads.contains_key(*n) || x.old.contains_key(*n);
        let new: Vec<&String> = names.iter().filter(|n| !known(n)).collect();
        for n in new {
            match self.head(n) {
                Some((h, None)) => drop(x.heads.insert(n.clone(), h)),
                Some((h, Some(d))) => drop(x.old.insert(n.clone(), (h, d))),
                None => bad += 1,
            }
        }
        self.unreadable.store(bad, Relaxed);
        x.mtime = mtime;
        (x.tips, x.last) = Default::default();
        let heads = std::mem::take(&mut x.heads);
        heads.values().for_each(|v| x.tip(v));
        x.heads = heads;
        let h = x.tips.get(HISTORY).and_then(|t| x.heads.get(&t.1));
        let h = h.and_then(|v| self.body(v).ok()).unwrap_or_default();
        x.frozen =
            h.chunks_exact(32).filter_map(|d| d.try_into().ok()).collect();
        Ok(x)
    }

    /// Oldest first, frozen history included.
    pub fn versions(&self) -> Result<Vec<Version>> {
        let x = self.index()?;
        Ok(sorted(x.heads.values().chain(x.past().map(|(v, _)| v))))
    }

    pub fn body(&self, v: &Version) -> Result<Secret> {
        let mut b = Zeroizing::new(vec![]);
        self.version(&v.file)?
            .read_to_end(&mut b)
            .context("damaged version")?;
        let at =
            b.iter().position(|&c| c == b'\n').context("damaged version")? + 1;
        // `size` comes from another device: no sum that can overflow.
        let body = b.get(at..).and_then(|b| b.get(..v.size));
        Ok(Zeroizing::new(body.context("damaged version")?.to_vec()))
    }

    pub fn entries(&self) -> Result<BTreeMap<String, Version>> {
        let x = self.index()?;
        let tips = x.tips.values().filter_map(|t| x.heads.get(&t.1));
        let live = tips.filter(|v| v.size > 0 && !v.name.starts_with(OWN));
        Ok(live.map(|v| (v.name.clone(), v.clone())).collect())
    }

    pub fn files(&self, name: &str) -> Result<Vec<String>> {
        let at = format!("{name}{FILES}");
        let all = self.entries()?.into_keys();
        Ok(all.filter_map(|n| n.strip_prefix(&at).map(String::from)).collect())
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        for f in self.files(name)? {
            self.put(&format!("{name}{FILES}{f}"), b"")?;
        }
        self.put(name, b"")
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<()> {
        ensure!(self.get(to).is_err(), "{to} exists");
        for f in self.files(from)? {
            let body = self.get(&format!("{from}{FILES}{f}"))?;
            self.put(&format!("{to}{FILES}{f}"), &body)?;
        }
        self.put(to, &self.get(from)?)?;
        self.remove(from)
    }

    /// (created, changed), in ms.
    pub fn times(&self, name: &str) -> Result<Option<(u64, u64)>> {
        let ms = self.versions()?.into_iter().filter(|v| v.name == name);
        let ms: Vec<u64> = ms.map(|v| v.ms).collect();
        Ok(ms.first().copied().zip(ms.last().copied()))
    }

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

    fn forms(&self) -> Result<Vec<(String, Form)>> {
        let shown = |n: &String| !n.split('/').any(|c| c.starts_with('.'));
        let names = self.entries()?.into_keys().filter(shown);
        let form = |n: String| {
            let f = Form::parse(&String::from_utf8_lossy(&self.get(&n)?));
            Ok((n, f))
        };
        names.map(form).collect()
    }

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
        let size = fs::read_dir(&self.v).into_iter().flatten().flatten();
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

    pub fn history(&self, name: &str) -> Result<Vec<(u64, Secret)>> {
        let mut vs = self.versions()?;
        vs.retain(|v| v.name == name);
        vs.iter().rev().map(|v| Ok((v.ms, self.body(v)?))).collect()
    }

    /// Entries whose newest version's parent is not the one before it.
    pub fn conflicts(&self) -> Result<Vec<String>> {
        let mut last: BTreeMap<String, (String, bool)> = BTreeMap::new();
        for v in sorted(self.index()?.heads.values()) {
            let split = last.get(&v.name).is_some_and(|p| p.0 != v.parent);
            last.insert(v.name.clone(), (v.file, split));
        }
        Ok(last.into_iter().filter(|(_, (_, c))| *c).map(|(n, _)| n).collect())
    }

    pub fn get(&self, name: &str) -> Result<Secret> {
        let x = self.index()?;
        let v = x.tips.get(name).and_then(|t| x.heads.get(&t.1));
        let v = v.filter(|v| v.size > 0);
        let v = v.with_context(|| format!("{name}: not in store"))?.clone();
        drop(x);
        self.body(&v)
    }

    /// Empty `body` deletes; dated after every version seen.
    pub fn put(&self, name: &str, body: &[u8]) -> Result<()> {
        self.put_on(name, body, None)
    }

    /// `parent`: for a rotation, the version under the retired key.
    fn put_on(
        &self,
        name: &str,
        body: &[u8],
        parent: Option<String>,
    ) -> Result<()> {
        let mut x = self.index()?;
        let tip = || x.tips.get(name).map_or("-".into(), |t| t.1.clone());
        let parent = parent.unwrap_or_else(tip);
        let now = std::time::UNIX_EPOCH.elapsed()?.as_millis() as u64;
        let ms = now.max(x.last.saturating_add(1));
        self.keep(&mut x, name, body, ms, parent)
    }

    /// An import, dated `at` ms. The same body in the same second is kept once;
    /// one in the newest version's second goes just after it.
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
        // Never write under a key that may be retired, here or by sync.
        let loaded = self.loaded.lock().unwrap_or_else(|p| p.into_inner());
        let now = fs::read(self.dir.join("key")).unwrap_or_default();
        ensure!(
            now == *loaded,
            "the store key changed since this unlock (a rotation, a new \
             password or a pairing): unlock again"
        );
        drop(loaded);
        let newest = self.keys.first().context("no store key")?;
        ensure!(
            name.starts_with(RETIRED)
                || !x
                    .tips
                    .contains_key(&format!("{RETIRED}{}", key_id(newest))),
            "{RETIRED_SAY}"
        );
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
        write(&self.v.join(&v.file), &ct)?;
        x.mtime = fs::metadata(&self.v).and_then(|m| m.modified()).ok();
        x.tip(&v);
        x.heads.insert(v.file.clone(), v);
        Ok(())
    }
}

/// (YubiKey challenge, PIN?) if quick unlock is on.
pub fn quick(dir: &Path) -> Option<(Vec<u8>, bool)> {
    let f = fs::read(dir.join("quick")).ok()?;
    Some((f.get(..32)?.to_vec(), *f.get(32)? == 1))
}

/// `ctap`: the salt, then per key: credential, PIN flag, sealed KEK; all hex.
pub struct Fido {
    pub salt: Vec<u8>,
    pub keys: Vec<(Vec<u8>, bool)>,
}

fn fido_line(l: &str) -> Option<(Vec<u8>, bool, Vec<u8>)> {
    let mut p = l.split(' ');
    let hex = |p: Option<&str>| HEXLOWER.decode(p?.as_bytes()).ok();
    Some((hex(p.next())?, p.next()? == "1", hex(p.next())?))
}

pub fn fido(dir: &Path) -> Option<Fido> {
    let f = fs::read_to_string(dir.join("ctap")).ok()?;
    let salt = HEXLOWER.decode(f.lines().next()?.as_bytes()).ok()?;
    let keys = f.lines().skip(1).filter_map(fido_line);
    let keys: Vec<_> = keys.map(|(c, pin, _)| (c, pin)).collect();
    (salt.len() == 32 && !keys.is_empty()).then_some(Fido { salt, keys })
}

pub fn frame(out: &mut Vec<u8>, b: &[u8]) {
    out.extend((b.len() as u32).to_be_bytes());
    out.extend(b);
}

pub fn unframe<'a>(b: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (n, rest) = b.split_first_chunk::<4>()?;
    let (f, rest) = rest.split_at_checked(u32::from_be_bytes(*n) as usize)?;
    *b = rest;
    Some(f)
}

/// `ctap` as frames, half the size, for pairing.
pub fn ctap_packed(text: &str) -> Option<Vec<u8>> {
    let mut l = text.lines();
    let mut out = vec![];
    frame(&mut out, &HEXLOWER.decode(l.next()?.as_bytes()).ok()?);
    for (cred, pin, sealed) in l.filter_map(fido_line) {
        for b in [&cred[..], &[pin as u8], &sealed] {
            frame(&mut out, b);
        }
    }
    Some(out)
}

pub fn ctap_unpacked(mut b: &[u8]) -> Option<String> {
    let mut out = HEXLOWER.encode(unframe(&mut b)?) + "\n";
    while !b.is_empty() {
        let (c, p, s) = (unframe(&mut b)?, unframe(&mut b)?, unframe(&mut b)?);
        let (c, s) = (HEXLOWER.encode(c), HEXLOWER.encode(s));
        out += &format!("{c} {} {s}\n", (p == [1]) as u8);
    }
    Some(out)
}

/// `None` removes every key.
pub fn fido_off(dir: &Path, cred: Option<&[u8]>) -> Result<()> {
    let at = dir.join("ctap");
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

/// Uniform, by rejection sampling.
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

const ONSETS: [&str; 32] = [
    "b", "c", "d", "f", "g", "h", "j", "k", "p", "s", "t", "v", "bl", "br",
    "ch", "cl", "cr", "dr", "fl", "fr", "gl", "gr", "pl", "pr", "sh", "sk",
    "sl", "sn", "sp", "st", "th", "tr",
];
const VOWELS: [&str; 8] = ["a", "e", "i", "o", "u", "ai", "ee", "ou"];
const CODAS: [&str; 8] = ["", "n", "m", "l", "r", "ng", "rn", "ll"];

/// Sixteen (4 bits), none a 1337 letter, so leet reads back.
pub const SEPS: &str = "-_.!#%&*+=?^~,:;";

/// `words` two-syllable words, 22 bits each, joined by fresh picks of `seps`
/// (none: capitalised). `leet`: a e l o s t become @ 3 1 0 $ 7 at p = 1/2.
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

pub fn speakable_bits(words: usize, seps: &str) -> u32 {
    let gaps = words.saturating_sub(1) as f64;
    22 * words as u32 + (gaps * (seps.len().max(1) as f64).log2()) as u32
}

pub const FILES: &str = "/.files/";

#[derive(Default, Clone, PartialEq, Debug)]
pub struct Health {
    pub weak: Vec<(String, u32)>,
    pub reused: Vec<Vec<String>>,
    pub expired: Vec<String>,
}

/// Top 10,000 passwords by rank (SecLists, MIT); EFF long list (CC BY 3.0).
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

static SYLLABLES: LazyLock<HashSet<String>> = LazyLock::new(|| {
    let mut all = HashSet::new();
    for (o, v) in ONSETS.iter().flat_map(|o| VOWELS.map(|v| (o, v))) {
        all.extend(CODAS.iter().map(|c| format!("{o}{v}{c}")));
    }
    all
});

/// Estimated bits: the cheapest parse of `pw`.
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
        // A separator between letters costs at most a SEPS pick (4 bits).
        let letter =
            |j: usize| cs.get(j).is_some_and(char::is_ascii_alphabetic);
        let sep =
            SEPS.contains(cs[i - 1]) && i >= 2 && letter(i - 2) && letter(i);
        let one = if sep { each.min(4.0) } else { each };
        best[i] = best[i - 1] + if near { 1.0 } else { one };
        for len in 2..=i.min(6) {
            let part = &cs[i - len..i];
            let (mut plain, mut odd) = (String::new(), 0.0);
            for c in part {
                let at = "@310$7".find(*c);
                odd += (at.is_some() || c.is_ascii_uppercase()) as u8 as f64;
                let c = at.map_or(*c, |i| "aelost".as_bytes()[i] as char);
                plain.push(c.to_ascii_lowercase());
            }
            if SYLLABLES.contains(&plain) {
                best[i] = best[i].min(best[i - len] + 11.0 + odd);
            }
        }
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

/// UTC, as YYYY-MM-DD.
pub fn today() -> String {
    let now = humantime::format_rfc3339_seconds(SystemTime::now());
    now.to_string()[..10].into()
}

/// Binary search of a local HIBP file: `SHA1:COUNT` lines sorted by hash.
pub fn pwned_file(file: &Path, pw: &str) -> Result<u64> {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    let (sent, kept) = pwned_key(pw);
    let want = format!("{sent}{kept}");
    let mut f = BufReader::new(fs::File::open(file)?);
    let (mut lo, mut hi) = (0, f.get_ref().metadata()?.len());
    let mut line = String::new();
    // Bisect bytes: compare the first whole line at or after `mid`.
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

/// HIBP range query: the 5 hex digits of SHA-1 sent, the 35 kept.
pub fn pwned_key(pw: &str) -> (String, String) {
    use sha1::Digest;
    let h = data_encoding::HEXUPPER.encode(&sha1::Sha1::digest(pw.as_bytes()));
    (h[..5].into(), h[5..].into())
}

pub fn pwned_count(rest: &str, text: &str) -> u64 {
    let hit =
        |l: &str| l.trim().strip_prefix(rest)?.strip_prefix(':')?.parse().ok();
    text.lines().find_map(hit).unwrap_or(0)
}

/// Password on line 1, then `key: value` lines; after an empty line, notes.
#[derive(Default, Clone, PartialEq, Debug)]
pub struct Form {
    pub pass: String,
    pub user: String,
    pub url: String,
    pub otp: String,
    /// Comma-separated.
    pub tags: String,
    pub expires: String,
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
        // Lenient on read, strict on save ([`Form::problem`]). `https://x` has
        // no space after the colon.
        let named = |l: &str| {
            l.split_once(':').is_some_and(|(k, v)| {
                k.starts_with(char::is_alphanumeric)
                    && k.chars().count() <= 32
                    && (v.is_empty() || v.starts_with(' '))
            })
        };
        let (mut notes, mut more, mut within) = (vec![], vec![], false);
        // After an empty line all is notes: none is ever taken for a field.
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

    /// Why it can't be saved: each part must read back as itself.
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

    /// Inverse of [`Form::parse`].
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
        // 4 puts, the retired notice, the history list, mail resealed.
        assert_eq!(s.versions().unwrap().len(), 7);
        assert!(s.conflicts().unwrap().is_empty());
        fs::write(
            crate::versions(&d).join("0123456789abcdef0123456789abcdef"),
            b"not ours",
        )
        .unwrap();
        drop(s);
        let mut s = Store::open(&d, b"pw", None).unwrap();
        assert_eq!(s.versions().unwrap().len(), 7);
        assert_eq!(s.unreadable.load(Relaxed), 1);
        s.lock(b"new", Some((&[9; 32], b"hmac"))).unwrap();
        let k = fs::read(d.join("key")).unwrap();
        assert_eq!(challenge(&k), Some(&[9; 32][..]));
        assert!(Store::open(&d, b"new", None).is_err(), "both factors");
        assert!(Store::open(&d, b"new", Some(b"hmac")).is_ok());
    }

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

    #[test]
    fn versions_move_into_store() {
        let d = dir("move");
        let s = Store::create(&d, b"pw", None).unwrap();
        s.put("x", b"1").unwrap();
        drop(s);
        fs::rename(versions(&d), d.join("v")).unwrap();
        fs::write(d.join("v/a"), b"").unwrap();
        fs::create_dir_all(d.join("store/v")).unwrap();
        let s = Store::open(&d, b"pw", None).unwrap();
        assert!(!d.join("v").exists());
        assert!(d.join("store/v/a").exists());
        assert_eq!(&s.get("x").unwrap()[..], b"1");
    }

    #[test]
    fn a_stale_session_writes_nothing() {
        let d = dir("stale-write");
        drop(Store::create(&d, b"pw", None).unwrap());
        let mut a = Store::open(&d, b"pw", None).unwrap();
        let b = Store::open(&d, b"pw", None).unwrap();
        b.put("x", b"1").unwrap();
        a.rotate().unwrap();
        assert!(b.put("x", b"2").is_err(), "sealed to a retired key");
        assert!(b.remove("x").is_err());
        a.put("x", b"3").unwrap();
        Store::open(&d, b"pw", None).unwrap().put("x", b"4").unwrap();
    }

    /// It then writes nothing until paired again.
    #[test]
    fn a_retired_key_is_learnt_by_sync() {
        let d = dir("retired");
        let (a, b) = (d.join("a"), d.join("b"));
        let s = Store::create(&a, b"pw", None).unwrap();
        s.put("x", b"1").unwrap();
        drop(s);
        let sync = |from: &Path, to: &Path| {
            fs::create_dir_all(crate::versions(to)).unwrap();
            for e in fs::read_dir(crate::versions(from)).unwrap().flatten() {
                fs::copy(e.path(), crate::versions(to).join(e.file_name()))
                    .unwrap();
            }
        };
        sync(&a, &b);
        fs::copy(a.join("key"), b.join("key")).unwrap();
        Store::open(&b, b"pw", None).unwrap().put("y", b"2").unwrap();
        let mut sa = Store::open(&a, b"pw", None).unwrap();
        sa.rotate().unwrap();
        assert!(!sa.retired());
        sync(&a, &b);
        let sb = Store::open(&b, b"pw", None).unwrap();
        assert!(sb.retired());
        assert!(sb.put("y", b"3").is_err());
        assert_eq!(&sb.get("x").unwrap()[..], b"1", "it still reads");
        fs::copy(a.join("key"), b.join("key")).unwrap();
        let sb = Store::open(&b, b"pw", None).unwrap();
        assert!(!sb.retired());
        sb.put("y", b"3").unwrap();
    }

    /// Whatever its date: not in history or the clock, nor on later devices.
    #[test]
    fn a_retired_key_replaces_and_adds_nothing() {
        let d = dir("revoked");
        let (a, r, c) = (d.join("a"), d.join("r"), d.join("c"));
        let copy = |from: &Path, to: &Path| {
            fs::create_dir_all(crate::versions(to)).unwrap();
            for e in fs::read_dir(crate::versions(from)).unwrap().flatten() {
                fs::copy(e.path(), crate::versions(to).join(e.file_name()))
                    .unwrap();
            }
            fs::copy(from.join("key"), to.join("key")).unwrap();
        };
        let s = Store::create(&a, b"pw", None).unwrap();
        s.put("bank", b"1").unwrap();
        s.put("mail", b"m").unwrap();
        drop(s);
        copy(&a, &r);
        let mut sa = Store::open(&a, b"pw", None).unwrap();
        sa.rotate().unwrap();
        let sr = Store::open(&r, b"pw", None).unwrap();
        sr.put("bank", b"forged").unwrap();
        sr.put("new", b"planted").unwrap();
        sr.put_at("mail", b"backdated", 1).unwrap();
        sr.put_at("bank", b"ahead", u64::MAX / 4).unwrap();
        for e in fs::read_dir(crate::versions(&r)).unwrap().flatten() {
            let to = crate::versions(&a).join(e.file_name());
            let _ = fs::copy(e.path(), to);
        }
        let check = |s: &Store, n: usize| {
            assert_eq!(&s.get("bank").unwrap()[..], b"1");
            assert_eq!(&s.get("mail").unwrap()[..], b"m");
            assert!(s.get("new").is_err());
            let names = s.entries().unwrap().into_keys();
            let names: Vec<String> = names.filter(|n| n != "x").collect();
            assert_eq!(names, ["bank", "mail"]);
            for v in s.versions().unwrap() {
                let b = s.body(&v).unwrap();
                assert!(
                    ![&b"forged"[..], b"planted", b"backdated", b"ahead"]
                        .contains(&&b[..])
                );
            }
            let h = s.history("bank").unwrap();
            assert_eq!(h.len(), n, "1, and sealed again at each rotation");
            assert!(s.conflicts().unwrap().is_empty());
            s.put("x", b"y").unwrap();
            let x = s.versions().unwrap().into_iter().find(|v| v.name == "x");
            assert!(x.unwrap().ms < u64::MAX / 8, "the clock stays");
        };
        let sa = Store::open(&a, b"pw", None).unwrap();
        check(&sa, 2);
        copy(&a, &c);
        check(&Store::open(&c, b"pw", None).unwrap(), 2);
        // Rotated again: frozen history stays, the rest stays out.
        let mut sa = Store::open(&a, b"pw", None).unwrap();
        sa.rotate().unwrap();
        check(&sa, 3);
    }

    #[test]
    fn store_paths_are_absolute_and_tilde_is_home() {
        let (h, here) =
            (std::env::home_dir().unwrap(), std::env::current_dir().unwrap());
        assert_eq!(path("~"), h);
        assert_eq!(path(" ~/a/b "), h.join("a/b"));
        assert_eq!(path("/x/y"), PathBuf::from("/x/y"));
        assert_eq!(path("rel"), here.join("rel"));
        assert_eq!(path("~bob"), here.join("~bob"));
    }

    #[test]
    fn a_bad_revocation_is_a_fork_the_good_devices_leave() {
        let d = dir("fork");
        let (a, b) = (d.join("a"), d.join("bad"));
        let s = Store::create(&a, b"pw", None).unwrap();
        s.put("x", b"1").unwrap();
        drop(s);
        let copy = |from: &Path, to: &Path| {
            fs::create_dir_all(crate::versions(to)).unwrap();
            for e in fs::read_dir(crate::versions(from)).unwrap().flatten() {
                let _ =
                    fs::copy(e.path(), crate::versions(to).join(e.file_name()));
            }
        };
        copy(&a, &b);
        fs::copy(a.join("key"), b.join("key")).unwrap();
        let mut sb = Store::open(&b, b"pw", None).unwrap();
        sb.rotate().unwrap();
        sb.put("x", b"bad").unwrap();
        copy(&b, &a);
        let mut sa = Store::open(&a, b"pw", None).unwrap();
        assert!(sa.retired() && sa.put("x", b"2").is_err());
        assert_eq!(&sa.get("x").unwrap()[..], b"1");
        sa.rotate().unwrap();
        sa.put("x", b"2").unwrap();
        assert!(!sa.retired());
        assert_eq!(&sa.get("x").unwrap()[..], b"2");
        assert_eq!(sa.history("x").unwrap().len(), 3, "1, sealed again, 2");
    }

    /// The newer wins, flagged until an edit follows it.
    #[test]
    fn concurrent_edits_are_flagged() {
        let d = dir("conflict");
        let s = Store::create(&d, b"pw", None).unwrap();
        s.put("x", b"1").unwrap();
        let o = d.join("other");
        let copy = |from: &Path, to: &Path| {
            for e in fs::read_dir(crate::versions(from)).unwrap().flatten() {
                fs::create_dir_all(crate::versions(to)).unwrap();
                fs::copy(e.path(), crate::versions(to).join(e.file_name()))
                    .unwrap();
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

    #[test]
    fn versions_are_age_files() {
        let d = dir("age");
        let s = Store::create(&d, b"pw", None).unwrap();
        s.put("x", b"hunter2").unwrap();
        let v = &s.entries().unwrap()["x"];
        let ct = fs::read(crate::versions(&d).join(&v.file)).unwrap();
        assert!(ct.starts_with(b"age-encryption.org/v1\n-> scrypt "));
        let pt = open(&s.keys()[0], &ct).unwrap();
        assert!(pt.starts_with(format!("{}\nhunter2", v.line()).as_bytes()));
        assert_eq!(pt.len(), 256, "padded");
    }

    /// Extreme size or time: damaged, not a panic; later writes still work.
    #[test]
    fn sizes_and_times_from_elsewhere_overflow_nothing() {
        let d = dir("overflow");
        let s = Store::create(&d, b"pw", None).unwrap();
        let line = format!("{} - {} x\n", u64::MAX, usize::MAX);
        let ct = seal(&s.keys()[0], line.as_bytes()).unwrap();
        write(&crate::versions(&d).join(name_of(&ct)), &ct).unwrap();
        assert!(s.get("x").is_err(), "damaged");
        s.put("y", b"after").unwrap();
        assert_eq!(&s.get("y").unwrap()[..], b"after");
    }

    #[test]
    fn speakable_passwords_keep_their_bits() {
        // Coda+onset pairs are unique, so syllables parse one way.
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
        // Leet digits are neither syllable letters nor separators.
        let p = speakable(64, "", true);
        assert_eq!(p.chars().filter(|c| c.is_ascii_uppercase()).count(), 64);
        assert!(p.contains(['@', '3', '1', '0', '$', '7']));
        assert!(p.contains(['a', 'e', 'l', 'o', 's', 't']));
        assert!(!SEPS.contains(['@', '3', '1', '0', '$', '7']));
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
        Store::open(&d, b"a long master phrase", None).unwrap();
        s.quick_on(b"", &c, &r).unwrap();
        assert_eq!(quick(&d), Some((c.to_vec(), false)));
        Store::open_quick(&d, b"", &r).unwrap();
        s.lock(b"another phrase", None).unwrap();
        assert!(quick(&d).is_none());
    }

    #[test]
    fn imports_keep_their_dates_and_order() {
        let s = Store::create(&dir("dated"), b"pw", None).unwrap();
        let day = 86_400_000;
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
        for _ in 0..100 {
            let near = |pw: String, bits: u32| {
                let got = strength(&pw);
                // Chance repeats and runs cost some bits, never most.
                assert!(got * 5 >= bits * 3, "{pw}: {got} for {bits}");
                assert!(got <= bits + 28, "{pw}: {got} for {bits}");
            };
            near(speakable(4, "", false), 88);
            near(speakable(5, "-", false), 110);
            near(speakable(4, SEPS, false), speakable_bits(4, SEPS));
            near(speakable(3, "", true), 66 + 6);
            near(generate(24, true), 151);
            near(generate(16, false), 95);
        }
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
        let phrase = strength("correct horse battery staple");
        assert!((40..80).contains(&phrase), "{phrase}");
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
        s.fido_add(&salt, b"cred-one", false, &one).unwrap();
        assert_eq!(fido(&d).unwrap().keys.len(), 2);
        fido_off(&d, Some(b"cred-one")).unwrap();
        assert!(Store::open_fido(&d, b"cred-one", &one).is_err());
        assert!(Store::open_fido(&d, b"cred-two", &two).is_ok());
        fido_off(&d, None).unwrap();
        assert!(fido(&d).is_none() && !d.join("ctap").exists());
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
        let bare = Form { pass: "a\nb".into(), ..Form::default() };
        assert_eq!(bare.text(), "a b\n");
        assert_eq!(Form::parse(""), Form::default());
        // Notes stay notes; a field no parser would know is refused, not moved.
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
