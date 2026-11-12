//! libapasa.so: pasa for com.apasa.Native (errors become RuntimeExceptions),
//! and pushir's org.pushir.Native.

extern crate pushir;

use anyhow::Context;
use jni::errors::ThrowRuntimeExAndDefault as Throw;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::jlong;
use jni::{Env, EnvUnowned};
use pasa::{Store, sync};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{LazyLock, Mutex};

static STORES: LazyLock<Mutex<HashMap<jlong, Store>>> =
    LazyLock::new(Default::default);
static RT: LazyLock<tokio::runtime::Runtime> =
    LazyLock::new(|| tokio::runtime::Runtime::new().expect("tokio"));

/// Any error, as a Java exception's message.
#[derive(Debug)]
struct Fail(String);

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Fail {}

impl From<jni::errors::Error> for Fail {
    fn from(e: jni::errors::Error) -> Self {
        Fail(e.to_string())
    }
}

impl From<anyhow::Error> for Fail {
    fn from(e: anyhow::Error) -> Self {
        Fail(format!("{e:#}"))
    }
}

type Result<T> = std::result::Result<T, Fail>;

/// Run `f`; an error or panic becomes a RuntimeException in Java.
fn run<'l, T: Default>(
    env: &mut EnvUnowned<'l>,
    f: impl FnOnce(&mut Env<'l>) -> Result<T>,
) -> T {
    env.with_env(f).resolve::<Throw>()
}

fn bytes(e: &Env, j: &JByteArray) -> Result<Option<Vec<u8>>> {
    Ok(if j.is_null() { None } else { Some(e.convert_byte_array(j)?) })
}

fn with<T>(h: jlong, f: impl FnOnce(&Store) -> anyhow::Result<T>) -> Result<T> {
    Ok(f(STORES.lock().unwrap().get(&h).context("locked")?)?)
}

fn report(r: Vec<(String, anyhow::Result<usize>)>) -> String {
    let line = |(w, r): (String, anyhow::Result<usize>)| match r {
        Ok(n) => format!("{w}: {n} new"),
        Err(e) => format!("{w}: {e:#}"),
    };
    r.into_iter().map(line).collect::<Vec<_>>().join("\n")
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_challenge<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    dir: JString<'l>,
) -> JByteArray<'l> {
    run(&mut env, |e| {
        let k = std::fs::read(Path::new(&dir.to_string()).join("key"))
            .unwrap_or_default();
        Ok(match pasa::challenge(&k) {
            Some(c) => e.byte_array_from_slice(c)?,
            None => JByteArray::default(),
        })
    })
}

/// `create`: a new store; `chal`/`resp`: a YubiKey's, or null.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_open<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    dir: JString<'l>,
    pw: JByteArray<'l>,
    chal: JByteArray<'l>,
    resp: JByteArray<'l>,
    create: bool,
) -> jlong {
    run(&mut env, |e| {
        let (dir, pw) = (dir.to_string(), bytes(e, &pw)?.unwrap_or_default());
        let (c, r) = (bytes(e, &chal)?, bytes(e, &resp)?);
        let dir = Path::new(&dir);
        let st = match create {
            true => Store::create(dir, &pw, c.as_deref().zip(r.as_deref()))?,
            false => Store::open(dir, &pw, r.as_deref())?,
        };
        opened(st)
    })
}

/// An opened store's handle.
fn opened(st: Store) -> Result<jlong> {
    let h = jlong::from_be_bytes(pasa::rand());
    STORES.lock().unwrap().insert(h, st);
    Ok(h)
}

/// Quick unlock, if it is on here: the YubiKey's challenge, then 1 if a
/// PIN goes with its answer; else null.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_quick<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    dir: JString<'l>,
) -> JByteArray<'l> {
    run(&mut env, |e| {
        Ok(match pasa::quick(Path::new(&dir.to_string())) {
            Some((c, pin)) => {
                e.byte_array_from_slice(&[&c[..], &[pin as u8]].concat())?
            }
            None => JByteArray::default(),
        })
    })
}

/// Open by the YubiKey's answer and the PIN (empty: none).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_openQuick<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    dir: JString<'l>,
    pin: JByteArray<'l>,
    resp: JByteArray<'l>,
) -> jlong {
    run(&mut env, |e| {
        let pin = zeroize::Zeroizing::new(bytes(e, &pin)?.unwrap_or_default());
        let resp = bytes(e, &resp)?.unwrap_or_default();
        opened(Store::open_quick(Path::new(&dir.to_string()), &pin, &resp)?)
    })
}

/// Turn quick unlock on for an open store: a PIN (empty: none), and the
/// YubiKey's answer to a fresh 32-byte challenge.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_quickOn<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
    pin: JByteArray<'l>,
    chal: JByteArray<'l>,
    resp: JByteArray<'l>,
) {
    run(&mut env, |e| {
        let pin = zeroize::Zeroizing::new(bytes(e, &pin)?.unwrap_or_default());
        let (c, r) = (bytes(e, &chal)?, bytes(e, &resp)?);
        let (c, r) = (c.unwrap_or_default(), r.unwrap_or_default());
        with(h, |s| s.quick_on(&pin, &c, &r))
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_quickOff<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    dir: JString<'l>,
) {
    run(&mut env, |_| {
        let _ = std::fs::remove_file(Path::new(&dir.to_string()).join("quick"));
        Ok(())
    })
}

/// The security keys that open the store here: the salt, then a line a
/// key (its credential, a space, 1 if its PIN goes with it), hex; "" if
/// none.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_fido<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    dir: JString<'l>,
) -> JString<'l> {
    run(&mut env, |e| {
        let hex =
            |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let f = pasa::fido(Path::new(&dir.to_string()));
        let lines = f.map_or(vec![], |f| {
            let key =
                |k: &(Vec<u8>, bool)| format!("{} {}", hex(&k.0), k.1 as u8);
            std::iter::once(hex(&f.salt))
                .chain(f.keys.iter().map(key))
                .collect()
        });
        Ok(e.new_string(lines.join("\n"))?)
    })
}

/// The salt a security key is asked with for an open store.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_fidoSalt<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
) -> JByteArray<'l> {
    run(&mut env, |e| {
        Ok(e.byte_array_from_slice(&with(h, |s| Ok(s.fido_salt()))?)?)
    })
}

/// Let a security key open an open store here ([`pasa::Store::fido_add`]).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_fidoAdd<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
    salt: JByteArray<'l>,
    cred: JByteArray<'l>,
    pin: bool,
    secret: JByteArray<'l>,
) {
    run(&mut env, |e| {
        let salt = bytes(e, &salt)?.unwrap_or_default();
        let cred = bytes(e, &cred)?.unwrap_or_default();
        let secret =
            zeroize::Zeroizing::new(bytes(e, &secret)?.unwrap_or_default());
        with(h, |s| s.fido_add(&salt, &cred, pin, &secret))
    })
}

/// Open by a security key's answer ([`pasa::Store::open_fido`]).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_openFido<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    dir: JString<'l>,
    cred: JByteArray<'l>,
    secret: JByteArray<'l>,
) -> jlong {
    run(&mut env, |e| {
        let cred = bytes(e, &cred)?.unwrap_or_default();
        let secret =
            zeroize::Zeroizing::new(bytes(e, &secret)?.unwrap_or_default());
        opened(Store::open_fido(Path::new(&dir.to_string()), &cred, &secret)?)
    })
}

/// No security key opens the store here any more.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_fidoOff<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    dir: JString<'l>,
) {
    run(&mut env, |_| Ok(pasa::fido_off(Path::new(&dir.to_string()), None)?))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_close<'l>(
    _: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
) {
    STORES.lock().unwrap().remove(&h);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_names<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
) -> JString<'l> {
    run(&mut env, |e| {
        let n = with(h, |s| {
            Ok(s.entries()?
                .into_keys()
                .filter(|n| !n.split('/').any(|c| c.starts_with('.'))))
        })?;
        Ok(e.new_string(n.collect::<Vec<_>>().join("\n"))?)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_get<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
    name: JString<'l>,
) -> JString<'l> {
    run(&mut env, |e| {
        let v = with(h, |s| {
            Ok(String::from_utf8_lossy(&s.get(&name.to_string())?).into_owned())
        })?;
        Ok(e.new_string(v)?)
    })
}

/// An empty body deletes.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_put<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
    name: JString<'l>,
    body: JString<'l>,
) {
    run(&mut env, |_| {
        with(h, |s| s.put(&name.to_string(), body.to_string().as_bytes()))
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_field<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    body: JString<'l>,
    f: JString<'l>,
) -> JString<'l> {
    run(&mut env, |e| {
        Ok(e.new_string(
            pasa::field(&body.to_string(), &f.to_string()).unwrap_or_default(),
        )?)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_generate<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    len: i32,
    symbols: bool,
) -> JString<'l> {
    run(&mut env, |e| Ok(e.new_string(pasa::generate(len as usize, symbols))?))
}

/// A guess at a typed password's bits ([`pasa::strength`]).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_strength<'l>(
    _: EnvUnowned<'l>,
    _: JClass<'l>,
    pw: JString<'l>,
) -> i32 {
    pasa::strength(&pw.to_string()) as i32
}

/// When an entry was made and last changed: milliseconds, a line each;
/// empty if there is none.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_times<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
    name: JString<'l>,
) -> JString<'l> {
    run(&mut env, |e| {
        let t = with(h, |s| s.times(&name.to_string()))?;
        let t = t.map(|(made, changed)| format!("{made}\n{changed}"));
        Ok(e.new_string(t.unwrap_or_default())?)
    })
}

/// Weak passwords as `weak`, tab, name, tab, bits; shared ones as
/// `reused`, then the names, tabs between; expired ones as `expired`,
/// tab, name: a line each.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_health<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
) -> JString<'l> {
    run(&mut env, |e| {
        let h = with(h, |s| s.health())?;
        let weak = h.weak.iter().map(|(n, b)| format!("weak\t{n}\t{b}"));
        let reused =
            h.reused.iter().map(|g| format!("reused\t{}", g.join("\t")));
        let expired = h.expired.iter().map(|n| format!("expired\t{n}"));
        let all: Vec<String> = weak.chain(reused).chain(expired).collect();
        Ok(e.new_string(all.join("\n"))?)
    })
}

/// The store in numbers: what each counts, a tab, the count; a line each.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_stats<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
) -> JString<'l> {
    run(&mut env, |e| {
        let rows = with(h, |s| s.stats())?;
        let rows: Vec<String> =
            rows.iter().map(|(what, n)| format!("{what}\t{n}")).collect();
        Ok(e.new_string(rows.join("\n"))?)
    })
}

/// For a breach lookup: what of the password's SHA-1 is sent, then what
/// is kept, a line each ([`pasa::pwned_key`]).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_pwnedKey<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    pw: JString<'l>,
) -> JString<'l> {
    run(&mut env, |e| {
        let (sent, kept) = pasa::pwned_key(&pw.to_string());
        Ok(e.new_string(format!("{sent}\n{kept}"))?)
    })
}

/// How often the lookup's answer lists what was kept.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_pwnedCount<'l>(
    _: EnvUnowned<'l>,
    _: JClass<'l>,
    kept: JString<'l>,
    text: JString<'l>,
) -> jlong {
    pasa::pwned_count(&kept.to_string(), &text.to_string()) as jlong
}

/// A password to say aloud ([`pasa::speakable`]).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_speakable<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    words: i32,
    seps: JString<'l>,
    leet: bool,
) -> JString<'l> {
    run(&mut env, |e| {
        let seps = seps.to_string().replace(|c: char| !c.is_ascii(), "");
        Ok(e.new_string(pasa::speakable(words as usize, &seps, leet))?)
    })
}

/// Delete an entry and what is attached to it.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_remove<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
    name: JString<'l>,
) {
    run(&mut env, |_| with(h, |s| s.remove(&name.to_string())))
}

/// An entry and what is attached to it, under a new name.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_rename<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
    from: JString<'l>,
    to: JString<'l>,
) {
    run(&mut env, |_| with(h, |s| s.rename(&from.to_string(), &to.to_string())))
}

/// An entry's versions, newest first: milliseconds, U+001F, the text;
/// U+001E between versions.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_history<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
    name: JString<'l>,
) -> JString<'l> {
    run(&mut env, |e| {
        let all = with(h, |s| s.history(&name.to_string()))?;
        let one = |(ms, b): &(u64, pasa::Secret)| {
            format!("{ms}\u{1f}{}", String::from_utf8_lossy(b))
        };
        let all: Vec<String> = all.iter().map(one).collect();
        Ok(e.new_string(all.join("\u{1e}"))?)
    })
}

/// The names of the files attached to an entry, one a line.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_files<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
    name: JString<'l>,
) -> JString<'l> {
    run(&mut env, |e| {
        let f = with(h, |s| s.files(&name.to_string()))?;
        Ok(e.new_string(f.join("\n"))?)
    })
}

/// An entry's bytes as they are: an attached file's.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_bytes<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
    name: JString<'l>,
) -> JByteArray<'l> {
    run(&mut env, |e| {
        let b = with(h, |s| s.get(&name.to_string()))?;
        Ok(e.byte_array_from_slice(&b)?)
    })
}

/// Keep bytes as an entry: an attached file.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_keep<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
    name: JString<'l>,
    body: JByteArray<'l>,
) {
    run(&mut env, |e| {
        let b = zeroize::Zeroizing::new(bytes(e, &body)?.unwrap_or_default());
        with(h, |s| s.put(&name.to_string(), &b))
    })
}

/// An entry's text as its form: password, user, url, otpauth URI, tags,
/// expiry date, other fields and notes, U+001F between them.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_form<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    body: JString<'l>,
) -> JString<'l> {
    run(&mut env, |e| {
        let f = pasa::Form::parse(&body.to_string());
        let all =
            [f.pass, f.user, f.url, f.otp, f.tags, f.expires, f.more, f.notes];
        Ok(e.new_string(all.join("\u{1f}"))?)
    })
}

/// A form as [`Java_com_apasa_Native_form`] gives it.
fn form(form: &JString) -> pasa::Form {
    let s = form.to_string();
    let mut p = s.splitn(8, '\u{1f}').map(String::from);
    let mut next = || p.next().unwrap_or_default();
    pasa::Form {
        pass: next(),
        user: next(),
        url: next(),
        otp: next(),
        tags: next(),
        expires: next(),
        more: next(),
        notes: next(),
    }
}

/// The entry's text of a form.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_text<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    f: JString<'l>,
) -> JString<'l> {
    run(&mut env, |e| Ok(e.new_string(form(&f).text())?))
}

/// Why a form may not be saved as it is ([`pasa::Form::problem`]), or "".
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_problem<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    f: JString<'l>,
) -> JString<'l> {
    run(&mut env, |e| Ok(e.new_string(form(&f).problem().unwrap_or_default())?))
}

/// The paired devices' names, one a line.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_peers<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    dir: JString<'l>,
) -> JString<'l> {
    run(&mut env, |e| {
        let ps = sync::peers(Path::new(&dir.to_string()));
        let names: Vec<String> = ps.into_iter().map(|p| p.name).collect();
        Ok(e.new_string(names.join("\n"))?)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_forget<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    dir: JString<'l>,
    name: JString<'l>,
) {
    run(&mut env, |_| {
        Ok(sync::forget(Path::new(&dir.to_string()), &name.to_string())?)
    })
}

/// Let a device pair, called `name` here: its code, carrying the key file as
/// it is (the store stays as it is). With `qr_pw` an offline QR code's text
/// under that password; else a short code.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_pair<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
    name: JString<'l>,
    qr_pw: JString<'l>,
) -> JString<'l> {
    run(&mut env, |e| {
        let name = name.to_string();
        let pw = (!qr_pw.is_null()).then(|| qr_pw.to_string());
        let dir = STORES.lock().unwrap().get(&h).context("locked")?.dir.clone();
        let got = sync::offer(&dir, &name)?;
        let code = match pw {
            Some(pw) => RT.block_on(sync::qr(&got, &pw))?,
            None => RT.block_on(sync::give(&got))?.0,
        };
        Ok(e.new_string(code)?)
    })
}

/// While the app shows (and sync is on): paired devices dial here.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_serve<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    dir: JString<'l>,
    on: bool,
) {
    static SERVING: Mutex<Option<tokio::task::JoinHandle<()>>> =
        Mutex::new(None);
    run(&mut env, |_| {
        let mut s = SERVING.lock().unwrap_or_else(|p| p.into_inner());
        // Ended, its endpoint and key's lock let go, before another starts.
        if let Some(h) = s.take() {
            h.abort();
            let _ = RT.block_on(h);
        }
        let dir = std::path::PathBuf::from(dir.to_string());
        if on {
            let go = async move { drop(sync::serve(&dir, |_, _| {}).await) };
            *s = Some(RT.spawn(go));
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_join<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    dir: JString<'l>,
    name: JString<'l>,
    code: JString<'l>,
    pw: JString<'l>,
) -> JString<'l> {
    run(&mut env, |e| {
        let (dir, name) = (dir.to_string(), name.to_string());
        let dir = Path::new(&dir);
        let (code, pw) = (code.to_string(), pw.to_string());
        let got = match code.trim().starts_with("PAIRIR1:") {
            true => RT.block_on(sync::unqr(&code, &pw))?,
            false => RT.block_on(sync::fetch(&code))?,
        };
        // The key file and the store, as they are: the password opens
        // them afterwards.
        sync::take(dir, &name, &got)?;
        Ok(e.new_string(report(RT.block_on(sync::sync(dir, false))?))?)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_sync<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    dir: JString<'l>,
    news: bool,
) -> JString<'l> {
    run(&mut env, |e| {
        let r = RT.block_on(sync::sync(Path::new(&dir.to_string()), news))?;
        Ok(e.new_string(report(r))?)
    })
}

/// This device's pushir lane secret for pasa.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_lane<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    dir: JString<'l>,
) -> JByteArray<'l> {
    run(&mut env, |e| {
        Ok(e.byte_array_from_slice(&sync::lane(Path::new(&dir.to_string()))?)?)
    })
}

/// The mailbox pushir gave this device, for peers to wake it.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_mailbox<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    dir: JString<'l>,
    id: JString<'l>,
) {
    run(&mut env, |_| {
        let id = id.to_string().parse().map_err(anyhow::Error::from)?;
        Ok(sync::set_mailbox(Path::new(&dir.to_string()), id)?)
    })
}

/// A push on our lane (a peer's wake, or the connection back from a gap):
/// sync, and say how it went. One at a time: a push during a sync waits,
/// and those that pile up behind it make one sync, not one each.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_wake<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    dir: JString<'l>,
) -> JString<'l> {
    static WAITING: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    static SYNC: Mutex<()> = Mutex::new(());
    run(&mut env, |e| {
        use std::sync::atomic::Ordering::SeqCst;
        if WAITING.swap(true, SeqCst) {
            return Ok(e.new_string("")?);
        }
        let _one = SYNC.lock().unwrap_or_else(|p| p.into_inner());
        WAITING.store(false, SeqCst);
        let r = RT.block_on(sync::sync(Path::new(&dir.to_string()), false))?;
        Ok(e.new_string(report(r))?)
    })
}
