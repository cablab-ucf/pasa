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
/// A joined pairing's hand-over key, in memory until the unlock that
/// follows seals it into `dev`.
static PENDING: Mutex<Option<(String, zeroize::Zeroizing<Vec<u8>>)>> =
    Mutex::new(None);
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
        let mut st = match create {
            true => Store::create(dir, &pw, c.as_deref().zip(r.as_deref()))?,
            false => Store::open(dir, &pw, r.as_deref())?,
        };
        if let Some((name, hand)) = PENDING.lock().unwrap().take() {
            sync::keep_hand(&mut st, &name, &hand)?;
        }
        sync::adopt(&mut st)?;
        let h = jlong::from_be_bytes(pasa::rand());
        STORES.lock().unwrap().insert(h, st);
        Ok(h)
    })
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

/// A password to say aloud ([`pasa::speakable`]).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_speakable<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    words: i32,
    hyphens: bool,
    leet: bool,
) -> JString<'l> {
    run(&mut env, |e| {
        Ok(e.new_string(pasa::speakable(words as usize, hyphens, leet))?)
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

/// An entry's text as its form: password, user, url, otpauth URI and
/// notes, U+001F between them.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_form<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    body: JString<'l>,
) -> JString<'l> {
    run(&mut env, |e| {
        let f = pasa::Form::parse(&body.to_string());
        Ok(e.new_string(
            [f.pass, f.user, f.url, f.otp, f.notes].join("\u{1f}"),
        )?)
    })
}

/// The entry's text of a form as [`Java_com_apasa_Native_form`] gives it.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_text<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    form: JString<'l>,
) -> JString<'l> {
    run(&mut env, |e| {
        let s = form.to_string();
        let mut p = s.splitn(5, '\u{1f}').map(String::from);
        let mut next = || p.next().unwrap_or_default();
        let f = pasa::Form {
            pass: next(),
            user: next(),
            url: next(),
            otp: next(),
            notes: next(),
        };
        Ok(e.new_string(f.text())?)
    })
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

/// Let a device join, called `name` here: its code, then the pairing
/// password, a line each.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_apasa_Native_pair<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    h: jlong,
    name: JString<'l>,
) -> JString<'l> {
    run(&mut env, |e| {
        let pw = sync::password();
        let mut stores = STORES.lock().unwrap();
        let st = stores.get_mut(&h).context("locked")?;
        let (code, _) =
            RT.block_on(sync::pair(st, &name.to_string(), &pw, false))?;
        Ok(e.new_string(format!("{code}\n{pw}"))?)
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
        let hand = RT.block_on(sync::join(
            dir,
            &name,
            &code.to_string(),
            &pw.to_string(),
        ))?;
        *PENDING.lock().unwrap() = Some((name, hand));
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
