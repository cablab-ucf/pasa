use anyhow::{Context, Result, bail, ensure};
use data_encoding::HEXLOWER;
use pasa::{Secret, Store, challenge, field, home, rand};
use std::io::{IsTerminal, Read, Write};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

const USAGE: &str = "\
pasa [ls]                    names
pasa [show] NAME [FIELD]     entry, or a field: pass, user, otp, ...
pasa cp NAME [FIELD]         to the clipboard for 45 s
pasa set NAME                from stdin (a terminal: the password)
pasa edit NAME               in $EDITOR
pasa gen NAME [LEN] [-n] [-c] new password (-n: no symbols, -c: copy)
pasa rm NAME | mv OLD NEW
pasa log NAME                every version
pasa load < x.tar | dump     tar in or out: path = name
pasa init [-y] | passwd [-y|-n]   -y: and a YubiKey (per device)
pasa keys                    the store keys: age -d takes them as passphrases
pasa pair NAME [--qr]        let a device join, called NAME here
pasa join NAME CODE          join the device NAME showing CODE
pasa sync | serve | listen | peers | forget NAME | revoke NAME";

fn ask(p: &str) -> Result<Secret> {
    Ok(Zeroizing::new(rpassword::prompt_password(p)?.into_bytes()))
}

fn new_password() -> Result<Secret> {
    let p = ask("New password: ")?;
    ensure!(*p == *ask("Again: ")?, "passwords differ");
    Ok(p)
}

/// The YubiKey's HMAC-SHA1 (slot 2) of `c`.
fn yubikey(c: &[u8]) -> Result<Secret> {
    eprintln!("Touch your YubiKey");
    let o = Command::new("ykman")
        .args(["otp", "calculate", "2", &HEXLOWER.encode(c)])
        .output()?;
    ensure!(
        o.status.success(),
        "ykman: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    Ok(Zeroizing::new(HEXLOWER.decode(o.stdout.trim_ascii())?))
}

/// A new password and, with `yk`, a challenge and the YubiKey's response.
fn factors(yk: bool) -> Result<(Secret, [u8; 32], Option<Secret>)> {
    let (pw, c) = (new_password()?, rand::<32>());
    Ok((pw, c, if yk { Some(yubikey(&c)?) } else { None }))
}

fn open() -> Result<Store> {
    let k = std::fs::read(home().join("key")).context("no store: pasa init")?;
    let pw = ask("Password: ")?;
    let yk = challenge(&k).map(yubikey).transpose()?;
    #[allow(unused_mut)]
    let mut s = Store::open(&home(), &pw, yk.as_deref().map(|v| &v[..]))?;
    #[cfg(feature = "sync")]
    pasa::sync::adopt(&mut s)?;
    Ok(s)
}

fn text(b: &[u8]) -> Result<&str> {
    std::str::from_utf8(b).context("not text")
}

/// Clipboard tools: (copy, paste).
const CLIPS: [(&[&str], &[&str]); 3] = [
    (&["wl-copy"], &["wl-paste", "-n"]),
    (&["xclip", "-sel", "clip"], &["xclip", "-o", "-sel", "clip"]),
    (&["pbcopy"], &["pbpaste"]),
];

fn piped(cmd: &[&str], s: &[u8]) -> Result<()> {
    let mut c =
        Command::new(cmd[0]).args(&cmd[1..]).stdin(Stdio::piped()).spawn()?;
    c.stdin.take().context("stdin")?.write_all(s)?;
    ensure!(c.wait()?.success(), "{} failed", cmd[0]);
    Ok(())
}

/// Copy `s`; a detached child clears it in 45 s if it is still there.
fn clip(s: &str) -> Result<()> {
    for (i, (copy, _)) in CLIPS.iter().enumerate() {
        if piped(copy, s.as_bytes()).is_err() {
            continue;
        }
        let mut c = Command::new(std::env::current_exe()?);
        c.args(["--clear-clipboard", &i.to_string()]).stdin(Stdio::piped());
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut c, 0);
        let mut c = c.stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
        c.stdin.take().context("stdin")?.write_all(s.as_bytes())?;
        return Ok(());
    }
    bail!("no wl-copy, xclip or pbcopy")
}

fn clear_clipboard(i: usize) -> Result<()> {
    let (copy, paste) = CLIPS[i];
    let mut s = Zeroizing::new(vec![]);
    std::io::stdin().read_to_end(&mut s)?;
    std::thread::sleep(std::time::Duration::from_secs(45));
    let now = Zeroizing::new(
        Command::new(paste[0]).args(&paste[1..]).output()?.stdout,
    );
    if *now == *s {
        piped(copy, b"")?;
    }
    Ok(())
}

fn edit(old: &[u8]) -> Result<Secret> {
    let shm = std::path::Path::new("/dev/shm");
    let d = if shm.is_dir() { shm.into() } else { std::env::temp_dir() };
    let f = d.join(format!("pasa-{}", HEXLOWER.encode(&rand::<8>())));
    pasa::write(&f, old)?;
    let ed = std::env::var("EDITOR").unwrap_or("vi".into());
    let ok = Command::new("sh")
        .args(["-c", &format!("{ed} \"$1\""), "-"])
        .arg(&f)
        .status();
    let new = std::fs::read(&f).map(Zeroizing::new);
    std::fs::remove_file(&f)?;
    ensure!(ok?.success(), "{ed} failed");
    Ok(new?)
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = a.iter().map(String::as_str).collect();
    let flag = |f| a.contains(&f);
    match a[..] {
        [] | ["ls"] => {
            let s = open()?;
            let e = s.entries()?;
            e.keys()
                .filter(|n| !n.split('/').any(|c| c.starts_with('.')))
                .for_each(|n| println!("{n}"));
            for n in s.conflicts()? {
                eprintln!(
                    "{n}: changed on two devices apart; the other is in pasa log {n}"
                );
            }
            match s.unreadable.load(std::sync::atomic::Ordering::Relaxed) {
                0 => {}
                n => eprintln!(
                    "{n} versions no store key opens: damaged, or another store's"
                ),
            }
            return Ok(());
        }
        ["--clear-clipboard", i] => return clear_clipboard(i.parse()?),
        ["keys"] => {
            print!("{}", *open()?.passphrases());
            return Ok(());
        }
        ["init", ..] => {
            let (pw, c, r) = factors(flag("-y"))?;
            Store::create(&home(), &pw, r.as_ref().map(|r| (&c[..], &r[..])))?;
        }
        ["passwd", ..] => {
            let mut s = open()?;
            let had = challenge(&std::fs::read(s.dir.join("key"))?).is_some();
            let (pw, c, r) = factors(flag("-y") || had && !flag("-n"))?;
            s.lock(&pw, r.as_ref().map(|r| (&c[..], &r[..])))?
        }
        ["cp", n, ..] => {
            let f = a.get(2).unwrap_or(&"pass");
            return clip(
                &field(text(&open()?.get(n)?)?, f).context("no such field")?,
            );
        }
        ["set", n] => {
            let mut b = Zeroizing::new(vec![]);
            match std::io::stdin().is_terminal() {
                true => b = ask("Password: ")?,
                false => drop(std::io::stdin().read_to_end(&mut b)?),
            }
            open()?.put(n, &b)?
        }
        ["edit", n] => {
            let s = open()?;
            let old = s.get(n).unwrap_or_default();
            let new = edit(&old)?;
            if *new == *old {
                return Ok(());
            }
            s.put(n, &new)?
        }
        ["gen", n, ..] => {
            let len = a.get(2).and_then(|l| l.parse().ok()).unwrap_or(24);
            let pw = pasa::generate(len, !flag("-n"));
            let s = open()?;
            let old = s.get(n).unwrap_or_default();
            let rest = text(&old)?.split_once('\n').map_or("", |r| r.1);
            s.put(n, format!("{pw}\n{rest}").as_bytes())?;
            match flag("-c") {
                true => clip(&pw)?,
                false => println!("{pw}"),
            }
        }
        ["rm", n] => {
            let s = open()?;
            s.get(n)?;
            s.put(n, b"")?
        }
        ["mv", from, to] => {
            let s = open()?;
            ensure!(s.get(to).is_err(), "{to} exists");
            s.put(to, &s.get(from)?)?;
            s.put(from, b"")?
        }
        ["log", n] => {
            let s = open()?;
            for v in s.versions()?.into_iter().filter(|v| v.name == n) {
                let t = std::time::UNIX_EPOCH
                    + std::time::Duration::from_millis(v.ms);
                let b = s.body(&v)?;
                let t = humantime::format_rfc3339_seconds(t);
                println!("── {t}\n{}", String::from_utf8_lossy(&b));
            }
            return Ok(());
        }
        ["load"] => {
            let s = open()?;
            for e in tar::Archive::new(std::io::stdin()).entries()? {
                let mut e = e?;
                if e.header().entry_type().is_file() {
                    let p = e
                        .path()?
                        .to_string_lossy()
                        .trim_start_matches("./")
                        .to_string();
                    let mut b = Zeroizing::new(vec![]);
                    e.read_to_end(&mut b)?;
                    s.put(&p, &b)?;
                }
            }
        }
        ["dump"] => {
            let mut t = tar::Builder::new(std::io::stdout().lock());
            let s = open()?;
            for (n, v) in s.entries()? {
                if let Err(e) = pasa::path_safe(&n) {
                    eprintln!("skipped: {e}");
                    continue;
                }
                let b = s.body(&v)?;
                let mut h = tar::Header::new_gnu();
                h.set_size(b.len() as u64);
                h.set_mode(0o600);
                t.append_data(&mut h, n, &b[..])?;
            }
            return Ok(t.finish()?);
        }
        #[cfg(feature = "sync")]
        [
            "pair" | "join" | "sync" | "serve" | "listen" | "peers" | "forget"
            | "revoke",
            ..,
        ] => return sync(&a),
        ["show", n] | [n] => {
            print!("{}", String::from_utf8_lossy(&open()?.get(n)?));
            return Ok(());
        }
        ["show", n, f] | [n, f] => {
            println!(
                "{}",
                field(text(&open()?.get(n)?)?, f).context("no such field")?
            );
            return Ok(());
        }
        _ => bail!("{USAGE}"),
    }
    #[cfg(feature = "sync")]
    if home().join("peers").exists() {
        sync(&["sync", "--news"])?;
    }
    Ok(())
}

#[cfg(feature = "sync")]
fn report_all(r: Vec<(String, Result<usize>)>) {
    r.into_iter().for_each(|(w, r)| report(&w, r))
}

#[cfg(feature = "sync")]
fn report(who: &str, r: Result<usize>) {
    match r {
        Ok(n) => eprintln!("{who}: {n} new"),
        Err(e) => eprintln!("{who}: {e:#}"),
    }
}

#[cfg(feature = "sync")]
#[tokio::main]
async fn sync(a: &[&str]) -> Result<()> {
    use pasa::sync;
    let dir = home();
    match a {
        ["pair", name, ..] => {
            let (pw, qr) = (pairir::password(), a.contains(&"--qr"));
            let mut s = open()?;
            let (code, end) = sync::pair(&mut s, name, &pw, qr).await?;
            if qr {
                println!(
                    "{}",
                    qrcode::QrCode::new(&code)?
                        .render::<qrcode::render::unicode::Dense1x2>()
                        .build()
                );
            }
            println!("{code}\npassword: {pw}\nthere: pasa join NAME {code}");
            match end {
                None => {}
                Some(end) => match end.await? {
                    pairir::End::Taken => eprintln!("{name} took it"),
                    pairir::End::Expired => {
                        eprintln!("nobody came: pair again")
                    }
                    pairir::End::Spent => bail!(
                        "the code was used by someone who did not prove it: \
                         pasa forget {name}, then pair again"
                    ),
                },
            }
        }
        ["join", name, code] => {
            let pw = String::from_utf8(ask("Pairing password: ")?.to_vec())?;
            let hand = sync::join(&dir, name, code, &pw).await?;
            eprintln!("Now the store's password, to keep the pairing sealed:");
            sync::keep_hand(&mut open()?, name, &hand)?;
            report_all(sync::sync(&dir, false).await?);
        }
        ["sync", ..] => {
            report_all(sync::sync(&dir, a.contains(&"--news")).await?)
        }
        ["serve"] => sync::serve(&dir, report).await?,
        ["listen"] => sync::listen(&dir, report).await?,
        ["peers"] => {
            sync::peers(&dir).iter().for_each(|p| println!("{}", p.name))
        }
        ["forget", name] => sync::forget(&dir, name)?,
        ["revoke", name] => {
            sync::revoke(&mut open()?, name)?;
            report_all(sync::sync(&dir, true).await?);
        }
        _ => bail!("{USAGE}"),
    }
    Ok(())
}
