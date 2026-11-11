use anyhow::{Context, Result, bail, ensure};
use data_encoding::HEXLOWER;
use pasa::{Secret, Store, challenge, field, home, rand};
use std::io::{IsTerminal, Read, Write};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

#[cfg(feature = "gui")]
mod gui;
#[cfg(feature = "tui")]
mod tui;
#[cfg(any(feature = "tui", feature = "gui"))]
mod view;

const USAGE: &str = "\
pasa [ls]                    names
pasa tui | gui               browse, copy, edit: one unlock
pasa [show] NAME [FIELD]     entry, or a field: pass, user, otp, ...
pasa cp NAME [FIELD]         to the clipboard for 45 s
pasa set NAME                from stdin (a terminal: the password)
pasa edit NAME               in $EDITOR
pasa gen NAME [N] [-n] [-c]  new password of N characters (-n: no symbols, -c: copy)
pasa gen NAME [N] -w [-d] [-s CHARS] [-l]
                             ... of N speakable words (-d: dash-ed, -s: one of
                             CHARS between them, -l: some letters as 1337)
pasa attach NAME FILE        keep a file with an entry
pasa files NAME [FILE]       those files, or one, to stdout
pasa health [--pwned]        weak, reused and expired passwords; --pwned: breached ones,
                             from the list $PASA_PWNED names, else asking
                             haveibeenpwned.com by 5 hex digits of each SHA-1
pasa stats                   the store in numbers
pasa rm NAME | mv OLD NEW
pasa log NAME                every version
pasa load < x.tar | dump     tar in or out: path = name
pasa init [-y] | passwd [-y|-n]   -y: and a YubiKey (per device)
pasa ctap | ctap off         let the security key plugged in open the store here beside
                             the password, by CTAP2 (FIDO2 without the network: only
                             this machine and the key, over USB); again for a spare, at
                             any time. off: none does. Needs libfido2's tools.
pasa key [-s]                set up a new YubiKey (its slot 2 must be empty); -s: and a
                             spare with the same secret, now or never: have both at hand
pasa quick [-n] | quick off  open here by a YubiKey tap and a PIN (-n: no PIN); the
                             password still opens it alone, so make it long
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

/// A new YubiKey made ready: `secret` (20 bytes) becomes its slot 2's
/// HMAC-SHA1 secret. Only if the key says that slot is empty: never over
/// what one holds. A spare is given the same secret, while it is at hand.
fn key_setup(secret: &[u8]) -> Result<()> {
    let info = Command::new("ykman").args(["otp", "info"]).output();
    let info = info.context("ykman (YubiKey Manager) is needed for this")?;
    ensure!(
        String::from_utf8_lossy(&info.stdout).contains("Slot 2: empty"),
        "slot 2 of this YubiKey is in use, or no key is plugged in: nothing \
         was written"
    );
    // The secret goes in where ykman asks for it, not as an argument
    // any process can read.
    let mut c = Command::new("ykman")
        .args(["otp", "chalresp", "--force", "2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let hex = Zeroizing::new(HEXLOWER.encode(secret) + "\n");
    c.stdin.take().context("ykman")?.write_all(hex.as_bytes())?;
    let o = c.wait_with_output()?;
    ensure!(
        o.status.success(),
        "ykman: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    Ok(())
}

/// One of libfido2's tools (fido2-token, fido2-cred, fido2-assert) on
/// `input`, its lines out. CTAP2 goes between this computer and the key
/// alone: no server, no network. `pin`: given where the tool asks for
/// it (a window has no terminal for it to ask on); `None`: it asks on
/// the terminal itself.
fn fido_tool(
    tool: &str,
    flags: &[&str],
    dev: &str,
    input: &str,
    pin: Option<&[u8]>,
) -> Result<Vec<String>> {
    // The input holds nothing secret: random bytes, a name, the
    // credential and the salt the `ctap` file has in the clear.
    let at = home().join(format!(".ctap-{}", HEXLOWER.encode(&rand::<4>())));
    pasa::write(&at, input.as_bytes())?;
    // Away from the terminal, the tool reads the PIN where we write it.
    let detach =
        pin.is_some() && Command::new("setsid").arg("-V").output().is_ok();
    let mut c = Command::new(if detach { "setsid" } else { tool });
    c.args(detach.then_some(["-w", tool]).into_iter().flatten());
    c.args(flags).arg("-i").arg(&at).arg(dev);
    c.stdout(Stdio::piped()).stderr(Stdio::piped());
    c.stdin(if pin.is_some() { Stdio::piped() } else { Stdio::inherit() });
    let run = c.spawn().and_then(|mut c| {
        if let (Some(pin), Some(mut i)) = (pin, c.stdin.take()) {
            i.write_all(&[pin, b"\n"].concat())?;
        }
        c.wait_with_output()
    });
    let _ = std::fs::remove_file(&at);
    let o = run.with_context(|| {
        format!("{tool} (libfido2's tools) is needed for security keys")
    })?;
    let said = String::from_utf8_lossy(&o.stderr);
    ensure!(o.status.success(), "{}", said.trim());
    Ok(String::from_utf8(o.stdout)?.lines().map(Into::into).collect())
}

/// The security key plugged in (the first, of several), and whether it
/// has a PIN.
fn fido_key() -> Result<(String, bool)> {
    let l = Command::new("fido2-token").arg("-L").output();
    let l = l.context(
        "fido2-token (libfido2's tools) is needed for security keys",
    )?;
    let l = String::from_utf8_lossy(&l.stdout).into_owned();
    let dev = l.lines().next().and_then(|l| l.split_once(": "));
    let dev = dev.context("no security key is plugged in")?.0.to_string();
    let i = Command::new("fido2-token").args(["-I", &dev]).output()?;
    let i = String::from_utf8_lossy(&i.stdout).into_owned();
    let options = i.lines().find(|l| l.starts_with("options:"));
    let pin =
        options.is_some_and(|o| o.split([' ', ',']).any(|w| w == "clientPin"));
    Ok((dev, pin))
}

const B64: data_encoding::Encoding = data_encoding::BASE64;

/// The key's secret for credential `cred` and `salt` (hmac-secret): with
/// its PIN if the credential was made with one, since the secret differs.
fn fido_secret(
    dev: &str,
    cred: &[u8],
    salt: &[u8],
    pin: bool,
    typed: Option<&[u8]>,
) -> Result<Secret> {
    let input = format!(
        "{}\npasa\n{}\n{}\n",
        B64.encode(&rand::<32>()),
        B64.encode(cred),
        B64.encode(salt)
    );
    let args: &[&str] =
        if pin { &["-G", "-h", "-t", "pin=true"] } else { &["-G", "-h"] };
    eprintln!("Touch your security key");
    let out =
        fido_tool("fido2-assert", args, dev, &input, typed.filter(|_| pin))?;
    let secret = out.get(4).context("the key gave no secret")?;
    let secret = Zeroizing::new(B64.decode(secret.as_bytes())?);
    ensure!(secret.len() == 32, "the key gave no secret");
    Ok(secret)
}

/// Whether the key holds `cred`, asked without a touch.
fn fido_holds(dev: &str, cred: &[u8]) -> bool {
    let input =
        format!("{}\npasa\n{}\n", B64.encode(&rand::<32>()), B64.encode(cred));
    fido_tool("fido2-assert", &["-G", "-t", "up=false"], dev, &input, None)
        .is_ok()
}

/// Let the security key plugged in open the store on this device: a new
/// credential on it (not one of those a key has room for only a few
/// of), and the key the password opens sealed to its secret. `typed`:
/// its PIN, from a window.
pub(crate) fn fido_add(s: &Store, typed: Option<&[u8]>) -> Result<()> {
    let (dev, pin) = fido_key()?;
    let input = format!(
        "{}\npasa\npasa\n{}\n",
        B64.encode(&rand::<32>()),
        B64.encode(&rand::<16>())
    );
    eprintln!("Touch your security key");
    let out = fido_tool(
        "fido2-cred",
        &["-M", "-h"],
        &dev,
        &input,
        typed.filter(|_| pin),
    )?;
    let cred = out.get(4).context("the key made no credential")?;
    let cred = B64.decode(cred.as_bytes())?;
    let salt = s.fido_salt();
    s.fido_add(&salt, &cred, pin, &fido_secret(&dev, &cred, &salt, pin, typed)?)
}

/// Open by the security key plugged in, if it is one of this store's.
pub(crate) fn unlock_fido(typed: Option<&[u8]>) -> Result<Store> {
    let f = pasa::fido(&home()).context("no security key opens this store")?;
    let (dev, _) = fido_key()?;
    let one = f.keys.len() == 1;
    let key = f.keys.iter().find(|k| one || fido_holds(&dev, &k.0));
    let (cred, pin) =
        key.context("this security key is not one of this store's")?;
    let secret = fido_secret(&dev, cred, &f.salt, *pin, typed)?;
    adopted(Store::open_fido(&home(), cred, &secret)?)
}

/// A new password and, with `yk`, a challenge and the YubiKey's response.
fn factors(yk: bool) -> Result<(Secret, [u8; 32], Option<Secret>)> {
    let (pw, c) = (new_password()?, rand::<32>());
    Ok((pw, c, if yk { Some(yubikey(&c)?) } else { None }))
}

/// With quick unlock on: the YubiKey and the PIN; else, or if that
/// fails or no PIN is typed, the password.
fn open() -> Result<Store> {
    // A security key of this store's, plugged in: it opens it.
    if pasa::fido(&home()).is_some() && fido_key().is_ok() {
        match unlock_fido(None) {
            Ok(s) => return Ok(s),
            Err(e) => eprintln!("{e:#}"),
        }
    }
    if let Some((c, pin)) = pasa::quick(&home()) {
        let typed = match pin {
            true => ask("PIN (Enter: the password instead): ")?,
            false => Default::default(),
        };
        if !pin || !typed.is_empty() {
            match unlock_quick(&c, &typed) {
                Ok(s) => return Ok(s),
                Err(e) => eprintln!("{e:#}"),
            }
        }
    }
    unlock(&ask("Password: ")?)
}

fn unlock(pw: &[u8]) -> Result<Store> {
    let k = std::fs::read(home().join("key")).context("no store: pasa init")?;
    let yk = challenge(&k).map(yubikey).transpose()?;
    adopted(Store::open(&home(), pw, yk.as_deref().map(|v| &v[..]))?)
}

/// By the YubiKey's answer to `c` and the PIN ([`Store::quick_on`]).
fn unlock_quick(c: &[u8], pin: &[u8]) -> Result<Store> {
    adopted(Store::open_quick(&home(), pin, &yubikey(c)?)?)
}

/// Turn quick unlock on for the open store, with `pin` (empty: none).
fn quick_on(s: &Store, pin: &[u8]) -> Result<()> {
    let c = rand::<32>();
    s.quick_on(pin, &c, &yubikey(&c)?)
}

#[allow(unused_mut)]
fn adopted(mut s: Store) -> Result<Store> {
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
    let mut c = Command::new(cmd[0]);
    c.args(&cmd[1..]).stdin(Stdio::piped()).stderr(Stdio::null());
    let mut c = c.spawn()?;
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

/// `pw` as the new password of `n`, its other lines kept.
fn generate(s: &Store, n: &str, pw: String) -> Result<String> {
    let old = s.get(n).unwrap_or_default();
    let rest = text(&old)?.split_once('\n').map_or("", |r| r.1);
    s.put(n, format!("{pw}\n{rest}").as_bytes())?;
    Ok(pw)
}

/// How often breaches hold `pw`. With `$PASA_PWNED` a local copy of
/// haveibeenpwned's list (ordered by hash) answers and nothing leaves;
/// else the site is asked: only 5 hex digits of the password's SHA-1
/// leave, with curl, and the answer is padded.
fn pwned(pw: &str) -> Result<u64> {
    if let Some(list) = std::env::var_os("PASA_PWNED") {
        return pasa::pwned_file(std::path::Path::new(&list), pw);
    }
    let (sent, kept) = pasa::pwned_key(pw);
    let url = format!("https://api.pwnedpasswords.com/range/{sent}");
    let o = Command::new("curl")
        .args(["-sf", "--max-time", "15", "-H", "Add-Padding: true", &url])
        .output()
        .context("curl")?;
    ensure!(o.status.success(), "haveibeenpwned.com did not answer");
    Ok(pasa::pwned_count(&kept, &String::from_utf8_lossy(&o.stdout)))
}

/// `git` in `v/`, where the user made that a repository: its output.
fn git(a: &[&str]) -> Option<Vec<u8>> {
    let v = home().join("v");
    let mut c = Command::new("git");
    c.arg("-C").arg(&v).args(a).env("GIT_TERMINAL_PROMPT", "0");
    let o = v.join(".git").exists().then(|| c.stderr(Stdio::null()).output());
    o?.ok().filter(|o| o.status.success()).map(|o| o.stdout)
}

/// Commit what `v/` gained, and push if that has somewhere to go. A file
/// gone from `v/` is never committed as gone: `ls` says so instead.
fn record() {
    let me =
        ["user.name=pasa", "user.email=pasa@localhost", "commit.gpgsign=false"];
    let me = me.iter().flat_map(|c| ["-c", c]);
    git(&["add", "--ignore-removal", "."]);
    if git(&me.chain(["commit", "-qm", "."]).collect::<Vec<_>>()).is_some() {
        git(&["push", "-q"]);
    }
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
            match git(&["ls-files", "-d"])
                .map_or(0, |d| d.split(|b| *b == b'\n').count() - 1)
            {
                0 => {}
                n => eprintln!(
                    "{n} versions gone from v/: git -C {} checkout . brings them back",
                    home().join("v").display()
                ),
            }
            return Ok(());
        }
        ["help" | "-h" | "--help"] => {
            println!("{USAGE}");
            return Ok(());
        }
        #[cfg(feature = "tui")]
        ["tui"] => return tui::run(open()?),
        #[cfg(feature = "gui")]
        ["gui"] => return gui::run(),
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
        ["ctap", "off"] => return pasa::fido_off(&home(), None),
        ["ctap", ..] => return fido_add(&unlock(&ask("Password: ")?)?, None),
        // A new key, and with -s a spare: the same secret, held only here.
        ["key", ..] => {
            let secret = Zeroizing::new(pasa::rand::<20>());
            key_setup(&secret[..])?;
            eprintln!("This YubiKey is set up.");
            if flag("-s") {
                eprintln!("Now plug in the spare instead, and press Enter.");
                std::io::stdin().read_line(&mut String::new())?;
                key_setup(&secret[..])?;
                eprintln!(
                    "The spare is set up: either key does for the other."
                );
            }
            return Ok(());
        }
        ["quick", "off"] => {
            return Ok(std::fs::remove_file(home().join("quick"))?);
        }
        ["quick", ..] => {
            let s = unlock(&ask("Password: ")?)?;
            let mut pin = Secret::default();
            if !flag("-n") {
                pin = ask("PIN: ")?;
                ensure!(*pin == *ask("Again: ")?, "the PINs differ");
            }
            return quick_on(&s, &pin);
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
            let len = a.get(2).and_then(|l| l.parse().ok());
            let pw = match flag("-w") {
                true => {
                    let at = a.iter().position(|x| *x == "-s");
                    let seps = at.and_then(|i| a.get(i + 1)).copied();
                    let seps =
                        seps.unwrap_or(if flag("-d") { "-" } else { "" });
                    ensure!(seps.is_ascii(), "-s: ASCII characters");
                    pasa::speakable(len.unwrap_or(4), seps, flag("-l"))
                }
                false => pasa::generate(len.unwrap_or(24), !flag("-n")),
            };
            let pw = generate(&open()?, n, pw)?;
            match flag("-c") {
                true => clip(&pw)?,
                false => println!("{pw}"),
            }
        }
        ["rm", n] => {
            let s = open()?;
            s.get(n)?;
            s.remove(n)?
        }
        ["mv", from, to] => open()?.rename(from, to)?,
        ["health", ..] => {
            let s = open()?;
            let h = s.health()?;
            h.weak
                .iter()
                .for_each(|(n, b)| println!("weak    {n}: about {b} bits"));
            h.reused.iter().for_each(|g| println!("reused  {}", g.join(", ")));
            h.expired.iter().for_each(|n| println!("expired {n}"));
            // Passwords alone: not what is attached, nor an empty one.
            let asked = |n: &String| {
                flag("--pwned") && !n.split('/').any(|c| c.starts_with('.'))
            };
            for n in s.entries()?.into_keys().filter(asked) {
                let pw =
                    pasa::Form::parse(text(&s.get(&n)?).unwrap_or("")).pass;
                if pw.is_empty() {
                    continue;
                }
                match pwned(&pw)? {
                    0 => {}
                    times => println!("pwned   {n}: in breaches {times} times"),
                }
            }
            return Ok(());
        }
        ["stats"] => {
            for (what, n) in open()?.stats()? {
                println!("{what:<30}{n}");
            }
            return Ok(());
        }
        ["attach", n, file] => {
            let s = open()?;
            s.get(n)?;
            let f =
                std::path::Path::new(file).file_name().context("no file")?;
            let to = format!("{n}{}{}", pasa::FILES, f.to_string_lossy());
            s.put(&to, &Zeroizing::new(std::fs::read(file)?))?
        }
        ["files", n] => {
            open()?.files(n)?.iter().for_each(|f| println!("{f}"));
            return Ok(());
        }
        ["files", n, f] => {
            let b = open()?.get(&format!("{n}{}{f}", pasa::FILES))?;
            return Ok(std::io::stdout().write_all(&b)?);
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
            let mut all = vec![];
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
                    all.push((e.header().mtime().unwrap_or(0), p, b));
                }
            }
            // A dated file is a version as it was then: oldest first, so
            // each follows the one before it.
            all.sort_by_key(|e| e.0);
            for (at, p, b) in all {
                match at {
                    0 => s.put(&p, &b)?,
                    at => s.put_at(&p, &b, at * 1000)?,
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
    record();
    #[cfg(feature = "sync")]
    if home().join("peers").exists() {
        sync(&["sync", "--news"])?;
    }
    Ok(())
}

/// `pasa sync` beside a view, unseen: what it brings shows as `v/` changes.
#[cfg(any(feature = "tui", feature = "gui"))]
fn aside(news: bool) {
    if cfg!(feature = "sync") && home().join("peers").exists() {
        let c = std::env::current_exe().map(Command::new);
        let _ = c.map(|mut c| {
            c.arg("sync").args(news.then_some("--news")).stdin(Stdio::null());
            c.stdout(Stdio::null()).stderr(Stdio::null()).spawn()
        });
    }
}

#[cfg(feature = "sync")]
fn report_all(r: Vec<(String, Result<usize>)>) {
    r.into_iter().for_each(|(w, r)| report(&w, r))
}

#[cfg(feature = "sync")]
fn report(who: &str, r: Result<usize>) {
    if matches!(r, Ok(1..)) {
        record();
    }
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
            // The pairing's key is here alone: a slip is asked again.
            let mut s = open();
            for _ in 0..2 {
                if let Err(e) = &s {
                    eprintln!("{e:#}");
                    s = open();
                }
            }
            let mut s = s.with_context(|| {
                format!("not sealed: pasa forget {name}, then pair again")
            })?;
            sync::keep_hand(&mut s, name, &hand)?;
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
