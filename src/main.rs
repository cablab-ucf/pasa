#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use anyhow::{Context, Result, bail, ensure};
use data_encoding::HEXLOWER;
use pasa::{Secret, Store, challenge, field, home, rand};
use std::io::{IsTerminal, Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

use authenticator::authenticatorservice::{
    AuthenticatorService, RegisterArgs, SignArgs,
};
use authenticator::crypto::COSEAlgorithm;
use authenticator::ctap2::attestation::AuthenticatorDataFlags;
use authenticator::ctap2::server::{
    AuthenticationExtensionsClientInputs, HMACGetSecretInput,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
    PublicKeyCredentialUserEntity, RelyingParty, ResidentKeyRequirement,
    Transport, UserVerificationRequirement,
};
use authenticator::statecallback::StateCallback;
use authenticator::{Pin, StatusPinUv, StatusUpdate};
use sha2::Digest;

#[cfg(feature = "gui")]
mod gui;
#[cfg(feature = "scan")]
mod scan;
#[cfg(feature = "tui")]
mod tui;
#[cfg(any(feature = "tui", feature = "gui"))]
mod view;

const USAGE: &str = "\
pasa [ls]                    names
pasa tui | gui               browse, copy, edit: one unlock
pasa [show] NAME [FIELD]     entry, or a field: pass, user, otp, ...
pasa cp NAME [FIELD]         to the clipboard for 45 s
pasa pick [FIELD]            choose the entry with fzf, then as cp
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
                             any time. off: none does. Pairing brings them along
pasa key [-s]                set up a new YubiKey (its slot 2 must be empty); -s: and a
                             spare with the same secret, now or never: have both at hand
pasa quick [-n] | quick off  open here by a YubiKey tap and a PIN (-n: no PIN); the
                             password still opens it alone, so make it long
pasa keys                    the store keys: age -d takes them as passphrases
pasa pair NAME [--qr]        hand the key files, as they are (the hardware keys' too), to
                             a new device called NAME here: a code to type, or a QR code
                             (offline) after its password; serve until it has synced. No
                             store password asked
pasa join NAME CODE|--scan   take the code device NAME shows (a QR code: its password
                             too; --scan: by the camera, in this program), then sync. The
                             store's password opens it afterwards
pasa sync on | off           sync with the paired devices, or stay offline: off until turned
                             on (pairing does). A month apart, each device says so
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
    // ykman reaches slot 2 through the key's keyboard side, which macOS
    // opens only to apps given Input Monitoring.
    let mac = match cfg!(target_os = "macos") {
        true => {
            "\nOn a Mac that needs Input Monitoring: add the YubiKey as \
                 a security key instead (pasa ctap), which needs nothing."
        }
        false => "",
    };
    ensure!(
        o.status.success(),
        "ykman: {}{mac}",
        String::from_utf8_lossy(&o.stderr).trim()
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

const B64: data_encoding::Encoding = data_encoding::BASE64;

/// What security keys are asked under: a name on the key, not an address.
const RP: &str = "pasa";

/// What `go` asks of a security key plugged in, by CTAP2 over USB from this
/// process (Firefox's own, authenticator-rs): no tool to install, no
/// server, no network, and nothing a system guards as a keyboard (macOS
/// asks no Input Monitoring for it). `typed`: its PIN, from a window,
/// tried once; `None`: asked here if the key wants one. `wait`: ms.
fn ctap<T: Send + 'static>(
    typed: Option<&[u8]>,
    wait: u64,
    go: impl FnOnce(
        &mut AuthenticatorService,
        u64,
        Sender<StatusUpdate>,
        StateCallback<authenticator::Result<T>>,
    ) -> authenticator::Result<()>,
) -> Result<T> {
    let mut m = AuthenticatorService::new()?;
    m.add_u2f_usb_hid_platform_transports();
    let (status, said) = channel();
    let text =
        |p: &[u8]| Zeroizing::new(String::from_utf8_lossy(p).into_owned());
    let typed = typed.map(text);
    let why = Arc::new(Mutex::new(None));
    let told = why.clone();
    std::thread::spawn(move || {
        for s in said {
            let tell = |w: &'static str| {
                *told.lock().unwrap_or_else(|p| p.into_inner()) = Some(w);
            };
            let (to, wrong) = match s {
                StatusUpdate::PresenceRequired => {
                    eprintln!("Touch your security key");
                    continue;
                }
                StatusUpdate::PinUvError(StatusPinUv::PinRequired(to)) => {
                    (to, false)
                }
                StatusUpdate::PinUvError(StatusPinUv::InvalidPin(to, _)) => {
                    (to, true)
                }
                StatusUpdate::PinUvError(StatusPinUv::PinBlocked)
                | StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked) => {
                    tell(
                        "its PIN is blocked after wrong tries: use the password",
                    );
                    continue;
                }
                _ => continue,
            };
            // Unanswered, `to` goes: the key is asked nothing more.
            let pin = match &typed {
                Some(p) if !wrong && !p.is_empty() => Some(p.clone()),
                Some(_) => {
                    tell(match wrong {
                        true => "wrong PIN",
                        false => "this key has a PIN: type it, then try again",
                    });
                    None
                }
                None => {
                    let q =
                        if wrong { "Wrong PIN; again: " } else { "Its PIN: " };
                    ask(q).ok().filter(|p| !p.is_empty()).map(|p| text(&p))
                }
            };
            if let Some(p) = pin {
                let _ = to.send(Pin::new(&p));
            }
        }
    });
    let (tx, rx) = channel();
    let done = StateCallback::new(Box::new(move |r| {
        let _ = tx.send(r);
    }));
    go(&mut m, wait, status, done)?;
    let got = rx.recv()?;
    let why = *why.lock().unwrap_or_else(|p| p.into_inner());
    got.map_err(|e| {
        anyhow::anyhow!(
            "the security key: {}",
            why.map_or(e.to_string(), String::from)
        )
    })
}

/// `salt` as WebAuthn's PRF hands it to a key: SHA-256("WebAuthn PRF", 0,
/// salt). The phone's way (Yubico's kit), and this one's since.
fn prf(salt: &[u8]) -> [u8; 32] {
    let h =
        sha2::Sha256::new().chain_update(b"WebAuthn PRF\0").chain_update(salt);
    h.finalize().into()
}

/// The secrets of the security key plugged in, if it holds one of `keys`
/// (credential, whether its PIN goes with it), for `salt`: which, and its
/// secret for the salt as WebAuthn's PRF asks it, then as it is (keys
/// added on a computer before). One touch.
fn fido_secret(
    keys: &[(Vec<u8>, bool)],
    salt: &[u8],
    typed: Option<&[u8]>,
) -> Result<(Vec<u8>, [Secret; 2])> {
    let raw: [u8; 32] = salt.try_into()?;
    // With its PIN if it has one (as the phone asks), when any was
    // added so.
    let uv = match keys.iter().any(|k| k.1) {
        true => UserVerificationRequirement::Preferred,
        false => UserVerificationRequirement::Discouraged,
    };
    let got = ctap(typed, 30_000, |m, t, status, done| {
        let ask = SignArgs {
            client_data_hash: rand::<32>(),
            origin: RP.into(),
            relying_party_id: RP.into(),
            allow_list: allow(keys),
            user_verification_req: uv,
            user_presence_req: true,
            extensions: AuthenticationExtensionsClientInputs {
                hmac_get_secret: Some(HMACGetSecretInput {
                    salt1: prf(salt),
                    salt2: Some(raw),
                }),
                ..Default::default()
            },
            pin: None,
            use_ctap1_fallback: false,
        };
        m.sign(t, ask, status, done)
    })?;
    let out =
        got.extensions.hmac_get_secret.context("the key gave no secret")?;
    let two = out.output2.context("the key gave one secret of two")?;
    // CTAP 2.0 keys may leave out which, asked with one.
    let one = keys.first().filter(|_| keys.len() == 1).map(|k| k.0.clone());
    let cred = got.assertion.credentials.map(|c| c.id).or(one);
    let cred = cred.context("the key did not say which of its keys it is")?;
    Ok((
        cred,
        [Zeroizing::new(out.output1.to_vec()), Zeroizing::new(two.to_vec())],
    ))
}

fn allow(keys: &[(Vec<u8>, bool)]) -> Vec<PublicKeyCredentialDescriptor> {
    let usb = || vec![Transport::USB];
    keys.iter()
        .map(|k| PublicKeyCredentialDescriptor {
            id: k.0.clone(),
            transports: usb(),
        })
        .collect()
}

/// Whether a security key plugged in holds one of `keys`: asked without a
/// touch or a PIN, a moment's wait.
fn fido_here(keys: &[(Vec<u8>, bool)]) -> bool {
    let probe = |m: &mut AuthenticatorService, t, status, done| {
        let ask = SignArgs {
            client_data_hash: rand::<32>(),
            origin: RP.into(),
            relying_party_id: RP.into(),
            allow_list: allow(keys),
            user_verification_req: UserVerificationRequirement::Discouraged,
            user_presence_req: false,
            extensions: Default::default(),
            pin: None,
            use_ctap1_fallback: false,
        };
        m.sign(t, ask, status, done)
    };
    ctap(Some(b""), 1500, probe).is_ok()
}

/// Let the security key plugged in open the store on this device: a new
/// credential on it (not one of those a key has room for only a few
/// of), with its PIN if it has one, and the key the password opens sealed
/// to its secret. `typed`: its PIN, from a window.
pub(crate) fn fido_add(s: &Store, typed: Option<&[u8]>) -> Result<()> {
    let made = ctap(typed, 30_000, |m, t, status, done| {
        let ask = RegisterArgs {
            client_data_hash: rand::<32>(),
            relying_party: RelyingParty {
                id: RP.into(),
                name: Some(RP.into()),
            },
            origin: RP.into(),
            user: PublicKeyCredentialUserEntity {
                id: rand::<16>().to_vec(),
                name: Some(RP.into()),
                display_name: Some(RP.into()),
            },
            pub_cred_params: vec![PublicKeyCredentialParameters {
                alg: COSEAlgorithm::ES256,
            }],
            exclude_list: vec![],
            user_verification_req: UserVerificationRequirement::Preferred,
            resident_key_req: ResidentKeyRequirement::Discouraged,
            extensions: AuthenticationExtensionsClientInputs {
                hmac_create_secret: Some(true),
                ..Default::default()
            },
            pin: None,
            use_ctap1_fallback: false,
        };
        m.register(t, ask, status, done)
    })?;
    let a = made.att_obj.auth_data;
    let pin = a.flags.contains(AuthenticatorDataFlags::USER_VERIFIED);
    let cred = a.credential_data.context("the key made no credential")?;
    let cred = cred.credential_id;
    let salt = s.fido_salt();
    let (_, [secret, _]) = fido_secret(&[(cred.clone(), pin)], &salt, typed)?;
    s.fido_add(&salt, &cred, pin, &secret)
}

/// Open by the security key plugged in, if it is one of this store's:
/// added here or where the store was paired from.
pub(crate) fn unlock_fido(typed: Option<&[u8]>) -> Result<Store> {
    let f = pasa::fido(&home()).context("no security key opens this store")?;
    let (cred, secrets) = fido_secret(&f.keys, &f.salt, typed)?;
    let k = f.keys.iter().find(|k| k.0 == cred);
    let pin = k.context("this security key is not one of this store's")?.1;
    for s in &secrets {
        if let Ok(s) = Store::open_fido(&home(), &cred, s) {
            return Ok(s);
        }
    }
    // Added with its PIN and asked without (or the other way), its secret
    // is another.
    ensure!(
        pin == f.keys.iter().any(|k| k.1),
        "this key's PIN was set or removed since it was added: use the \
         password, then add the key again"
    );
    bail!("this security key does not open the store")
}

/// A new password and, with `yk`, a challenge and the YubiKey's response.
fn factors(yk: bool) -> Result<(Secret, [u8; 32], Option<Secret>)> {
    let (pw, c) = (new_password()?, rand::<32>());
    Ok((pw, c, if yk { Some(yubikey(&c)?) } else { None }))
}

/// With quick unlock on: the YubiKey and the PIN; else, or if that
/// fails or no PIN is typed, the password.
fn open() -> Result<Store> {
    // Devices apart for a month, said where a person reads.
    #[cfg(feature = "sync")]
    if std::io::stderr().is_terminal() {
        for (who, d) in pasa::sync::unseen(&home()) {
            eprintln!(
                "Not synced with {who} for {d} days: check in (pasa sync on, \
                 then pasa sync)"
            );
        }
    }
    // A security key of this store's, plugged in: it opens it.
    if pasa::fido(&home()).is_some_and(|f| fido_here(&f.keys)) {
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
    Store::open(&home(), pw, yk.as_deref().map(|v| &v[..]))
}

/// By the YubiKey's answer to `c` and the PIN ([`Store::quick_on`]).
fn unlock_quick(c: &[u8], pin: &[u8]) -> Result<Store> {
    Store::open_quick(&home(), pin, &yubikey(c)?)
}

/// Turn quick unlock on for the open store, with `pin` (empty: none).
fn quick_on(s: &Store, pin: &[u8]) -> Result<()> {
    let c = rand::<32>();
    s.quick_on(pin, &c, &yubikey(&c)?)
}

/// An entry chosen with fzf, which is given the names alone: no secret,
/// no preview. It draws on the terminal and says which.
fn pick(s: &Store) -> Result<String> {
    let names = s.entries()?.into_keys();
    let names = names.filter(|n| !n.split('/').any(|c| c.starts_with('.')));
    let names: String = names.map(|n| n + "\n").collect();
    let mut c = Command::new("fzf")
        .args(["--no-multi", "--prompt", "pasa> "])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("fzf is needed for pick (or pasa tui)")?;
    c.stdin.take().context("fzf")?.write_all(names.as_bytes())?;
    let o = c.wait_with_output()?;
    let n = String::from_utf8(o.stdout)?.trim_end_matches('\n').to_string();
    ensure!(o.status.success() && !n.is_empty(), "nothing chosen");
    Ok(n)
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
        #[cfg(feature = "sync")]
        ["--net", ..] => return net_side(&a[1..]),
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
        ["pick", ..] => {
            let (s, f) = (open()?, a.get(1).unwrap_or(&"pass"));
            let n = pick(&s)?;
            return clip(
                &field(text(&s.get(&n)?)?, f).context("no such field")?,
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
                // When it was written, as `load` reads it back.
                h.set_mtime(v.ms / 1000);
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
    if pasa::sync::net(&home()).join("peers").exists()
        && pasa::sync::on(&home())
    {
        sync(&["sync", "--news"])?;
    }
    Ok(())
}

/// `pasa sync` beside a view, unseen: what it brings shows as `v/` changes.
#[cfg(any(feature = "tui", feature = "gui"))]
fn aside(news: bool) {
    #[cfg(feature = "sync")]
    if pasa::sync::net(&home()).join("peers").exists()
        && pasa::sync::on(&home())
    {
        let c = std::env::current_exe().map(Command::new);
        let _ = c.map(|mut c| {
            c.arg("sync").args(news.then_some("--news")).stdin(Stdio::null());
            c.stdout(Stdio::null()).stderr(Stdio::null()).spawn()
        });
    }
    let _ = news;
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

/// The network side ([`net_side`]) as a child that sees `v/` and `net/`
/// alone; it ends when its stdin closes (this process ends, or drops it).
#[cfg(feature = "sync")]
fn net(args: &[&str]) -> Result<std::process::Child> {
    let dir = home();
    pasa::sync::net(&dir); // moved beside v/ here, where the child may not
    let a: Vec<&str> = ["--net"].iter().chain(args).copied().collect();
    let mut c = pasa::confine::command(&dir, &std::env::current_exe()?, &a);
    c.stdin(Stdio::piped()).stdout(Stdio::piped());
    Ok(c.spawn()?)
}

/// A network child's lines, as they come.
#[cfg(feature = "sync")]
fn lines(c: &mut std::process::Child) -> impl Iterator<Item = String> + use<> {
    use std::io::BufRead;
    let out = c.stdout.take().map(std::io::BufReader::new);
    out.into_iter().flat_map(|o| o.lines().map_while(Result::ok))
}

/// What a sync said of each peer, a line each: `who \t n` or `who \t !why`.
#[cfg(feature = "sync")]
fn results(
    c: &mut std::process::Child,
) -> impl Iterator<Item = (String, Result<usize>)> + use<> {
    lines(c).filter_map(|l| {
        let (w, r) = l.split_once('\t')?;
        let r = match r.strip_prefix('!') {
            Some(e) => Err(anyhow::anyhow!(e.to_string())),
            None => r.parse().map_err(Into::into),
        };
        Some((w.to_string(), r))
    })
}

/// Run a network child to its end, saying what it brought.
#[cfg(feature = "sync")]
fn net_run(args: &[&str]) -> Result<()> {
    let mut c = net(args)?;
    results(&mut c).for_each(|(w, r)| report(&w, r));
    ensure!(c.wait()?.success(), "the network side failed");
    Ok(())
}

/// Serve until `name` has synced once: it dials here.
#[cfg(feature = "sync")]
fn serve_until(name: &str) -> Result<()> {
    eprintln!("waiting for {name} to sync (Ctrl-C: later, by pasa serve)");
    let mut c = net(&["serve"])?;
    for (w, r) in results(&mut c) {
        let done = w == name && r.is_ok();
        report(&w, r);
        if done {
            return Ok(());
        }
    }
    bail!("not served here: {name} syncs with whatever serves this store")
}

/// The network side, first thing confined to `v/` and `net/`: a sync,
/// serving, listening, or a short code's half of a pairing (what it
/// carries comes on stdin, sealed). It ends when its parent does.
#[cfg(feature = "sync")]
fn net_side(a: &[&str]) -> Result<()> {
    let dir = home();
    if !pasa::confine::confine(&dir)? {
        eprintln!("pasa: the network side is not confined: no Landlock here");
    }
    let mut got = String::new();
    if a == ["give"] {
        std::io::stdin().read_line(&mut got)?;
    }
    std::thread::spawn(|| {
        let _ = std::io::copy(&mut std::io::stdin(), &mut std::io::sink());
        std::process::exit(0)
    });
    net_go(&dir, a, got.trim())
}

/// `go`, while sync is on here: nothing goes online while it is off, and
/// within seconds of the switch it starts or stops. A service running
/// `pasa serve` follows the switch, as the window does.
#[cfg(feature = "sync")]
async fn while_on<F: std::future::Future<Output = Result<()>>>(
    dir: &std::path::Path,
    go: impl Fn() -> F,
) -> Result<()> {
    use pasa::sync::on;
    let tick = || tokio::time::sleep(std::time::Duration::from_secs(2));
    loop {
        if !on(dir) {
            eprintln!("Offline: nothing goes online until pasa sync on");
            while !on(dir) {
                tick().await
            }
        }
        tokio::select! {
            r = go() => return r,
            _ = async { while on(dir) { tick().await } } => {}
        }
    }
}

#[cfg(feature = "sync")]
#[tokio::main]
async fn net_go(dir: &std::path::Path, a: &[&str], got: &str) -> Result<()> {
    use pasa::sync;
    fn said(who: &str, r: Result<usize>) {
        match r {
            Ok(n) => println!("{who}\t{n}"),
            Err(e) => {
                println!("{who}\t!{}", format!("{e:#}").replace('\n', " "))
            }
        }
    }
    match a {
        ["sync", ..] => {
            let r = sync::sync(dir, a.contains(&"--news")).await?;
            r.into_iter().for_each(|(w, r)| said(&w, r))
        }
        ["serve"] => while_on(dir, || sync::serve(dir, said)).await?,
        ["listen"] => while_on(dir, || sync::listen(dir, said)).await?,
        ["give"] => {
            let (code, end) = sync::give(&B64.decode(got.as_bytes())?).await?;
            println!("{code}");
            println!(
                "{}",
                match end.await? {
                    pairir::End::Taken => "taken",
                    pairir::End::Expired => "expired",
                    pairir::End::Spent => "spent",
                }
            );
        }
        ["take", code] => println!("{}", B64.encode(&sync::fetch(code).await?)),
        _ => bail!("{USAGE}"),
    }
    Ok(())
}

/// A QR code's password: typed, or made here; said before the code shows,
/// never beside it.
#[cfg(feature = "sync")]
fn qr_password(name: &str) -> Result<Secret> {
    let pw = ask("QR code password (Enter: make one): ")?;
    if !pw.is_empty() {
        return Ok(pw);
    }
    let pw = pasa::speakable(2, "-", false);
    eprint!(
        "Its password: {pw}\nType it on {name} after scanning. Enter: the QR code "
    );
    std::io::stdin().read_line(&mut String::new())?;
    Ok(Zeroizing::new(pw.into_bytes()))
}

#[cfg(feature = "sync")]
#[tokio::main]
async fn sync(a: &[&str]) -> Result<()> {
    use pasa::sync;
    let dir = home();
    match a {
        ["pair", name, ..] => {
            // The key file as it is, never opened: no password here.
            let got = sync::offer(&dir, name)?;
            match a.contains(&"--qr") {
                true => {
                    let pw = qr_password(name)?;
                    let qr = sync::qr(&got, text(&pw)?).await?;
                    // The password off the screen, scrollback too.
                    if std::io::stderr().is_terminal() {
                        eprint!("\x1b[H\x1b[2J\x1b[3J");
                    }
                    let c = qrcode::QrCode::new(&qr)?;
                    println!(
                        "{}",
                        c.render::<qrcode::render::unicode::Dense1x2>().build()
                    );
                    println!("there: scan it, or pasa join NAME {qr}");
                }
                false => {
                    let mut c = net(&["give"])?;
                    let mut i = c.stdin.take().context("stdin")?;
                    writeln!(i, "{}", B64.encode(&got))?;
                    let mut l = lines(&mut c);
                    let code = l.next().context("no code: no relay?")?;
                    println!("{code}\nthere: pasa join NAME {code}");
                    match l.next().as_deref() {
                        Some("taken") => eprintln!("{name} took it"),
                        Some("spent") => bail!(
                            "the code was used by someone who did not prove it: \
                             pasa forget {name}, then pair again"
                        ),
                        _ => bail!("nobody came: pair again"),
                    }
                }
            }
            serve_until(name)?;
        }
        ["join", name, code] => {
            // --scan: the QR code the other device shows, by the camera.
            let scanned = match *code {
                #[cfg(feature = "scan")]
                "--scan" => {
                    eprintln!("Hold the QR code to the camera (Ctrl-C: stop)");
                    crate::scan::scan()?
                }
                c => c.to_string(),
            };
            let code = scanned.trim();
            let got = match code.starts_with("PAIRIR1:") {
                true => {
                    let pw = ask("QR code password: ")?;
                    sync::unqr(code, text(&pw)?).await?
                }
                false => {
                    let mut c = net(&["take", code])?;
                    let l = lines(&mut c).next().context("no answer")?;
                    Zeroizing::new(B64.decode(l.as_bytes())?)
                }
            };
            // Its key file, as it is; the store, as it is: the password
            // opens them afterwards, here alone.
            sync::take(&dir, name, &got)?;
            net_run(&["sync"])?;
            eprintln!("The store is here: its password opens it (pasa ls)");
        }
        ["sync", "on"] => {
            sync::set_on(&dir, true)?;
            eprintln!("Sync on: paired devices sync with this one");
        }
        ["sync", "off"] => {
            sync::set_on(&dir, false)?;
            eprintln!("Offline: nothing goes online until pasa sync on");
        }
        ["sync", ..] => {
            ensure!(sync::on(&dir), "offline: pasa sync on, then pasa sync");
            net_run(a)?
        }
        ["serve"] | ["listen"] => net_run(a)?,
        ["peers"] => {
            let on = if sync::on(&dir) { "on" } else { "off (pasa sync on)" };
            eprintln!("Sync: {on}");
            for (name, d, late) in sync::apart(&dir) {
                match late {
                    true => {
                        println!("{name}\tnot synced for {d} days: check in")
                    }
                    false => println!("{name}\tsynced {d} days ago"),
                }
            }
        }
        ["forget", name] => sync::forget(&dir, name)?,
        ["revoke", name] => {
            sync::revoke(&mut open()?, name)?;
            if sync::on(&dir) {
                net_run(&["sync", "--news"])?;
            }
            eprintln!(
                "A new store key: pair the other devices again (pasa pair \
                 NAME here, join there), and forget {name} on each"
            );
        }
        _ => bail!("{USAGE}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// The salt a key is asked with is WebAuthn's PRF form, as the phone
    /// (Yubico's kit) asks it: a key added there opens the store here.
    #[test]
    fn salts_go_to_keys_as_webauthn_prf_hands_them() {
        let salt: Vec<u8> = (0..32).collect();
        assert_eq!(
            data_encoding::HEXLOWER.encode(&super::prf(&salt)),
            "dc1f4f3b3d759586245d5de7e2e115d2a056a2df27109db7cef9b4b3a89bb106"
        );
    }
}
