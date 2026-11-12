//! Pairing and syncing are apart, and neither opens a key. A pairing hands
//! another device the key file as it is (sealed to the password), with this
//! device's endpoint and a fresh transport key, by a QR code (offline,
//! under a password of its own) or a short code (pairir). A sync swaps the
//! versions each device lacks (age files to the store key), seeing `v/` and
//! `net/` alone ([`net`], `confine`). The password and the hardware key
//! open the key file afterwards, on each device alone.
//!
//! Dialers use throwaway endpoints; `serve` admits whoever proves a
//! pairing's key (irnet::psk: HPKE over X-Wing inside TLS 1.3), while pasa
//! is open there; each swap tells the other where, so either dials. A wake
//! is an empty message to a peer's pushir lane: it says sync, nothing more.

use crate::{MAX, Store, is_name, name_of, rand, write};
use anyhow::{Context, Result, anyhow, bail, ensure};
use data_encoding::HEXLOWER;
use irnet::psk::{Rx, Tx};
use iroh::{EndpointAddr, PublicKey, RelayUrl, SecretKey, TransportAddr};
use pushir::Lane;
use std::path::{Path, PathBuf};
use std::{collections::HashSet, fs, time::Duration};
use tokio::time::timeout;
use zeroize::Zeroizing;

const ALPN: &[u8] = b"pasa/6";

/// What the network side sees beside `v/`: the pairings, this device's
/// endpoint key and lane. Never a key file.
pub fn net(dir: &Path) -> PathBuf {
    let n = dir.join("net");
    // Before 0.4.9 these lay beside the key files.
    if !n.exists() && dir.join("peers").exists() {
        let _ = fs::create_dir_all(&n);
        for f in ["peers", "node", "id", "mailbox", "lane", "give", "take"] {
            let _ = fs::rename(dir.join(f), n.join(f));
        }
    }
    n
}

/// A pairing: its transport key, the peer's endpoint if it serves, its
/// pushir lane if it listens.
pub struct Peer {
    pub name: String,
    pub psk: [u8; 32],
    pub id: Option<PublicKey>,
    pub lane: Option<Lane>,
}

/// `psk endpoint lane name`, a line each (before 0.4.10 a device id came
/// before the name).
pub fn peers(dir: &Path) -> Vec<Peer> {
    let f = fs::read_to_string(net(dir).join("peers")).unwrap_or_default();
    let peer = |l: &str| {
        let w: Vec<&str> = l.split(' ').collect();
        let psk =
            HEXLOWER.decode(w.first()?.as_bytes()).ok()?.try_into().ok()?;
        let id = w.get(1)?.parse().ok();
        let lane = w.get(2)?.parse().ok();
        let name = w[3..].last()?.to_string();
        Some(Peer { psk, id, lane, name })
    };
    f.lines().filter_map(peer).collect()
}

fn save(dir: &Path, ps: &[Peer]) -> Result<()> {
    let line = |p: &Peer| {
        let m = p.lane.as_ref().map_or("-".into(), Lane::to_string);
        let id = p.id.map_or("-".into(), |k| k.to_string());
        format!("{} {id} {m} {}\n", HEXLOWER.encode(&p.psk), p.name)
    };
    write(
        &net(dir).join("peers"),
        ps.iter().map(line).collect::<String>().as_bytes(),
    )
}

fn named(name: &str) -> Result<()> {
    ensure!(!name.is_empty() && !name.contains(['\n', '/', ' ']), "bad name");
    Ok(())
}

fn add(dir: &Path, p: Peer) -> Result<()> {
    named(&p.name)?;
    let mut ps = peers(dir);
    ps.retain(|q| q.name != p.name);
    ps.push(p);
    save(dir, &ps)
}

pub fn forget(dir: &Path, name: &str) -> Result<()> {
    let mut ps = peers(dir);
    let n = ps.len();
    ps.retain(|p| p.name != name);
    ensure!(ps.len() < n, "no peer {name}");
    save(dir, &ps)?;
    // It held our lane's secret: a new one, which the peers that stay get
    // at their next sync. `listen` moves to it by itself; the Android app
    // when it next starts.
    let at = fs::read_to_string(net(dir).join("mailbox")).ok();
    if let Some(at) = at.and_then(|l| l.parse::<Lane>().ok()) {
        let _ = fs::remove_file(net(dir).join("lane"));
        set_mailbox(dir, at.id)?;
    }
    Ok(())
}

/// End pairing `name` and rotate the store key, here: every entry sealed
/// again to a new key, which the other devices get by pairing again (keys
/// never travel in a sync). Forget it on every device it paired with.
pub fn revoke(s: &mut Store, name: &str) -> Result<()> {
    forget(&s.dir, name)?;
    s.rotate()
}

/// A secret key in `net/file`, made once.
fn key(dir: &Path, file: &str) -> Result<SecretKey> {
    fs::create_dir_all(net(dir))?;
    Ok(SecretKey::from_bytes(&pushir::kept(&net(dir).join(file))?))
}

/// This device's pushir lane secret for pasa, made once: peers alone get
/// it, and what is sealed under it says only "sync".
pub fn lane(dir: &Path) -> Result<pushir::Key> {
    fs::create_dir_all(net(dir))?;
    pushir::kept(&net(dir).join("lane"))
}

/// Where peers wake us: our lane on the mailbox pushir gave this device.
pub fn set_mailbox(dir: &Path, id: PublicKey) -> Result<()> {
    let l = Lane { relay: pushir::relay()?, id, secret: lane(dir)? };
    write(&net(dir).join("mailbox"), l.to_string().as_bytes())
}

/// `$PASA_RELAY`, or the lab's. One that does not parse is an error, not
/// the lab's after all.
fn relay() -> Result<RelayUrl> {
    match std::env::var("PASA_RELAY") {
        Ok(r) => r
            .parse()
            .ok()
            .with_context(|| format!("PASA_RELAY: {r} is no relay's url")),
        Err(_) => Ok(irnet::relays().swap_remove(0)),
    }
}

fn ep() -> Result<iroh::endpoint::Builder> {
    Ok(irnet::on(&[relay()?]))
}

/// What a swap learnt of the peer (lane, endpoint), and how many versions
/// it took.
type Swapped = (Option<Lane>, Option<PublicKey>, usize);

/// Swap lanes and endpoints, then the versions each lacks: age files, and
/// nothing of the keys.
async fn swap(dir: &Path, mut tx: Tx, mut rx: Rx) -> Result<Swapped> {
    let mailbox = fs::read(net(dir).join("mailbox")).unwrap_or_default();
    tx.send(&mailbox).await?;
    tx.send(key(dir, "node")?.public().as_bytes()).await?;
    let theirs = String::from_utf8(rx.recv(1024).await?).ok();
    let theirs = theirs.and_then(|l| l.parse().ok());
    let id = <[u8; 32]>::try_from(&rx.recv(32).await?[..]).ok();
    let id = id.and_then(|b| PublicKey::from_bytes(&b).ok());
    let v = dir.join("v");
    let names = fs::read_dir(&v).into_iter().flatten().flatten();
    let mine: HashSet<String> = names
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| is_name(n))
        .collect();
    // Both lists at once: past a stream's window (2 MiB, some 65,000
    // versions) each side would wait for the other to read.
    let names = mine.iter().map(String::as_str).collect::<String>();
    let (sent, list) = tokio::join!(tx.send(names.as_bytes()), rx.recv(MAX));
    let list = (sent?, list?).1;
    let other: HashSet<String> = list
        .chunks(32)
        .filter_map(|c| String::from_utf8(c.to_vec()).ok())
        .filter(|n| is_name(n))
        .collect();
    let give = async {
        for n in mine.difference(&other) {
            let b = fs::read(v.join(n))?;
            if name_of(&b) == *n {
                tx.send(&b).await?;
            }
        }
        tx.send(b"").await?;
        tx.finish().await
    };
    let take = async {
        let mut want: HashSet<&String> = other.difference(&mine).collect();
        let n = want.len();
        loop {
            let b = rx.recv(MAX).await?;
            if b.is_empty() {
                break;
            }
            ensure!(want.remove(&name_of(&b)), "a file not asked for");
            write(&v.join(name_of(&b)), &b)?;
        }
        rx.end().await?;
        anyhow::Ok(n - want.len())
    };
    let (g, t) = tokio::join!(give, take);
    g?;
    Ok((theirs, id, t?))
}

/// Keep what a swap learnt of `name`.
fn learnt(
    dir: &Path,
    name: &str,
    lane: Option<Option<Lane>>,
    id: Option<PublicKey>,
) {
    let mut ps = peers(dir);
    let Some(p) = ps.iter_mut().find(|p| p.name == name) else { return };
    let before = (p.lane.clone(), p.id);
    p.lane = lane.unwrap_or(p.lane.take());
    p.id = id.or(p.id);
    if before != (p.lane.clone(), p.id) {
        let _ = save(dir, &ps);
    }
}

/// Wake every listening peer but `except`: an empty message to its lane,
/// over one connection per relay, the relays at once. A wake lost or
/// repeated costs a sync at most.
async fn wake(dir: &Path, except: &str) {
    let mut by: std::collections::BTreeMap<String, Vec<Lane>> =
        Default::default();
    for p in peers(dir).into_iter().filter(|p| p.name != except) {
        if let Some(l) = p.lane {
            by.entry(l.relay.to_string()).or_default().push(l);
        }
    }
    let mut all = tokio::task::JoinSet::new();
    for lanes in by.into_values() {
        all.spawn(async move {
            let mut tx = pushir::Sender::connect(&lanes[0].relay).await?;
            for l in &lanes {
                tx.send(l, b"").await?;
            }
            tx.close().await
        });
    }
    while all.join_next().await.is_some() {}
}

/// Sync with every peer whose endpoint is known, all at once (one that is
/// away costs its 15 s once, not once each); with `news` (a change here),
/// then wake those that listen. A peer not met yet is said, not skipped.
pub async fn sync(
    dir: &Path,
    news: bool,
) -> Result<Vec<(String, Result<usize>)>> {
    let (ep, relay) = (ep()?.alpns(vec![ALPN.into()]).bind().await?, relay()?);
    let mut all = tokio::task::JoinSet::new();
    let mut out = vec![];
    for p in peers(dir) {
        let Some(id) = p.id else {
            let e = anyhow!(
                "not met yet: it syncs once it has reached this device"
            );
            out.push((p.name, Err(e)));
            continue;
        };
        let (ep, relay, dir) = (ep.clone(), relay.clone(), dir.to_path_buf());
        all.spawn(async move {
            let go = async {
                let at =
                    EndpointAddr::from_parts(id, [TransportAddr::Relay(relay)]);
                let meet = async {
                    let c = ep.connect(at, ALPN).await?;
                    let (tx, rx) = irnet::psk::dial(&c, &p.psk).await?;
                    anyhow::Ok((c, tx, rx))
                };
                let (c, tx, rx) =
                    timeout(Duration::from_secs(15), meet).await.map_err(
                        |_| anyhow!("not reached: is pasa open there?"),
                    )??;
                // A whole store may take a while; a stalled peer, not forever.
                let r = timeout(SWAP, swap(&dir, tx, rx)).await;
                c.close(0u32.into(), b"");
                r.unwrap_or_else(|_| Err(anyhow!("timed out")))
            };
            let r = go.await;
            (p.name, r)
        });
    }
    // What each swap learnt is kept one at a time: `peers` is one file.
    while let Some(r) = all.join_next().await {
        let (name, r) = r?;
        out.push((
            name.clone(),
            r.map(|(_, id, n)| {
                learnt(dir, &name, None, id);
                n
            }),
        ));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    // Each swap ended on both sides; a peer gone since need not ack.
    let _ = timeout(Duration::from_secs(2), ep.close()).await;
    if news {
        wake(dir, "").await;
    }
    Ok(out)
}

/// How long one swap may take, a whole store included.
const SWAP: Duration = Duration::from_secs(300);

/// Accept syncs from paired devices; wake the others after news. One
/// process at a time serves a store: two endpoints with one key would take
/// its place at the relay from each other.
pub async fn serve(
    dir: &Path,
    log: impl Fn(&str, Result<usize>) + Clone + Send + 'static,
) -> Result<()> {
    let node = key(dir, "node")?;
    let lock = fs::File::open(net(dir).join("node"))?;
    // Android's std has no file lock: an app there is one process.
    match lock.try_lock() {
        Err(fs::TryLockError::WouldBlock) => bail!("pasa serves here already"),
        Err(fs::TryLockError::Error(e))
            if e.kind() != std::io::ErrorKind::Unsupported =>
        {
            Err(e)?
        }
        _ => {}
    }
    let ep = ep()?.secret_key(node).alpns(vec![ALPN.into()]).bind().await?;
    while let Some(inc) = ep.accept().await {
        let (dir, log) = (dir.to_path_buf(), log.clone());
        tokio::spawn(async move {
            let ps = peers(&dir);
            let psks: Vec<&[u8; 32]> = ps.iter().map(|p| &p.psk).collect();
            let go = async {
                let (i, tx, rx) =
                    irnet::psk::accept(&inc.await?, &psks).await?;
                anyhow::Ok((i, swap(&dir, tx, rx).await?))
            };
            match timeout(SWAP, go).await {
                Ok(Ok((i, (mailbox, id, n)))) => {
                    learnt(&dir, &ps[i].name, Some(mailbox), id);
                    if n > 0 {
                        wake(&dir, &ps[i].name).await;
                    }
                    log(&ps[i].name, Ok(n))
                }
                Ok(Err(e)) => log("?", Err(e)),
                Err(_) => log("?", Err(anyhow!("timed out"))),
            }
        });
    }
    Ok(())
}

/// Desktop: attach to the pushir daemon; sync now, and on each message
/// (a peer's wake, or the mailbox back from a gap). Wakes that came during
/// a sync are answered by one more.
#[cfg(unix)]
pub async fn listen(dir: &Path, log: fn(&str, Result<usize>)) -> Result<()> {
    loop {
        // On the lane as it is now: a forgotten peer ends the old one,
        // which is seen at the next wake or within a quarter of an hour.
        let secret = lane(dir)?;
        let (id, mut rx) =
            pushir::local::attach(&pushir::local::sock(), &secret).await?;
        set_mailbox(dir, id)?;
        while lane(dir)? == secret {
            sync(dir, false).await?.into_iter().for_each(|(w, r)| log(&w, r));
            // The next wake; or, each quarter hour, whether the lane moved.
            loop {
                match timeout(Duration::from_secs(900), rx.recv()).await {
                    Ok(None) => return Ok(()),
                    Ok(Some(_)) => break,
                    Err(_) if lane(dir)? != secret => break,
                    Err(_) => {}
                }
            }
            while rx.try_recv().is_ok() {}
        }
    }
}

/// What a pairing hands the device called `name` here: this device's
/// endpoint, a fresh transport key for the two, and the key file as it is,
/// sealed to the password (and YubiKey). Nothing is unlocked to make it,
/// and nothing in it opens a version without that password. The pairing
/// is kept here; the other device dials here once it has [`take`]n it.
pub fn offer(dir: &Path, name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let f = fs::read(dir.join("key")).context("no store here")?;
    let (psk, id) = (rand::<32>(), key(dir, "node")?.public());
    add(dir, Peer { name: name.into(), psk, id: None, lane: None })?;
    Ok(Zeroizing::new([id.as_bytes(), &psk[..], &f].concat()))
}

/// Take what [`offer`] made, as a code brought it, calling that device
/// `name`: it is a peer at once, to sync with, and its key file is this
/// device's (one that differed kept as `key.old`). Nothing is unlocked:
/// the password opens it afterwards, here alone.
pub fn take(dir: &Path, name: &str, got: &[u8]) -> Result<()> {
    named(name)?;
    let bad = || anyhow!("not a pasa pairing");
    let (id, rest) = got.split_at_checked(32).ok_or_else(bad)?;
    let (psk, f) = rest.split_at_checked(32).ok_or_else(bad)?;
    ensure!(!f.is_empty(), "not a pasa pairing");
    let id = Some(PublicKey::from_bytes(id.try_into()?)?);
    let at = dir.join("key");
    match fs::read(&at) {
        Ok(old) if old != f => write(&dir.join("key.old"), &old)?,
        _ => {}
    }
    write(&at, f)?;
    add(dir, Peer { name: name.into(), psk: psk.try_into()?, id, lane: None })
}

/// A QR code's text: what [`offer`] made, under `pw` (pairir: Argon2id,
/// XChaCha20-Poly1305). Offline.
pub async fn qr(got: &[u8], pw: &str) -> Result<String> {
    pairir::seal_qr("pasa", got, pw).await
}

/// What a QR code holds, under its password.
pub async fn unqr(text: &str, pw: &str) -> Result<Zeroizing<Vec<u8>>> {
    pairir::open_qr("pasa", text.trim(), pw).await
}

/// A short code's network half: what [`offer`] made, to whoever proves the
/// code (pairir: CPace, then X-Wing, inside post-quantum TLS); how it ends.
pub async fn give(
    got: &[u8],
) -> Result<(String, tokio::task::JoinHandle<pairir::End>)> {
    pairir::give(&[relay()?], "pasa", got, None).await
}

/// The other half: what the device showing `code` gives.
pub async fn fetch(code: &str) -> Result<Zeroizing<Vec<u8>>> {
    pairir::take(&[relay()?], "pasa", code.trim(), None).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::RelayMode;

    /// `b` takes what `a` offers; neither store is opened.
    fn pair(a: &Path, an: &str, b: &Path, bn: &str) {
        take(b, an, &offer(a, bn).unwrap()).unwrap();
    }

    /// `a` dials `b`: how many versions each took.
    async fn swap_once(
        a: &Path,
        b: &Path,
        bn: &str,
        an: &str,
    ) -> (usize, usize) {
        let bind = || {
            irnet::endpoint()
                .alpns(vec![ALPN.into()])
                .relay_mode(RelayMode::Disabled)
                .bind()
        };
        let (ea, eb) = (bind().await.unwrap(), bind().await.unwrap());
        let (at, b2, an) = (eb.addr(), b.to_path_buf(), an.to_string());
        let psk = peers(a).into_iter().find(|p| p.name == bn).unwrap().psk;
        let srv = tokio::spawn(async move {
            let c = eb.accept().await.unwrap().await.unwrap();
            let (_, tx, rx) = irnet::psk::accept(&c, &[&psk]).await.unwrap();
            let (m, id, n) = swap(&b2, tx, rx).await.unwrap();
            learnt(&b2, &an, Some(m), id);
            c.closed().await;
            eb.close().await;
            n
        });
        let c = ea.connect(at, ALPN).await.unwrap();
        let (tx, rx) = irnet::psk::dial(&c, &psk).await.unwrap();
        let (_, id, n) = swap(a, tx, rx).await.unwrap();
        learnt(a, bn, None, id);
        c.close(0u32.into(), b"");
        ea.close().await;
        (n, srv.await.unwrap())
    }

    /// Every file under `d`, and whether any holds `secret`.
    fn holds(d: &Path, secret: &[u8]) -> bool {
        fs::read_dir(d).unwrap().flatten().any(|e| match e.path() {
            p if p.is_dir() => holds(&p, secret),
            p => {
                fs::read(p).unwrap().windows(secret.len()).any(|w| w == secret)
            }
        })
    }

    /// A phone with the store pairs a desktop with none, by a QR code under
    /// a two-letter password; they sync. Neither opens the store or sees
    /// its password: the key file and the versions travel as they are.
    /// Then, on the desktop alone, the password opens what came.
    #[tokio::test(flavor = "multi_thread")]
    async fn pair_then_sync_then_unlock() {
        let d = crate::tests::dir("pairing");
        let (phone, desk) = (d.join("phone"), d.join("desk"));
        // Long enough that no age header's base64 holds it by chance.
        const PW: &[u8] = b"the store's own password";
        let sp = Store::create(&phone, PW, None).unwrap();
        sp.put("mail/work", b"hunter2\nuser: me").unwrap();
        sp.put("bank", b"Tr0ub4dor&3").unwrap();
        let store_key = sp.keys()[0].clone();
        drop(sp);
        let file = fs::read(phone.join("key")).unwrap();
        let got = offer(&phone, "desk").unwrap();
        assert!(got.ends_with(&file), "the key file as it is");
        for s in [&store_key[..], b"hunter2", PW] {
            assert!(!got.windows(s.len()).any(|w| w == s), "in the clear");
        }
        let qr = qr(&got, "ab").await.unwrap();
        assert!(unqr(&qr, "ac").await.is_err());
        take(&desk, "phone", &unqr(&qr, "ab").await.unwrap()).unwrap();
        assert_eq!(fs::read(desk.join("key")).unwrap(), file);
        // No unlock anywhere: the desktop dials the phone; then each knows
        // where the other serves.
        assert_eq!(swap_once(&desk, &phone, "phone", "desk").await, (2, 0));
        let at = |d: &Path, n: &str| peers(d).into_iter().find(|p| p.name == n);
        let node = |d: &Path| key(d, "node").unwrap().public();
        assert_eq!(at(&desk, "phone").unwrap().id, Some(node(&phone)));
        assert_eq!(at(&phone, "desk").unwrap().id, Some(node(&desk)));
        // The sync side's view, v/ and net/: age files and transport keys;
        // no store key, no entry, no key file.
        for d in [&phone, &desk] {
            for e in fs::read_dir(d.join("v")).unwrap().flatten() {
                let b = fs::read(e.path()).unwrap();
                assert!(b.starts_with(b"age-encryption.org/v1\n-> scrypt "));
            }
            for s in [&store_key[..], b"hunter2", b"Tr0ub4dor", &file[..]] {
                for sub in ["v", "net"] {
                    assert!(
                        !holds(&d.join(sub), s),
                        "{}: a secret",
                        d.display()
                    );
                }
            }
        }
        let sd = Store::open(&desk, PW, None).unwrap();
        assert_eq!(&sd.get("mail/work").unwrap()[..], b"hunter2\nuser: me");
    }

    /// Lists past a stream's window (2 MiB: 70,000 names here) cross: each
    /// side sends its own while it reads the other's.
    #[tokio::test(flavor = "multi_thread")]
    async fn long_lists_cross() {
        let d = crate::tests::dir("lists");
        let (a, b) = (d.join("a"), d.join("b"));
        Store::create(&a, b"pw", None).unwrap();
        pair(&a, "a", &b, "b");
        for (side, x) in [(&a, 0u32), (&b, 1)] {
            fs::create_dir_all(side.join("v")).unwrap();
            for i in 0..70_000u32 {
                let n = format!("{x:08x}{i:024x}");
                fs::File::create(side.join("v").join(n)).unwrap();
            }
        }
        let go = swap_once(&a, &b, "b", "a");
        let took = timeout(Duration::from_secs(120), go).await;
        assert_eq!(took.expect("the lists never crossed"), (0, 0));
    }

    /// Versions merge by union; a stray file stays. After a revoke the store
    /// key is new: another device reads what follows once paired again, and
    /// the revoked one's transport key is no longer taken.
    #[tokio::test(flavor = "multi_thread")]
    async fn sync_and_revoke() {
        let d = crate::tests::dir("sync");
        let (a, b, c) = (d.join("a"), d.join("b"), d.join("c"));
        let mut sa = Store::create(&a, b"pw", None).unwrap();
        pair(&a, "a", &b, "b");
        pair(&a, "a", &c, "c");
        sa.put("x", b"1").unwrap();
        Store::open(&b, b"pw", None).unwrap().put("y", b"2").unwrap();
        fs::write(a.join("v/stray"), b"editor backup").unwrap();
        // a listens: whoever it dials learns its lane, to wake it there.
        set_mailbox(&a, SecretKey::from_bytes(&[3; 32]).public()).unwrap();
        assert_eq!(swap_once(&a, &b, "b", "a").await, (1, 1));
        let at = peers(&b).into_iter().find(|p| p.name == "a").unwrap().lane;
        assert!(at.is_some_and(|l| l.secret == lane(&a).unwrap()));
        swap_once(&a, &c, "c", "a").await;
        let names = |d: &Path| {
            let s = Store::open(d, b"pw", None).unwrap();
            s.entries().unwrap().into_keys().collect::<Vec<_>>()
        };
        assert_eq!(names(&c), ["x", "y"]);
        let old = lane(&a).unwrap();
        revoke(&mut sa, "b").unwrap();
        assert!(lane(&a).unwrap() != old, "b knew a's lane");
        let b_psk = peers(&b)[0].psk;
        assert!(peers(&a).iter().all(|p| p.psk != b_psk), "b is refused");
        sa.put("z", b"3").unwrap();
        swap_once(&a, &c, "c", "a").await;
        assert_eq!(names(&c), ["x", "y"], "z only once paired again");
        pair(&a, "a", &c, "c");
        assert!(c.join("key.old").exists(), "the key file it had");
        assert_eq!(names(&c), ["x", "y", "z"]);
    }
}
