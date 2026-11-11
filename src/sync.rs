//! Pairing and syncing are apart. A pairing hands another device the key
//! file (sealed to the password) and the pairing's own keys (sealed to the
//! store key): nothing that opens without the store's password, by a QR
//! code (offline) or a short code (pairir). A sync swaps the versions each
//! device lacks, and sees `v/` and `net/` alone ([`net`], `confine`):
//! transport keys, endpoints and age files, never a key file.
//!
//! Dialers use throwaway endpoints; `serve` admits whoever proves a
//! pairing's key (irnet::psk: HPKE over X-Wing inside TLS 1.3), while pasa
//! is open there; each swap tells the other where, so either dials. A wake
//! is an empty message to a peer's pushir lane: it says sync, nothing more.
//!
//! After a rotation the new store keys travel as an age file to a
//! hand-over key each pairing shares, kept only in the devices' sealed
//! `dev`; with them, the ids of revoked devices, so none passes keys on.

use crate::{MAX, Store, is_name, name_of, open, rand, seal, write};
use anyhow::{Context, Result, anyhow, bail, ensure};
use data_encoding::HEXLOWER;
use irnet::psk::{Rx, Tx};
use iroh::{EndpointAddr, PublicKey, RelayUrl, SecretKey, TransportAddr};
use pushir::Lane;
use std::path::{Path, PathBuf};
use std::{collections::HashSet, fs, time::Duration};
use tokio::time::timeout;
use zeroize::Zeroizing;

const ALPN: &[u8] = b"pasa/5";

/// What the network side sees beside `v/`: the pairings, this device's
/// endpoint key, id and lane, the hand-overs. Never a key file.
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
/// pushir lane if it listens, its device id once it said.
pub struct Peer {
    pub name: String,
    pub psk: [u8; 32],
    pub id: Option<PublicKey>,
    pub lane: Option<Lane>,
    pub device: Option<String>,
}

pub fn peers(dir: &Path) -> Vec<Peer> {
    let f = fs::read_to_string(net(dir).join("peers")).unwrap_or_default();
    let peer = |l: &str| {
        let mut w = l.splitn(5, ' ');
        let psk =
            HEXLOWER.decode(w.next()?.as_bytes()).ok()?.try_into().ok()?;
        let id = w.next()?.parse().ok();
        let lane = w.next()?.parse().ok();
        let device = Some(w.next()?).filter(|d| *d != "-").map(String::from);
        Some(Peer { psk, id, lane, device, name: w.next()?.into() })
    };
    f.lines().filter_map(peer).collect()
}

fn save(dir: &Path, ps: &[Peer]) -> Result<()> {
    let line = |p: &Peer| {
        let m = p.lane.as_ref().map_or("-".into(), Lane::to_string);
        let id = p.id.map_or("-".into(), |k| k.to_string());
        let dev = p.device.as_deref().unwrap_or("-");
        format!("{} {id} {m} {dev} {}\n", HEXLOWER.encode(&p.psk), p.name)
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
    let _ = fs::remove_file(net(dir).join("give").join(name));
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

/// This device's id: public, random, made once.
fn device(dir: &Path) -> Result<String> {
    let p = net(dir).join("id");
    if !p.exists() {
        write(&p, HEXLOWER.encode(&rand::<16>()).as_bytes())?;
    }
    Ok(fs::read_to_string(p)?.trim().into())
}

fn revoked(dir: &Path) -> HashSet<String> {
    let f = fs::read_to_string(dir.join("revoked")).unwrap_or_default();
    f.lines().map(String::from).collect()
}

fn revoke_ids(dir: &Path, ids: impl IntoIterator<Item = String>) -> Result<()> {
    let mut r = revoked(dir);
    r.extend(ids);
    write(
        &dir.join("revoked"),
        r.iter().map(|i| format!("{i}\n")).collect::<String>().as_bytes(),
    )?;
    for p in peers(dir) {
        if p.device.as_ref().is_some_and(|d| r.contains(d)) {
            forget(dir, &p.name)?;
        }
    }
    Ok(())
}

/// End pairing `name` and rotate the store key; the other peers get the
/// new key and the revocation at their next sync. Revoke it on every
/// device it paired with.
pub fn revoke(s: &mut Store, name: &str) -> Result<()> {
    let p = peers(&s.dir)
        .into_iter()
        .find(|p| p.name == name)
        .context("no such peer")?;
    match p.device {
        Some(d) => revoke_ids(&s.dir, [d])?,
        None => forget(&s.dir, name)?,
    }
    s.hands.remove(name);
    s.rotate()?;
    hand(s)
}

/// For every peer: the store keys and the revoked device ids, sealed to
/// that pairing's hand-over key. Only once a rotation made a key that a
/// pairing's key file lacks: until then there is nothing to hand.
pub fn hand(s: &Store) -> Result<()> {
    if s.keys().len() < 2 {
        return Ok(());
    }
    let keys: Vec<u8> =
        s.keys().iter().flat_map(|k| k.iter().copied()).collect();
    let r: String =
        revoked(&s.dir).into_iter().map(|i| format!("{i}\n")).collect();
    let msg = Zeroizing::new(
        [&[s.keys().len() as u8][..], &keys, r.as_bytes()].concat(),
    );
    for (name, k) in &s.hands {
        write(&net(&s.dir).join("give").join(name), &seal(k, &msg)?)?;
    }
    Ok(())
}

/// At unlock: what peers handed over (revocations first, then keys);
/// hand on to the rest.
pub fn adopt(s: &mut Store) -> Result<()> {
    for e in fs::read_dir(net(&s.dir).join("take")).into_iter().flatten() {
        let p = e?.path();
        let b = fs::read(&p)?;
        fs::remove_file(&p)?;
        let Some(m) = s.hands.values().find_map(|k| open(k, &b)) else {
            continue;
        };
        let n = *m.first().context("empty hand-over")? as usize;
        let (keys, ids) =
            m[1..].split_at_checked(32 * n).context("short hand-over")?;
        revoke_ids(
            &s.dir,
            std::str::from_utf8(ids)?.lines().map(String::from),
        )?;
        s.hands.retain(|name, _| peers(&s.dir).iter().any(|p| &p.name == name));
        s.add_keys(keys)?;
    }
    hand(s)
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

/// What a swap learnt of the peer (lane, device id, endpoint), and how
/// many versions it took.
type Swapped = (Option<Lane>, Option<String>, Option<PublicKey>, usize);

/// Swap lanes, device ids, endpoints and hand-overs, then the versions
/// each lacks.
async fn swap(
    dir: &Path,
    peer: &str,
    mut tx: Tx,
    mut rx: Rx,
) -> Result<Swapped> {
    let (read, n) = (|f: &Path| fs::read(f).unwrap_or_default(), net(dir));
    tx.send(&read(&n.join("mailbox"))).await?;
    tx.send(device(dir)?.as_bytes()).await?;
    tx.send(key(dir, "node")?.public().as_bytes()).await?;
    tx.send(&read(&n.join("give").join(peer))).await?;
    let theirs = String::from_utf8(rx.recv(1024).await?).ok();
    let theirs = theirs.and_then(|l| l.parse().ok());
    let dev =
        String::from_utf8(rx.recv(32).await?).ok().filter(|d| d.len() == 32);
    let id = <[u8; 32]>::try_from(&rx.recv(32).await?[..]).ok();
    let id = id.and_then(|b| PublicKey::from_bytes(&b).ok());
    let keys = rx.recv(64 << 10).await?;
    if !keys.is_empty() {
        write(&n.join("take").join(name_of(&keys)), &keys)?;
    }
    let v = dir.join("v");
    let names = fs::read_dir(&v).into_iter().flatten().flatten();
    let mine: HashSet<String> = names
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| is_name(n))
        .collect();
    tx.send(mine.iter().map(String::as_str).collect::<String>().as_bytes())
        .await?;
    let list = rx.recv(MAX).await?;
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
    Ok((theirs, dev, id, t?))
}

/// Keep what a swap learnt of `name`.
fn learnt(
    dir: &Path,
    name: &str,
    lane: Option<Option<Lane>>,
    dev: Option<String>,
    id: Option<PublicKey>,
) {
    let mut ps = peers(dir);
    let Some(p) = ps.iter_mut().find(|p| p.name == name) else { return };
    let before = (p.lane.clone(), p.device.clone(), p.id);
    p.lane = lane.unwrap_or(p.lane.take());
    p.device = dev.or(p.device.take());
    p.id = id.or(p.id);
    if before != (p.lane.clone(), p.device.clone(), p.id) {
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
                let r = timeout(SWAP, swap(&dir, &p.name, tx, rx)).await;
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
            r.map(|(_, dev, id, n)| {
                learnt(dir, &name, None, dev, id);
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
                anyhow::Ok((i, swap(&dir, &ps[i].name, tx, rx).await?))
            };
            match timeout(SWAP, go).await {
                Ok(Ok((i, (mailbox, dev, id, n)))) => {
                    learnt(&dir, &ps[i].name, Some(mailbox), dev, id);
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

/// Keep a pairing's hand-over key, sealed in `dev`.
pub fn keep_hand(s: &mut Store, name: &str, hand: &[u8]) -> Result<()> {
    s.hands.insert(name.into(), Zeroizing::new(hand.to_vec()));
    s.save()
}

/// What a pairing hands the device called `name` here, made with the store
/// open: this device's endpoint, the key file (sealed to the password and
/// YubiKey) and the pairing's transport and hand-over keys sealed to the
/// newest store key. Nothing in it opens without the store's password: a
/// QR code's password only keeps it from whoever else sees the code. The
/// pairing is kept here; it dials here once it has [`taken`] it.
pub fn offer(s: &mut Store, name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let (psk, hand) = (rand::<32>(), rand::<32>());
    let id = key(&s.dir, "node")?.public();
    let f = fs::read(s.dir.join("key")).context("no store here")?;
    let both = Zeroizing::new([psk, hand].concat());
    let sealed = seal(&s.keys()[0], &both)?;
    let n = u16::try_from(sealed.len())?.to_be_bytes();
    let new =
        Peer { name: name.into(), psk, id: None, lane: None, device: None };
    add(&s.dir, new)?;
    keep_hand(s, name, &hand)?;
    Ok(Zeroizing::new([id.as_bytes(), &n[..], &sealed, &f].concat()))
}

/// A pairing taken, until the unlock that opens its keys ([`taken`]).
pub struct Taken {
    name: String,
    id: PublicKey,
    sealed: Vec<u8>,
}

/// Take what [`offer`] made, as a code brought it, calling that device
/// `name`. Its key file is kept if there is no store here.
pub fn take(dir: &Path, name: &str, got: &[u8]) -> Result<Taken> {
    named(name)?;
    let bad = || anyhow!("not a pasa pairing");
    let (id, rest) = got.split_at_checked(32).ok_or_else(bad)?;
    let (n, rest) = rest.split_at_checked(2).ok_or_else(bad)?;
    let n = u16::from_be_bytes([n[0], n[1]]) as usize;
    let (sealed, f) = rest.split_at_checked(n).ok_or_else(bad)?;
    let id = PublicKey::from_bytes(id.try_into()?)?;
    if !dir.join("key").exists() {
        write(&dir.join("key"), f)?;
    }
    Ok(Taken { name: name.into(), id, sealed: sealed.into() })
}

/// At the unlock after [`take`]: the pairing's keys opened by the store
/// key, the peer kept with its endpoint, its hand-over key in `dev`.
pub fn taken(s: &mut Store, t: Taken) -> Result<()> {
    let both = s.keys().iter().find_map(|k| open(k, &t.sealed));
    let both = both.context("that pairing is another store's")?;
    let (psk, hand) =
        both.split_at_checked(32).context("not a pasa pairing")?;
    let psk = psk.try_into()?;
    let p =
        Peer { name: t.name, psk, id: Some(t.id), lane: None, device: None };
    let name = p.name.clone();
    add(&s.dir, p)?;
    keep_hand(s, &name, hand)
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

    /// `a` paired with `b`, as `offer` and `taken` leave them.
    fn pair_by_hand(
        a: &mut Store,
        an: &str,
        b: &mut Store,
        bn: &str,
        psk: [u8; 32],
    ) {
        let hand = rand::<32>();
        let p = |n: &str| Peer {
            name: n.into(),
            psk,
            id: None,
            lane: None,
            device: None,
        };
        add(&a.dir, p(bn)).unwrap();
        add(&b.dir, p(an)).unwrap();
        keep_hand(a, bn, &hand).unwrap();
        keep_hand(b, an, &hand).unwrap();
    }

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
            let (m, dev, id, n) = swap(&b2, &an, tx, rx).await.unwrap();
            learnt(&b2, &an, Some(m), dev, id);
            c.closed().await;
            eb.close().await;
            n
        });
        let c = ea.connect(at, ALPN).await.unwrap();
        let (tx, rx) = irnet::psk::dial(&c, &psk).await.unwrap();
        let (_, dev, id, n) = swap(a, bn, tx, rx).await.unwrap();
        learnt(a, bn, None, dev, id);
        c.close(0u32.into(), b"");
        ea.close().await;
        (n, srv.await.unwrap())
    }

    fn device_store(d: &Path, from: &Path) -> Store {
        fs::create_dir_all(d).unwrap();
        fs::copy(from.join("key"), d.join("key")).unwrap();
        Store::open(d, b"pw", None).unwrap()
    }

    /// Versions merge by union; a rotation's key reaches the peers still
    /// paired, never the revoked one, even through a third device.
    #[tokio::test(flavor = "multi_thread")]
    async fn sync_and_revoke() {
        let d = crate::tests::dir("sync");
        let (a, b, c) = (d.join("a"), d.join("b"), d.join("c"));
        let mut sa = Store::create(&a, b"pw", None).unwrap();
        let (mut sb, mut sc) = (device_store(&b, &a), device_store(&c, &a));
        pair_by_hand(&mut sa, "a", &mut sb, "b", [5; 32]);
        pair_by_hand(&mut sa, "a", &mut sc, "c", [6; 32]);
        pair_by_hand(&mut sb, "b", &mut sc, "c", [7; 32]);
        sa.put("x", b"1").unwrap();
        sb.put("y", b"2").unwrap();
        fs::write(a.join("v/stray"), b"editor backup").unwrap();
        // a listens: whoever it dials learns its lane, to wake it there.
        set_mailbox(&a, SecretKey::from_bytes(&[3; 32]).public()).unwrap();
        assert_eq!(
            swap_once(&a, &b, "b", "a").await,
            (1, 1),
            "a stray file stays"
        );
        let at = peers(&b).into_iter().find(|p| p.name == "a").unwrap().lane;
        assert!(at.is_some_and(|l| l.secret == lane(&a).unwrap()));
        swap_once(&a, &c, "c", "a").await;
        swap_once(&b, &c, "c", "b").await;
        assert_eq!(
            sb.entries().unwrap().keys().collect::<Vec<_>>(),
            ["x", "y"]
        );
        // a revokes b: c gets the new key and the revocation, so c's
        // hand-over to b (still paired there) carries nothing new.
        let old = lane(&a).unwrap();
        revoke(&mut sa, "b").unwrap();
        let now = fs::read_to_string(a.join("net/mailbox")).unwrap();
        let now = now.parse::<Lane>().unwrap().secret;
        assert!(now != old && now == lane(&a).unwrap(), "b knew a's lane");
        swap_once(&a, &c, "c", "a").await;
        adopt(&mut sc).unwrap();
        assert_eq!(sc.keys().len(), 2);
        assert!(peers(&c).iter().all(|p| p.name != "b"), "c forgot b");
        assert!(!c.join("net/give/b").exists());
        assert!(
            peers(&b).iter().any(|p| p.name == "c"),
            "b still pairs with c"
        );
        swap_once(&b, &c, "c", "b").await;
        adopt(&mut sb).unwrap();
        assert_eq!(sb.keys().len(), 1, "b never gets the new key");
        assert_eq!(&sc.get("x").unwrap()[..], b"1");
        // Nothing serve can read opens a hand-over or a version.
        let give = fs::read(a.join("net/give/c")).unwrap();
        for p in peers(&a) {
            assert!(open(&p.psk, &give).is_none());
        }
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
    /// a two-letter password: it holds the key file and the pairing's keys,
    /// each sealed to the store, so it opens nothing without the store's
    /// password. Then they sync, and what the sync side sees holds no key.
    #[tokio::test(flavor = "multi_thread")]
    async fn pairing_hands_only_sealed_keys() {
        let d = crate::tests::dir("pairing");
        let (phone, desk) = (d.join("phone"), d.join("desk"));
        let mut sp = Store::create(&phone, b"pw", None).unwrap();
        sp.put("mail/work", b"hunter2\nuser: me").unwrap();
        sp.put("bank", b"Tr0ub4dor&3").unwrap();
        let got = offer(&mut sp, "desk").unwrap();
        let p = peers(&phone).into_iter().find(|p| p.name == "desk").unwrap();
        let secrets =
            [&sp.keys()[0][..], &p.psk, &sp.hands["desk"], b"hunter2", b"pw\n"];
        for s in secrets {
            assert!(!got.windows(s.len()).any(|w| w == s), "in the clear");
        }
        let qr = qr(&got, "ab").await.unwrap();
        assert!(unqr(&qr, "ac").await.is_err());
        let got = unqr(&qr, "ab").await.unwrap();
        let t = take(&desk, "phone", &got).unwrap();
        assert!(Store::open(&desk, b"not it", None).is_err());
        let mut sd = Store::open(&desk, b"pw", None).unwrap();
        taken(&mut sd, t).unwrap();
        // The desktop dials the phone, whose endpoint it took; then each
        // knows where the other serves.
        assert_eq!(swap_once(&desk, &phone, "phone", "desk").await, (2, 0));
        assert_eq!(&sd.get("mail/work").unwrap()[..], b"hunter2\nuser: me");
        let at = |d: &Path, n: &str| peers(d).into_iter().find(|p| p.name == n);
        let node = |d: &Path| key(d, "node").unwrap().public();
        assert_eq!(at(&desk, "phone").unwrap().id, Some(node(&phone)));
        assert_eq!(at(&phone, "desk").unwrap().id, Some(node(&desk)));
        assert_eq!(at(&desk, "phone").unwrap().psk, p.psk);
        // The sync side's view, v/ and net/: age files and transport keys,
        // no store key, no hand-over key, no password, no key file.
        let file = fs::read(phone.join("key")).unwrap();
        for d in [&phone, &desk] {
            for e in fs::read_dir(d.join("v")).unwrap().flatten() {
                let b = fs::read(e.path()).unwrap();
                assert!(b.starts_with(b"age-encryption.org/v1\n-> scrypt "));
            }
            for s in
                secrets.iter().skip(2).chain([&&sp.keys()[0][..], &&file[..]])
            {
                for sub in ["v", "net"] {
                    assert!(
                        !holds(&d.join(sub), s),
                        "{} holds a secret",
                        d.display()
                    );
                }
            }
        }
        assert!(!phone.join("net/give/desk").exists(), "one key: no hand-over");
    }
}
