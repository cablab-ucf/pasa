//! Devices swap the versions each lacks. Nothing here opens a version:
//! `serve` holds pairing keys (transport only), endpoint ids and age files.
//! Dialers use throwaway endpoints; `serve` admits whoever proves a
//! pairing's key (irnet::psk: HPKE over X-Wing inside TLS 1.3). A wake is
//! an empty message to a peer's pushir lane: it says sync, nothing more.
//!
//! A device serves while pasa is open there; each swap tells the peer
//! where, so either side dials the other. The one showing a pairing code
//! serves, the one taking it dials, and either may hold the store: a swap
//! hands the key file (sealed to the password) to a device without one.
//!
//! After a rotation the new store keys travel as an age file to a
//! hand-over key each pairing shares, kept only in the devices' sealed
//! `dev`, bound to the store's first key; with them, the ids of revoked
//! devices, so none passes keys on.

use crate::{MAX, Store, is_name, name_of, open, rand, seal, write};
use anyhow::{Context, Result, anyhow, bail, ensure};
use data_encoding::HEXLOWER;
use irnet::psk::{Rx, Tx};
use iroh::{EndpointAddr, PublicKey, RelayUrl, SecretKey, TransportAddr};
use pushir::Lane;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fs, path::Path, time::Duration};
use tokio::time::timeout;
use zeroize::Zeroizing;

const ALPN: &[u8] = b"pasa/5";

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
    let f = fs::read_to_string(dir.join("peers")).unwrap_or_default();
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
        &dir.join("peers"),
        ps.iter().map(line).collect::<String>().as_bytes(),
    )
}

fn add(dir: &Path, p: Peer) -> Result<()> {
    ensure!(
        !p.name.is_empty() && !p.name.contains(['\n', '/', ' ']),
        "bad name"
    );
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
    let _ = fs::remove_file(dir.join("give").join(name));
    save(dir, &ps)?;
    // It held our lane's secret: a new one, which the peers that stay get
    // at their next sync. `listen` moves to it by itself; the Android app
    // when it next starts.
    let at = fs::read_to_string(dir.join("mailbox")).ok();
    if let Some(at) = at.and_then(|l| l.parse::<Lane>().ok()) {
        let _ = fs::remove_file(dir.join("lane"));
        set_mailbox(dir, at.id)?;
    }
    Ok(())
}

/// This device's id: public, random, made once.
fn device(dir: &Path) -> Result<String> {
    let p = dir.join("id");
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

/// A pairing's hand-over key bound to the store's first key: what a
/// pairing's secrets alone (a QR code and its password) neither open nor
/// forge. Every device of a store holds its first key.
fn bound(hand: &[u8], s: &Store) -> Zeroizing<Vec<u8>> {
    let first = s.keys().last().map_or(&[][..], |k| &k[..]);
    let h = Sha256::new().chain_update(b"pasa hand-over\0").chain_update(hand);
    Zeroizing::new(h.chain_update(first).finalize().to_vec())
}

/// For every peer: the store keys and the revoked device ids, sealed to
/// that pairing's hand-over key, bound.
pub fn hand(s: &Store) -> Result<()> {
    let keys: Vec<u8> =
        s.keys().iter().flat_map(|k| k.iter().copied()).collect();
    let r: String =
        revoked(&s.dir).into_iter().map(|i| format!("{i}\n")).collect();
    let msg = Zeroizing::new(
        [&[s.keys().len() as u8][..], &keys, r.as_bytes()].concat(),
    );
    for (name, k) in &s.hands {
        write(&s.dir.join("give").join(name), &seal(&bound(k, s), &msg)?)?;
    }
    Ok(())
}

/// At unlock: what peers handed over (revocations first, then keys);
/// hand on to the rest.
pub fn adopt(s: &mut Store) -> Result<()> {
    for e in fs::read_dir(s.dir.join("take")).into_iter().flatten() {
        let p = e?.path();
        let b = fs::read(&p)?;
        fs::remove_file(&p)?;
        let Some(m) = s.hands.values().find_map(|k| open(&bound(k, s), &b))
        else {
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

/// A secret key in `dir/file`, made once.
fn key(dir: &Path, file: &str) -> Result<SecretKey> {
    Ok(SecretKey::from_bytes(&pushir::kept(&dir.join(file))?))
}

/// This device's pushir lane secret for pasa, made once: peers alone get
/// it, and what is sealed under it says only "sync".
pub fn lane(dir: &Path) -> Result<pushir::Key> {
    pushir::kept(&dir.join("lane"))
}

/// Where peers wake us: our lane on the mailbox pushir gave this device.
pub fn set_mailbox(dir: &Path, id: PublicKey) -> Result<()> {
    let l = Lane { relay: pushir::relay()?, id, secret: lane(dir)? };
    write(&dir.join("mailbox"), l.to_string().as_bytes())
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

/// Swap lanes, device ids, endpoints, key files and hand-overs, then the
/// versions each lacks. A device without a store keeps the key file it is
/// given: the store keys, sealed to the password, as a pairing hands them.
async fn swap(
    dir: &Path,
    peer: &str,
    mut tx: Tx,
    mut rx: Rx,
) -> Result<Swapped> {
    let read = |f: &Path| fs::read(f).unwrap_or_default();
    tx.send(&read(&dir.join("mailbox"))).await?;
    tx.send(device(dir)?.as_bytes()).await?;
    tx.send(key(dir, "node")?.public().as_bytes()).await?;
    tx.send(&read(&dir.join("key"))).await?;
    tx.send(&read(&dir.join("give").join(peer))).await?;
    let theirs = String::from_utf8(rx.recv(1024).await?).ok();
    let theirs = theirs.and_then(|l| l.parse().ok());
    let dev =
        String::from_utf8(rx.recv(32).await?).ok().filter(|d| d.len() == 32);
    let id = <[u8; 32]>::try_from(&rx.recv(32).await?[..]).ok();
    let id = id.and_then(|b| PublicKey::from_bytes(&b).ok());
    let file = rx.recv(64 << 10).await?;
    if !file.is_empty() && !dir.join("key").exists() {
        write(&dir.join("key"), &file)?;
    }
    let keys = rx.recv(64 << 10).await?;
    if !keys.is_empty() {
        write(&dir.join("take").join(name_of(&keys)), &keys)?;
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
    let lock = fs::File::open(dir.join("node"))?;
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

pub use pairir::password;

/// A pairing shown here: its code, how a short code ends, and the
/// hand-over key for [`keep_hand`].
pub type Shown =
    (String, Option<tokio::task::JoinHandle<pairir::End>>, Zeroizing<Vec<u8>>);

/// For another device, called `name` here, to take with [`join`]: this
/// device's endpoint, fresh transport and hand-over keys and, if there is
/// a store here, the key file (still sealed to the password and YubiKey),
/// by pairir under `pw`. `qr`: an offline QR code's text, else a short
/// code. Serve until it has synced: it dials here. The hand-over key goes
/// into `dev` with [`keep_hand`]: at once if the store is open, else at
/// the unlock after the store arrives.
pub async fn pair(dir: &Path, name: &str, pw: &str, qr: bool) -> Result<Shown> {
    fs::create_dir_all(dir)?;
    let (psk, hand) = (rand::<32>(), rand::<32>());
    let id = key(dir, "node")?.public();
    let f = fs::read(dir.join("key")).unwrap_or_default();
    let secret = Zeroizing::new([&psk[..], &hand, id.as_bytes(), &f].concat());
    let out = match qr {
        true => (pairir::seal_qr("pasa", &secret, pw).await?, None),
        false => {
            let (code, end) =
                pairir::give(&[relay()?], "pasa", &secret, Some(pw)).await?;
            (code, Some(end))
        }
    };
    add(
        dir,
        Peer { name: name.into(), psk, id: None, lane: None, device: None },
    )?;
    Ok((out.0, out.1, Zeroizing::new(hand.to_vec())))
}

/// Join the device that showed `code`, calling it `name`: its hand-over
/// key, for [`keep_hand`] (at the unlock that follows, if no store is open
/// here). A device with a store keeps its own key file, and hands it to the
/// other at the first sync if that has none.
pub async fn join(
    dir: &Path,
    name: &str,
    code: &str,
    pw: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let s = match code.trim().starts_with("PAIRIR1:") {
        true => pairir::open_qr("pasa", code, pw).await?,
        false => pairir::take(&[relay()?], "pasa", code, Some(pw)).await?,
    };
    ensure!(s.len() >= 96, "not a pasa pairing");
    if s.len() > 96 && !dir.join("key").exists() {
        write(&dir.join("key"), &s[96..])?;
    }
    let id = Some(PublicKey::from_bytes(s[64..96].try_into()?)?);
    add(
        dir,
        Peer {
            name: name.into(),
            psk: s[..32].try_into()?,
            id,
            lane: None,
            device: None,
        },
    )?;
    Ok(Zeroizing::new(s[32..64].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::RelayMode;

    /// `a` paired with `b`, as `pair` and `join` leave them.
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
        let now = fs::read_to_string(a.join("mailbox")).unwrap();
        let now = now.parse::<Lane>().unwrap().secret;
        assert!(now != old && now == lane(&a).unwrap(), "b knew a's lane");
        swap_once(&a, &c, "c", "a").await;
        adopt(&mut sc).unwrap();
        assert_eq!(sc.keys().len(), 2);
        assert!(peers(&c).iter().all(|p| p.name != "b"), "c forgot b");
        assert!(!c.join("give/b").exists());
        assert!(
            peers(&b).iter().any(|p| p.name == "c"),
            "b still pairs with c"
        );
        swap_once(&b, &c, "c", "b").await;
        adopt(&mut sb).unwrap();
        assert_eq!(sb.keys().len(), 1, "b never gets the new key");
        assert_eq!(&sc.get("x").unwrap()[..], b"1");
        // Nothing serve can read opens a hand-over or a version.
        let give = fs::read(a.join("give/c")).unwrap();
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

    /// The phone has the store, the desktop nothing: the desktop shows an
    /// offline QR code, the phone scans it and dials. The store arrives
    /// sealed, opens with its password alone, and each side learns where
    /// the other serves. What the QR code holds, its password with it,
    /// opens no hand-over and plants no key.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_store_reaches_a_device_without_one() {
        let d = crate::tests::dir("reach");
        let (phone, desk) = (d.join("phone"), d.join("desk"));
        let mut sp = Store::create(&phone, b"pw", None).unwrap();
        sp.put("mail/work", b"hunter2\nuser: me").unwrap();
        sp.put("bank", b"Tr0ub4dor&3").unwrap();
        // The desktop, with no store, shows a QR code; the phone takes it.
        let (qr, end, hand) =
            pair(&desk, "phone", "pairing pw", true).await.unwrap();
        assert!(end.is_none() && qr.starts_with("PAIRIR1:"));
        assert!(!desk.join("key").exists(), "no store to give");
        let before = fs::read(phone.join("key")).unwrap();
        let mine = join(&phone, "desk", &qr, "pairing pw").await.unwrap();
        assert_eq!(fs::read(phone.join("key")).unwrap(), before, "kept");
        keep_hand(&mut sp, "desk", &mine).unwrap();
        assert!(join(&phone, "x", &qr, "wrong").await.is_err());
        // The phone dials; the desktop takes the key file and every version.
        assert_eq!(swap_once(&phone, &desk, "desk", "phone").await, (0, 2));
        let mut sd = Store::open(&desk, b"pw", None).unwrap();
        keep_hand(&mut sd, "phone", &hand).unwrap();
        adopt(&mut sd).unwrap();
        assert_eq!(&sd.get("mail/work").unwrap()[..], b"hunter2\nuser: me");
        assert_eq!(sd.entries().unwrap().len(), 2);
        let at = |d: &Path, n: &str| peers(d).into_iter().find(|p| p.name == n);
        let node = |d: &Path| key(d, "node").unwrap().public();
        assert_eq!(at(&desk, "phone").unwrap().id, Some(node(&phone)));
        assert_eq!(at(&phone, "desk").unwrap().id, Some(node(&desk)));
        // On either disk: age files to random keys, never a password or key.
        for d in [&phone, &desk] {
            for e in fs::read_dir(d.join("v")).unwrap().flatten() {
                let b = fs::read(e.path()).unwrap();
                assert!(b.starts_with(b"age-encryption.org/v1\n-> scrypt "));
            }
            for secret in [&b"hunter2"[..], b"Tr0ub4dor", &sp.keys()[0]] {
                assert!(!holds(d, secret), "{} holds a secret", d.display());
            }
        }
        // The QR code and its password: the hand-over key, but no store
        // key, so a hand-over neither opens nor is forged with it alone.
        let give = fs::read(desk.join("give/phone")).unwrap();
        assert!(open(&hand, &give).is_none());
        let forged = seal(&hand, &[&[1u8][..], &[7; 32]].concat()).unwrap();
        write(&phone.join("take/forged"), &forged).unwrap();
        adopt(&mut sp).unwrap();
        assert_eq!(sp.keys().len(), 1, "no key planted");
    }
}
