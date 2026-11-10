//! Devices swap the versions each lacks. Nothing here opens a version:
//! `serve` holds pairing keys (transport only), endpoint ids and age files.
//! Dialers use throwaway endpoints; `serve` admits whoever proves a
//! pairing's key (irnet::psk: HPKE over X-Wing inside TLS 1.3).
//!
//! After a rotation the new store keys travel as an age file to a
//! hand-over key each pairing shares, kept only in the devices' sealed
//! `dev`; with them, the ids of revoked devices, so none passes keys on.

use crate::{MAX, Store, is_name, name_of, open, rand, seal, write};
use anyhow::{Context, Result, anyhow, ensure};
use data_encoding::HEXLOWER;
use irnet::psk::{Rx, Tx};
use iroh::{
    EndpointAddr, PublicKey, RelayMode, RelayUrl, SecretKey, TransportAddr,
};
use irpush::Slot;
use std::{collections::HashSet, fs, path::Path, time::Duration};
use tokio::time::timeout;
use zeroize::Zeroizing;

const ALPN: &[u8] = b"pasa/3";

/// A pairing: its transport key, the peer's endpoint if it serves, its
/// irpush mailbox and slot if it listens, its device id once it said.
pub struct Peer {
    pub name: String,
    pub psk: [u8; 32],
    pub id: Option<PublicKey>,
    pub mailbox: Option<(PublicKey, Slot)>,
    pub device: Option<String>,
}

fn mailbox(b: &[u8]) -> Option<(PublicKey, Slot)> {
    (b.len() == 48).then_some(())?;
    Some((
        PublicKey::from_bytes(b[..32].try_into().ok()?).ok()?,
        b[32..].try_into().ok()?,
    ))
}

pub fn peers(dir: &Path) -> Vec<Peer> {
    let f = fs::read_to_string(dir.join("peers")).unwrap_or_default();
    let peer = |l: &str| {
        let mut w = l.splitn(5, ' ');
        let psk =
            HEXLOWER.decode(w.next()?.as_bytes()).ok()?.try_into().ok()?;
        let id = w.next()?.parse().ok();
        let m = HEXLOWER
            .decode(w.next()?.as_bytes())
            .ok()
            .and_then(|b| mailbox(&b));
        let device = Some(w.next()?).filter(|d| *d != "-").map(String::from);
        Some(Peer { psk, id, mailbox: m, device, name: w.next()?.into() })
    };
    f.lines().filter_map(peer).collect()
}

fn save(dir: &Path, ps: &[Peer]) -> Result<()> {
    let line = |p: &Peer| {
        let m = p.mailbox.map_or("-".into(), |(k, s)| {
            HEXLOWER.encode(&[k.as_bytes(), &s[..]].concat())
        });
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
    save(dir, &ps)
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

/// For every peer: the store keys and the revoked device ids, sealed to
/// that pairing's hand-over key.
pub fn hand(s: &Store) -> Result<()> {
    let keys: Vec<u8> =
        s.keys().iter().flat_map(|k| k.iter().copied()).collect();
    let r: String =
        revoked(&s.dir).into_iter().map(|i| format!("{i}\n")).collect();
    let msg = Zeroizing::new(
        [&[s.keys().len() as u8][..], &keys, r.as_bytes()].concat(),
    );
    for (name, k) in &s.hands {
        write(&s.dir.join("give").join(name), &seal(k, &msg)?)?;
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

/// A secret key in `dir/file`, made once.
fn key(dir: &Path, file: &str) -> Result<SecretKey> {
    let p = dir.join(file);
    if !p.exists() {
        write(&p, &rand::<32>())?;
    }
    let b: [u8; 32] = fs::read(p)?.try_into().ok().context("bad key")?;
    Ok(SecretKey::from_bytes(&b))
}

/// This device's irpush slot for pasa, made once.
pub fn slot(dir: &Path) -> Result<Slot> {
    let p = dir.join("slot");
    if !p.exists() {
        write(&p, &rand::<16>())?;
    }
    fs::read(p)?.try_into().ok().context("bad slot")
}

/// Where peers wake us: the mailbox irpush gave this device.
pub fn set_mailbox(dir: &Path, id: PublicKey) -> Result<()> {
    write(&dir.join("mailbox"), &[id.as_bytes(), &slot(dir)?[..]].concat())
}

/// Whether `m` is a wake from a peer, sealed in the last five minutes.
pub fn is_wake(dir: &Path, m: &[u8]) -> bool {
    let now = std::time::UNIX_EPOCH.elapsed().unwrap_or_default().as_secs();
    let t = peers(dir).iter().find_map(|p| open(&p.psk, m));
    let t = t.and_then(|t| Some(u64::from_be_bytes(t[..].try_into().ok()?)));
    t.is_some_and(|t| t + 300 > now)
}

/// `$PASA_RELAY`, or the lab's.
fn relay() -> RelayUrl {
    let r = std::env::var("PASA_RELAY").ok().and_then(|r| r.parse().ok());
    r.unwrap_or_else(|| irnet::relays().swap_remove(0))
}

fn ep() -> iroh::endpoint::Builder {
    irnet::endpoint().relay_mode(RelayMode::custom([relay()]))
}

/// What a swap learnt of the peer, and how many versions it took.
type Swapped = (Option<(PublicKey, Slot)>, Option<String>, usize);

/// Swap mailboxes, device ids and hand-overs, then the versions each lacks.
async fn swap(
    dir: &Path,
    peer: &str,
    mut tx: Tx,
    mut rx: Rx,
) -> Result<Swapped> {
    tx.send(&fs::read(dir.join("mailbox")).unwrap_or_default()).await?;
    tx.send(device(dir)?.as_bytes()).await?;
    tx.send(&fs::read(dir.join("give").join(peer)).unwrap_or_default()).await?;
    let theirs = mailbox(&rx.recv(48).await?);
    let dev =
        String::from_utf8(rx.recv(32).await?).ok().filter(|d| d.len() == 32);
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
    Ok((theirs, dev, t?))
}

/// Keep what a swap learnt of `name`.
fn learnt(
    dir: &Path,
    name: &str,
    mailbox: Option<Option<(PublicKey, Slot)>>,
    dev: Option<String>,
) {
    let mut ps = peers(dir);
    let Some(p) = ps.iter_mut().find(|p| p.name == name) else { return };
    let before = (p.mailbox, p.device.clone());
    p.mailbox = mailbox.unwrap_or(p.mailbox);
    p.device = dev.or(p.device.take());
    if before != (p.mailbox, p.device.clone()) {
        let _ = save(dir, &ps);
    }
}

/// Wake every listening peer but `except`: the time, sealed to its key.
async fn wake(dir: &Path, except: &str) {
    let now = std::time::UNIX_EPOCH.elapsed().unwrap_or_default().as_secs();
    for p in peers(dir).into_iter().filter(|p| p.name != except) {
        if let (Some((id, slot)), Ok(w)) =
            (p.mailbox, seal(&p.psk, &now.to_be_bytes()))
        {
            let _ = irpush::send(&irpush::relay(), id, slot, &w).await;
        }
    }
}

/// Sync with every peer that serves; with `news` (a change here), then
/// wake those that listen.
pub async fn sync(
    dir: &Path,
    news: bool,
) -> Result<Vec<(String, Result<usize>)>> {
    let ep = ep().alpns(vec![ALPN.into()]).bind().await?;
    let mut out = vec![];
    for p in peers(dir) {
        let Some(id) = p.id else { continue };
        let go = async {
            let at =
                EndpointAddr::from_parts(id, [TransportAddr::Relay(relay())]);
            let c = ep.connect(at, ALPN).await?;
            let (tx, rx) = irnet::psk::dial(&c, &p.psk).await?;
            let r = swap(dir, &p.name, tx, rx).await;
            c.close(0u32.into(), b"");
            let (_, dev, n) = r?;
            learnt(dir, &p.name, None, dev);
            Ok(n)
        };
        let r = timeout(Duration::from_secs(30), go).await;
        out.push((p.name, r.unwrap_or_else(|_| Err(anyhow!("no answer")))));
    }
    ep.close().await;
    if news {
        wake(dir, "").await;
    }
    Ok(out)
}

/// Accept syncs from paired devices; wake the others after news.
pub async fn serve(dir: &Path, log: fn(&str, Result<usize>)) -> Result<()> {
    let ep = ep()
        .secret_key(key(dir, "node")?)
        .alpns(vec![ALPN.into()])
        .bind()
        .await?;
    while let Some(inc) = ep.accept().await {
        let dir = dir.to_path_buf();
        tokio::spawn(async move {
            let ps = peers(&dir);
            let psks: Vec<&[u8]> = ps.iter().map(|p| &p.psk[..]).collect();
            let go = async {
                let (i, tx, rx) =
                    irnet::psk::accept(&inc.await?, &psks).await?;
                anyhow::Ok((i, swap(&dir, &ps[i].name, tx, rx).await?))
            };
            match timeout(Duration::from_secs(300), go).await {
                Ok(Ok((i, (mailbox, dev, n)))) => {
                    learnt(&dir, &ps[i].name, Some(mailbox), dev);
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

/// Desktop: attach to the irpush daemon; sync on each fresh wake.
#[cfg(unix)]
pub async fn listen(dir: &Path, log: fn(&str, Result<usize>)) -> Result<()> {
    let (id, mut rx) =
        irpush::local::attach(&irpush::local::sock(), slot(dir)?).await?;
    set_mailbox(dir, id)?;
    sync(dir, false).await?.into_iter().for_each(|(w, r)| log(&w, r));
    while let Some(m) = rx.recv().await {
        if is_wake(dir, &m) {
            sync(dir, false).await?.into_iter().for_each(|(w, r)| log(&w, r));
        }
    }
    Ok(())
}

/// Keep a pairing's hand-over key, sealed in `dev`.
pub fn keep_hand(s: &mut Store, name: &str, hand: &[u8]) -> Result<()> {
    s.hands.insert(name.into(), Zeroizing::new(hand.to_vec()));
    s.save()
}

/// For a new device, called `name` here: this device's endpoint, fresh
/// transport and hand-over keys, and the key file (still sealed to the
/// password and YubiKey), by irpair under `pw`. `qr`: an offline QR
/// code's text, else a short code. The hand-over key goes straight into
/// the unlocked store's `dev`.
pub async fn pair(
    s: &mut Store,
    name: &str,
    pw: &str,
    qr: bool,
) -> Result<String> {
    let dir = s.dir.clone();
    let (psk, hand) = (rand::<32>(), rand::<32>());
    let id = key(&dir, "node")?.public();
    let f = fs::read(dir.join("key")).context("no store here")?;
    let secret = Zeroizing::new([&psk[..], &hand, id.as_bytes(), &f].concat());
    let out = match qr {
        true => irpair::seal_qr("pasa", &secret, pw).await?,
        false => irpair::give(ep(), "pasa", &secret, Some(pw)).await?,
    };
    add(
        &dir,
        Peer { name: name.into(), psk, id: None, mailbox: None, device: None },
    )?;
    keep_hand(s, name, &hand)?;
    Ok(out)
}

/// Join the device that showed `code`, calling it `name`: its hand-over
/// key, held in memory for [`keep_hand`] at the unlock that follows. A
/// device with a store keeps its own key file.
pub async fn join(
    dir: &Path,
    name: &str,
    code: &str,
    pw: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let s = match code.trim().starts_with("IRPAIR1:") {
        true => irpair::open_qr("pasa", code, pw).await?,
        false => irpair::take(ep(), &[relay()], "pasa", code, Some(pw)).await?,
    };
    ensure!(s.len() > 96, "not a pasa pairing");
    if !dir.join("key").exists() {
        write(&dir.join("key"), &s[96..])?;
    }
    let id = Some(PublicKey::from_bytes(s[64..96].try_into()?)?);
    add(
        dir,
        Peer {
            name: name.into(),
            psk: s[..32].try_into()?,
            id,
            mailbox: None,
            device: None,
        },
    )?;
    Ok(Zeroizing::new(s[32..64].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
            mailbox: None,
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
            let (m, dev, n) = swap(&b2, &an, tx, rx).await.unwrap();
            learnt(&b2, &an, Some(m), dev);
            c.closed().await;
            eb.close().await;
            n
        });
        let c = ea.connect(at, ALPN).await.unwrap();
        let (tx, rx) = irnet::psk::dial(&c, &psk).await.unwrap();
        let (_, dev, n) = swap(a, bn, tx, rx).await.unwrap();
        learnt(a, bn, None, dev);
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
        assert_eq!(
            swap_once(&a, &b, "b", "a").await,
            (1, 1),
            "a stray file stays"
        );
        swap_once(&a, &c, "c", "a").await;
        swap_once(&b, &c, "c", "b").await;
        assert_eq!(
            sb.entries().unwrap().keys().collect::<Vec<_>>(),
            ["x", "y"]
        );
        // a revokes b: c gets the new key and the revocation, so c's
        // hand-over to b (still paired there) carries nothing new.
        revoke(&mut sa, "b").unwrap();
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
}
