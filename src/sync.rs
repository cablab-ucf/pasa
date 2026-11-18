//! Pairing and sync; neither ever opens the key file or a version.

use crate::{MAX, Store, is_name, name_of, rand, write};
use anyhow::{Context, Result, anyhow, bail, ensure};
use data_encoding::HEXLOWER;
use irnet::psk::{Rx, Tx};
use iroh::endpoint::{ConnectOptions, Connection};
use iroh::{EndpointAddr, PublicKey, RelayUrl, SecretKey, TransportAddr};
use pushir::Lane;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::{collections::HashSet, fs, sync::Arc, time::Duration};
use tokio::time::timeout;
use zeroize::Zeroizing;

/// `pasa/7` first; `pasa/6`, without the digest, for peers before 0.4.19.
const ALPN: &[u8] = b"pasa/7";
const ALPN6: &[u8] = b"pasa/6";

fn alpns() -> Vec<Vec<u8>> {
    vec![ALPN.into(), ALPN6.into()]
}

/// The network side's files beside `v/`: never a key file.
pub fn net(dir: &Path) -> PathBuf {
    let n = dir.join("net");
    // Migration: before 0.4.9 these lay beside the key files.
    if !n.exists() && dir.join("peers").exists() {
        let _ = fs::create_dir_all(&n);
        for f in ["peers", "node", "id", "mailbox", "lane", "give", "take"] {
            let _ = fs::rename(dir.join(f), n.join(f));
        }
    }
    n
}

/// `id`: its endpoint, once known; `seen`: last sync or pairing, Unix seconds;
/// `at`: its direct addresses when last dialled.
pub struct Peer {
    pub name: String,
    pub psk: [u8; 32],
    pub id: Option<PublicKey>,
    pub lane: Option<Lane>,
    pub seen: Option<u64>,
    pub at: Vec<SocketAddr>,
}

/// `psk id lane seen at name` a line, `at` comma-separated: `seen` fourth
/// and name last, where older versions read them.
pub fn peers(dir: &Path) -> Vec<Peer> {
    let f = fs::read_to_string(net(dir).join("peers")).unwrap_or_default();
    let peer = |l: &str| {
        let w: Vec<&str> = l.split(' ').collect();
        let psk =
            HEXLOWER.decode(w.first()?.as_bytes()).ok()?.try_into().ok()?;
        let id = w.get(1)?.parse().ok();
        let lane = w.get(2)?.parse().ok();
        let name = w[3..].last()?.to_string();
        let seen =
            w.get(3).filter(|_| w.len() > 4).and_then(|s| s.parse().ok());
        let at = w.get(4).filter(|_| w.len() > 5);
        let at = at.iter().flat_map(|a| a.split(','));
        let at = at.filter_map(|a| a.parse().ok()).collect();
        Some(Peer { psk, id, lane, seen, at, name })
    };
    f.lines().filter_map(peer).collect()
}

fn save(dir: &Path, ps: &[Peer]) -> Result<()> {
    let line = |p: &Peer| {
        let m = p.lane.as_ref().map_or("-".into(), Lane::to_string);
        let id = p.id.map_or("-".into(), |k| k.to_string());
        let seen = p.seen.map_or("-".into(), |t| t.to_string());
        let at: Vec<String> = p.at.iter().map(SocketAddr::to_string).collect();
        let at = if at.is_empty() { "-".into() } else { at.join(",") };
        let psk = HEXLOWER.encode(&p.psk);
        format!("{psk} {id} {m} {seen} {at} {}\n", p.name)
    };
    write(
        &net(dir).join("peers"),
        ps.iter().map(line).collect::<String>().as_bytes(),
    )
}

fn now() -> u64 {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    t.map_or(0, |d| d.as_secs())
}

pub fn on(dir: &Path) -> bool {
    net(dir).join("on").exists()
}

pub fn set_on(dir: &Path, on: bool) -> Result<()> {
    let at = net(dir).join("on");
    if on {
        return write(&at, b"");
    }
    match fs::remove_file(&at) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

pub const APART: u64 = 30 * 86_400;

/// (name, days since last sync, >= APART); no `seen`: since the file's mtime.
pub fn apart(dir: &Path) -> Vec<(String, u64, bool)> {
    let now = now();
    let m = fs::metadata(net(dir).join("peers")).and_then(|m| m.modified());
    let t = m.ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok());
    let since = t.map_or(now, |d| d.as_secs());
    let one = |p: Peer| {
        let s = now.saturating_sub(p.seen.unwrap_or(since));
        (p.name, s / 86_400, s >= APART)
    };
    peers(dir).into_iter().map(one).collect()
}

pub fn unseen(dir: &Path) -> Vec<(String, u64)> {
    apart(dir).into_iter().filter(|a| a.2).map(|a| (a.0, a.1)).collect()
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
    // It knew our lane's secret: a new one, which the rest get at next sync.
    let at = fs::read_to_string(net(dir).join("mailbox")).ok();
    if let Some(at) = at.and_then(|l| l.parse::<Lane>().ok()) {
        let _ = fs::remove_file(net(dir).join("lane"));
        set_mailbox(dir, at.id)?;
    }
    Ok(())
}

pub fn revoke(s: &mut Store, name: &str) -> Result<()> {
    forget(&s.dir, name)?;
    s.rotate()
}

/// Each device of a store says itself there: `.pasa/devices/ENDPOINT`, its
/// name. Versions, so they reach every device as any version does (an
/// older pasa carries them unread).
const DEVICES: &str = ".pasa/devices/";

/// The secret two devices introduced through their store pair with: from
/// [`Store::intro`]'s for a store key, and both endpoints.
fn introduced(intro: &[u8; 32], a: &PublicKey, b: &PublicKey) -> [u8; 32] {
    let (lo, hi) = if a.as_bytes() < b.as_bytes() { (a, b) } else { (b, a) };
    let h = Sha256::new().chain_update(intro).chain_update(lo.as_bytes());
    h.chain_update(hi.as_bytes()).finalize().into()
}

/// A name as `peers` holds it: no space, slash or control character (none
/// for a terminal to obey), 32 characters at most.
fn clean(n: &str) -> String {
    let dash = |c: char| if c.is_whitespace() || c == '/' { '-' } else { c };
    let n = n.trim().chars().map(dash).filter(|c| !c.is_control());
    n.take(32).collect()
}

/// What this device calls itself to the others: `net/name` (an app's
/// choice, such as a phone's model), else the host's name.
fn own_name(dir: &Path, me: &PublicKey) -> String {
    #[cfg(unix)]
    let host = rustix::system::uname().nodename().to_str().ok().map(clean);
    #[cfg(not(unix))]
    let host = std::env::var("COMPUTERNAME").ok().map(|n| clean(&n));
    let set = fs::read_to_string(net(dir).join("name")).ok().map(|n| clean(&n));
    match set.filter(|n| !n.is_empty()).or(host).as_deref() {
        None | Some("" | "localhost") => {
            format!("device-{}", &me.to_string()[..8])
        }
        Some(n) => n.into(),
    }
}

/// This device said in the store, and each device the store says paired
/// with this one under its newest key: every device syncs with all, not
/// only with the one it paired with. One the store no longer says (revoked,
/// or on a retired key until paired again) goes; one paired directly stays
/// as it was. Sync off: nothing.
pub fn introduce(s: &Store) -> Result<()> {
    if !on(&s.dir) {
        return Ok(());
    }
    let me = key(&s.dir, "node")?.public();
    let mine = format!("{DEVICES}{me}");
    let said = s.hidden(DEVICES)?;
    let name = own_name(&s.dir, &me);
    if !said.iter().any(|(n, b)| *n == mine && b[..] == *name.as_bytes()) {
        s.put_on(&mine, name.as_bytes(), None)?;
    }
    let intro = s.intro();
    let newest = intro.first().context("no store key")?;
    let ours = |p: &Peer| {
        let of = |id| intro.iter().any(|k| introduced(k, &me, id) == p.psk);
        p.id.as_ref().is_some_and(of)
    };
    let told: Vec<(PublicKey, String)> = said
        .iter()
        .filter_map(|(n, b)| {
            let id: PublicKey = n.strip_prefix(DEVICES)?.parse().ok()?;
            let name = clean(std::str::from_utf8(b).ok()?);
            (id != me && !name.is_empty()).then_some((id, name))
        })
        .collect();
    let mut ps = peers(&s.dir);
    let direct: HashSet<PublicKey> =
        ps.iter().filter(|p| !ours(p)).filter_map(|p| p.id).collect();
    let n = ps.len();
    let says = |id: &PublicKey| told.iter().any(|t| t.0 == *id);
    ps.retain(|p| {
        let id = p.id.as_ref();
        !ours(p) || id.is_some_and(|id| !direct.contains(id) && says(id))
    });
    let mut changed = ps.len() != n;
    for (id, name) in told.iter().filter(|t| !direct.contains(&t.0)) {
        let psk = introduced(newest, &me, id);
        match ps.iter_mut().find(|p| p.id == Some(*id)) {
            Some(p) if p.psk == psk => {}
            // A new store key: the pairing it gives.
            Some(p) => {
                p.psk = psk;
                changed = true;
            }
            None => {
                let taken = |n: &str| ps.iter().any(|p| p.name == n);
                let name = match taken(name) {
                    false => name.clone(),
                    true => format!("{name}-{}", &id.to_string()[..8]),
                };
                let id = Some(*id);
                let (lane, seen, at) = (None, None, vec![]);
                ps.push(Peer { name, psk, id, lane, seen, at });
                changed = true;
            }
        }
    }
    if changed {
        save(&s.dir, &ps)?;
    }
    Ok(())
}

fn key(dir: &Path, file: &str) -> Result<SecretKey> {
    fs::create_dir_all(net(dir))?;
    Ok(SecretKey::from_bytes(&pushir::kept(&net(dir).join(file))?))
}

pub fn lane(dir: &Path) -> Result<pushir::Key> {
    fs::create_dir_all(net(dir))?;
    pushir::kept(&net(dir).join("lane"))
}

pub fn set_mailbox(dir: &Path, id: PublicKey) -> Result<()> {
    let l = Lane { relay: pushir::relay()?, id, secret: lane(dir)? };
    write(&net(dir).join("mailbox"), l.to_string().as_bytes())
}

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

/// (peer's lane, peer's endpoint, versions taken)
type Swapped = (Option<Lane>, Option<PublicKey>, usize);

/// Wire: lane, endpoint key, then on `pasa/7` the SHA-256 of the sorted
/// names, names (32 bytes each) unless both digests match, files the other
/// lacks, "".
async fn swap(dir: &Path, v7: bool, mut tx: Tx, mut rx: Rx) -> Result<Swapped> {
    let mailbox = fs::read(net(dir).join("mailbox")).unwrap_or_default();
    tx.send(&mailbox).await?;
    tx.send(key(dir, "node")?.public().as_bytes()).await?;
    let theirs = String::from_utf8(rx.recv(1024).await?).ok();
    let theirs = theirs.and_then(|l| l.parse().ok());
    let id = <[u8; 32]>::try_from(&rx.recv(32).await?[..]).ok();
    let id = id.and_then(|b| PublicKey::from_bytes(&b).ok());
    let v = crate::versions(dir);
    let names = fs::read_dir(&v).into_iter().flatten().flatten();
    let mine: HashSet<String> = names
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| is_name(n))
        .collect();
    let mut names: Vec<&str> = mine.iter().map(String::as_str).collect();
    names.sort_unstable();
    let names = names.concat();
    let digest = Sha256::digest(&names);
    let same = v7 && {
        tx.send(&digest).await?;
        rx.recv(32).await? == digest[..]
    };
    let other = if same {
        mine.clone()
    } else {
        // Both at once: past the 2 MiB stream window, sequential sends
        // deadlock.
        let (sent, list) =
            tokio::join!(tx.send(names.as_bytes()), rx.recv(MAX));
        let list = (sent?, list?).1;
        list.chunks(32)
            .filter_map(|c| String::from_utf8(c.to_vec()).ok())
            .filter(|n| is_name(n))
            .collect()
    };
    let give = async {
        for n in mine.difference(&other) {
            let b = fs::read(v.join(n))?;
            // One too large for a frame (an older pasa's) is kept back,
            // not fatal: the rest goes.
            if name_of(&b) == *n && b.len() <= MAX {
                tx.send(&b).await?;
            }
        }
        tx.send(b"").await?;
        tx.finish().await
    };
    let take = async {
        let mut want: HashSet<&String> = other.difference(&mine).collect();
        let mut n = 0;
        loop {
            let b = rx.recv(MAX).await?;
            if b.is_empty() {
                break;
            }
            ensure!(want.remove(&name_of(&b)), "a file not asked for");
            // Only versions are kept; anything else is passed over, not
            // fatal: a peer that holds one still syncs the rest.
            if b.starts_with(b"age-encryption.org/v1\n") {
                write(&v.join(name_of(&b)), &b)?;
                n += 1;
            }
        }
        rx.end().await?;
        anyhow::Ok(n)
    };
    let (g, t) = tokio::join!(give, take);
    g?;
    Ok((theirs, id, t?))
}

/// Records a sync with `name`; `lane: None` and no `at` keep the known.
fn learnt(
    dir: &Path,
    name: &str,
    lane: Option<Option<Lane>>,
    id: Option<PublicKey>,
    at: Vec<SocketAddr>,
) {
    let mut ps = peers(dir);
    let Some(p) = ps.iter_mut().find(|p| p.name == name) else { return };
    p.lane = lane.unwrap_or(p.lane.take());
    p.id = id.or(p.id);
    if !at.is_empty() {
        p.at = at;
    }
    p.seen = Some(now());
    let _ = save(dir, &ps);
}

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

/// The peer's direct addresses this connection went by.
fn direct(c: &Connection) -> Vec<SocketAddr> {
    let paths = c.paths();
    let at = paths.iter().map(|p| p.remote_addr().clone());
    let at = EndpointAddr::from_parts(c.remote_id(), at);
    at.ip_addrs().copied().collect()
}

/// All peers at once: an unreachable one costs its 15 s once, not per peer.
pub async fn sync(
    dir: &Path,
    news: bool,
) -> Result<Vec<(String, Result<usize>)>> {
    let (ep, relay) = (ep()?.alpns(alpns()).bind().await?, relay()?);
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
                // Direct where it was last met, and by the relay.
                let ip = p.at.iter().map(|a| TransportAddr::Ip(*a));
                let at = EndpointAddr::from_parts(id, ip).with_relay_url(relay);
                let meet = async {
                    let o = ConnectOptions::new()
                        .with_additional_alpns(vec![ALPN6.into()]);
                    let c = ep.connect_with_opts(at, ALPN, o).await?.await?;
                    let (tx, rx) = irnet::psk::dial(&c, &p.psk).await?;
                    anyhow::Ok((c, tx, rx))
                };
                let (c, tx, rx) =
                    timeout(Duration::from_secs(15), meet).await.map_err(
                        |_| anyhow!("not reached: is pasa open there?"),
                    )??;
                let v7 = c.alpn() == ALPN;
                let r = timeout(SWAP, swap(&dir, v7, tx, rx)).await;
                let at = direct(&c);
                c.close(0u32.into(), b"");
                let r = r.unwrap_or_else(|_| Err(anyhow!("timed out")));
                r.map(|s| (s, at))
            };
            let r = go.await;
            (p.name, r)
        });
    }
    // Serially: `peers` is one file.
    while let Some(r) = all.join_next().await {
        let (name, r) = r?;
        out.push((
            name.clone(),
            r.map(|((_, id, n), at)| {
                learnt(dir, &name, None, id, at);
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

const SWAP: Duration = Duration::from_secs(300);

pub async fn serve(
    dir: &Path,
    log: impl Fn(&str, Result<usize>) + Clone + Send + 'static,
) -> Result<()> {
    let node = key(dir, "node")?;
    let lock = fs::File::open(net(dir).join("node"))?;
    // One server per endpoint key: two would evict each other at the relay.
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
    let ep = ep()?.secret_key(node).alpns(alpns()).bind().await?;
    // Bounded work: handshakes before a proof (each 10 s at most), and
    // swaps after one, far above what a person's devices ask.
    use tokio::sync::Semaphore;
    let (pending, active) =
        (Arc::new(Semaphore::new(64)), Arc::new(Semaphore::new(16)));
    while let Some(inc) = ep.accept().await {
        let Ok(first) = pending.clone().try_acquire_owned() else {
            inc.refuse();
            continue;
        };
        let (dir, log, active) =
            (dir.to_path_buf(), log.clone(), active.clone());
        tokio::spawn(async move {
            let ps = peers(&dir);
            let psks: Vec<&[u8; 32]> = ps.iter().map(|p| &p.psk).collect();
            let go = async {
                let c = inc.await?;
                let (i, tx, rx) = irnet::psk::accept(&c, &psks).await?;
                drop(first);
                let _busy = active
                    .try_acquire_owned()
                    .ok()
                    .context("busy: sync later")?;
                anyhow::Ok((i, swap(&dir, c.alpn() == ALPN, tx, rx).await?))
            };
            match timeout(SWAP, go).await {
                Ok(Ok((i, (mailbox, id, n)))) => {
                    learnt(&dir, &ps[i].name, Some(mailbox), id, vec![]);
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

/// Syncs now and on each message; wakes during a sync coalesce into one more.
#[cfg(unix)]
pub async fn listen(dir: &Path, log: fn(&str, Result<usize>)) -> Result<()> {
    loop {
        // Reattach once `forget` rotates the lane: seen on a wake or in 15 min.
        let secret = lane(dir)?;
        let (id, mut rx) =
            pushir::local::attach(&pushir::local::sock(), &secret).await?;
        set_mailbox(dir, id)?;
        while lane(dir)? == secret {
            let began = tokio::time::Instant::now();
            sync(dir, false).await?.into_iter().for_each(|(w, r)| log(&w, r));
            loop {
                match timeout(Duration::from_secs(900), rx.recv()).await {
                    Ok(None) => return Ok(()),
                    Ok(Some(_)) => break,
                    Err(_) if lane(dir)? != secret => break,
                    Err(_) => {}
                }
            }
            // A wake replayed (a relay can) costs one sync in [`EVERY`] at
            // most; those meanwhile are one more.
            tokio::time::sleep_until(began + EVERY).await;
            while rx.try_recv().is_ok() {}
        }
    }
}

/// The least time between two syncs a wake starts.
pub const EVERY: Duration = Duration::from_secs(5);

/// Wire: endpoint key (32), psk (32), then the key file bare, or with hardware
/// keys KEYS and the key, quick and ctap files framed. Quick goes empty: with
/// its YubiKey's answer its PIN falls offline, so it stays on its device.
pub fn offer(dir: &Path, name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let f = fs::read(dir.join("key")).context("no store here")?;
    let ctap = fs::read_to_string(dir.join("ctap")).ok();
    let ctap = ctap.and_then(|t| crate::ctap_packed(&t)).unwrap_or_default();
    let (psk, id) = (rand::<32>(), key(dir, "node")?.public());
    add(
        dir,
        Peer {
            name: name.into(),
            psk,
            id: None,
            lane: None,
            seen: Some(now()),
            at: vec![],
        },
    )?;
    set_on(dir, true)?;
    let n = 64 + KEYS.len() + 12 + f.len() + ctap.len();
    let mut out = Zeroizing::new(Vec::with_capacity(n));
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(&psk);
    match ctap.is_empty() {
        true => out.extend(&f),
        false => {
            out.extend(KEYS);
            for b in [&f[..], &[], &ctap] {
                crate::frame(&mut out, b);
            }
        }
    }
    Ok(out)
}

const KEYS: &[u8] = b"pasakeys";

pub fn take(dir: &Path, name: &str, got: &[u8]) -> Result<()> {
    named(name)?;
    let bad = || anyhow!("not a pasa pairing");
    let (id, rest) = got.split_at_checked(32).ok_or_else(bad)?;
    let (psk, mut f) = rest.split_at_checked(32).ok_or_else(bad)?;
    let (mut quick, mut ctap) = (&[][..], String::new());
    if let Some(mut b) = f.strip_prefix(KEYS) {
        let mut next = || crate::unframe(&mut b).ok_or_else(bad);
        (f, quick) = (next()?, next()?);
        let packed = next()?;
        if !packed.is_empty() {
            ctap = crate::ctap_unpacked(packed).ok_or_else(bad)?;
        }
    }
    ensure!(!f.is_empty(), "not a pasa pairing");
    let id = Some(PublicKey::from_bytes(id.try_into()?)?);
    let at = dir.join("key");
    let new = match fs::read(&at) {
        // Every key file it had kept: a second join never loses the first's.
        Ok(old) if old != f => {
            let mut to = dir.join("key.old");
            for n in 1.. {
                if fs::read(&to).map_or(true, |b| b == old) {
                    break;
                }
                to = dir.join(format!("key.old.{n}"));
            }
            write(&to, &old).map(|_| true)?
        }
        old => old.is_err(),
    };
    write(&at, f)?;
    // Hardware keys' files open the key file they came with alone.
    for (n, b) in [("quick", quick), ("ctap", ctap.as_bytes())] {
        match b.is_empty() {
            false => write(&dir.join(n), b)?,
            true if new => {
                let _ = fs::remove_file(dir.join(n));
            }
            true => {}
        }
    }
    add(
        dir,
        Peer {
            name: name.into(),
            psk: psk.try_into()?,
            id,
            lane: None,
            seen: Some(now()),
            at: vec![],
        },
    )?;
    set_on(dir, true)
}

/// A QR code's password: 99 random bits.
pub use pairir::password;

pub async fn qr(got: &[u8], pw: &str) -> Result<String> {
    pairir::seal_qr("pasa", got, pw).await
}

pub async fn unqr(text: &str, pw: &str) -> Result<Zeroizing<Vec<u8>>> {
    pairir::open_qr("pasa", text.trim(), pw).await
}

pub async fn give(
    got: &[u8],
) -> Result<(String, tokio::task::JoinHandle<pairir::End>)> {
    pairir::give(&[relay()?], "pasa", got, None).await
}

pub async fn fetch(code: &str) -> Result<Zeroizing<Vec<u8>>> {
    pairir::take(&[relay()?], "pasa", code.trim(), None).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::RelayMode;

    fn pair(a: &Path, an: &str, b: &Path, bn: &str) {
        take(b, an, &offer(a, bn).unwrap()).unwrap();
    }

    /// `a` dials `b` on `alpn`: versions taken by (a, b).
    async fn swap_once(
        a: &Path,
        b: &Path,
        bn: &str,
        an: &str,
        alpn: &[u8],
    ) -> (usize, usize) {
        let bind = || {
            irnet::endpoint()
                .alpns(alpns())
                .relay_mode(RelayMode::Disabled)
                .bind()
        };
        let (ea, eb) = (bind().await.unwrap(), bind().await.unwrap());
        let (at, b2, an) = (eb.addr(), b.to_path_buf(), an.to_string());
        let psk = peers(a).into_iter().find(|p| p.name == bn).unwrap().psk;
        let srv = tokio::spawn(async move {
            let c = eb.accept().await.unwrap().await.unwrap();
            let (_, tx, rx) = irnet::psk::accept(&c, &[&psk]).await.unwrap();
            let v7 = c.alpn() == ALPN;
            let (m, id, n) = swap(&b2, v7, tx, rx).await.unwrap();
            learnt(&b2, &an, Some(m), id, vec![]);
            c.closed().await;
            eb.close().await;
            n
        });
        let c = ea.connect(at, alpn).await.unwrap();
        let (tx, rx) = irnet::psk::dial(&c, &psk).await.unwrap();
        let (_, id, n) = swap(a, alpn == ALPN, tx, rx).await.unwrap();
        learnt(a, bn, None, id, direct(&c));
        c.close(0u32.into(), b"");
        ea.close().await;
        (n, srv.await.unwrap())
    }

    fn holds(d: &Path, secret: &[u8]) -> bool {
        fs::read_dir(d).unwrap().flatten().any(|e| match e.path() {
            p if p.is_dir() => holds(&p, secret),
            p => {
                fs::read(p).unwrap().windows(secret.len()).any(|w| w == secret)
            }
        })
    }

    /// b and c, each paired with a alone, meet through the store: each
    /// lists the other and they sync directly. Revoked, c drops out.
    #[tokio::test(flavor = "multi_thread")]
    async fn devices_paired_apart_sync_with_each_other() {
        let d = crate::tests::dir("introduce");
        let (a, b, c) = (d.join("a"), d.join("b"), d.join("c"));
        const PW: &[u8] = b"pw";
        drop(Store::create(&a, PW, None).unwrap());
        pair(&a, "a", &b, "b");
        pair(&a, "a", &c, "c");
        for (d, n) in [(&a, "desk"), (&b, "laptop"), (&c, "phone")] {
            write(&net(d).join("name"), n.as_bytes()).unwrap();
        }
        let direct = peers(&b)[0].psk;
        // Each says itself as it opens; a carries what each said.
        let open = |d: &Path| drop(Store::open(d, PW, None).unwrap());
        for d in [&a, &b, &c] {
            open(d);
        }
        swap_once(&b, &a, "a", "b", ALPN).await;
        swap_once(&c, &a, "a", "c", ALPN).await;
        swap_once(&b, &a, "a", "b", ALPN).await;
        open(&b);
        open(&c);
        let of = |d: &Path, n: &str| peers(d).into_iter().find(|p| p.name == n);
        let (bc, cb) = (of(&b, "phone").unwrap(), of(&c, "laptop").unwrap());
        assert_eq!(bc.psk, cb.psk, "one pairing, from both sides");
        assert_eq!(peers(&b).len(), 2, "a, paired directly, and c");
        assert_eq!(of(&b, "a").unwrap().psk, direct, "a direct pair stays");
        Store::open(&b, PW, None).unwrap().put("from b", b"1").unwrap();
        assert_eq!(swap_once(&c, &b, "laptop", "phone", ALPN).await, (1, 0));
        // Opened again: nothing changes, nothing written.
        let at = fs::read(net(&b).join("peers")).unwrap();
        open(&b);
        assert_eq!(fs::read(net(&b).join("peers")).unwrap(), at);
        // a revokes c; b, paired again from a, has the new key: c is gone.
        revoke(&mut Store::open(&a, PW, None).unwrap(), "c").unwrap();
        pair(&a, "a", &b, "b");
        open(&b);
        assert!(
            of(&b, "phone").is_none(),
            "revoked: not said under the new key"
        );
    }

    /// Pairing and sync open nothing; afterwards the password opens what came.
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
        // A file no version, held by a peer: passed over, the rest arrives.
        let junk = b"not a version".as_slice();
        fs::write(crate::versions(&phone).join(name_of(junk)), junk).unwrap();
        assert_eq!(
            swap_once(&desk, &phone, "phone", "desk", ALPN).await,
            (2, 0)
        );
        assert!(!crate::versions(&desk).join(name_of(junk)).exists());
        fs::remove_file(crate::versions(&phone).join(name_of(junk))).unwrap();
        let at = |d: &Path, n: &str| peers(d).into_iter().find(|p| p.name == n);
        let node = |d: &Path| key(d, "node").unwrap().public();
        assert_eq!(at(&desk, "phone").unwrap().id, Some(node(&phone)));
        assert_eq!(at(&phone, "desk").unwrap().id, Some(node(&desk)));
        // The sync side's view (v/, net/) holds no secret.
        for d in [&phone, &desk] {
            for e in fs::read_dir(crate::versions(d)).unwrap().flatten() {
                let b = fs::read(e.path()).unwrap();
                assert!(b.starts_with(b"age-encryption.org/v1\n-> scrypt "));
            }
            for s in [&store_key[..], b"hunter2", b"Tr0ub4dor", &file[..]] {
                for sub in [crate::versions(d), d.join("net")] {
                    assert!(!holds(&sub, s), "{}: a secret", d.display());
                }
            }
        }
        let sd = Store::open(&desk, PW, None).unwrap();
        assert_eq!(&sd.get("mail/work").unwrap()[..], b"hunter2\nuser: me");
    }

    /// A replaced key file's hardware files go; a bare key file is still taken.
    #[tokio::test]
    async fn pairing_brings_the_hardware_keys() {
        let d = crate::tests::dir("pairing-keys");
        let (phone, desk) = (d.join("phone"), d.join("desk"));
        let s = Store::create(&phone, b"pw", None).unwrap();
        s.put("a", b"1").unwrap();
        let (c, yk) = ([7; 32], [9; 20]);
        s.quick_on(b"2468", &c, &yk).unwrap();
        let salt = s.fido_salt();
        let (one, two) = ([1; 32], [2; 32]);
        s.fido_add(&salt, &[3; 64], true, &one).unwrap();
        s.fido_add(&salt, &[4; 64], false, &two).unwrap();
        drop(s);
        let other = Store::create(&desk, b"old", None).unwrap();
        other.quick_on(b"", &c, &yk).unwrap();
        let old = fs::read(desk.join("key")).unwrap();
        drop(other);
        let quick = fs::read(phone.join("quick")).unwrap();
        let got = offer(&phone, "desk").unwrap();
        assert!(!got.windows(quick.len()).any(|w| w == quick), "quick sent");
        let text = fs::read_to_string(phone.join("ctap")).unwrap();
        let packed = crate::ctap_packed(&text).unwrap();
        assert!(packed.len() < text.len() * 6 / 10, "ctap packed");
        let got = unqr(&qr(&got, "ab").await.unwrap(), "ab").await.unwrap();
        take(&desk, "phone", &got).unwrap();
        for f in ["key", "ctap"] {
            assert_eq!(
                fs::read(desk.join(f)).unwrap(),
                fs::read(phone.join(f)).unwrap()
            );
        }
        assert_eq!(fs::read(desk.join("key.old")).unwrap(), old);
        // Quick unlock stays on its device; desk's own held the old key.
        assert!(!desk.join("quick").exists());
        Store::open_quick(&phone, b"2468", &yk).unwrap();
        Store::open_fido(&desk, &[3; 64], &one).unwrap();
        Store::open_fido(&desk, &[4; 64], &two).unwrap();
        let lap = d.join("lap");
        Store::create(&lap, b"pw3", None).unwrap();
        let got = offer(&lap, "desk").unwrap();
        assert!(got.ends_with(&fs::read(lap.join("key")).unwrap()));
        take(&desk, "lap", &got).unwrap();
        assert!(!desk.join("quick").exists() && !desk.join("ctap").exists());
        Store::open(&desk, b"pw3", None).unwrap();
        assert!(
            take(&desk, "x", &[got[..64].to_vec(), KEYS.to_vec()].concat())
                .is_err()
        );
    }

    #[test]
    fn a_device_says_no_control_character() {
        assert_eq!(clean(" my phone/\x1b]0;x\x07\t1 "), "my-phone-]0;x-1");
    }

    /// The name stays last on its line, where 0.4.12 reads it.
    #[test]
    fn off_until_on_and_a_month_apart_is_said() {
        let d = crate::tests::dir("apart");
        let (a, b) = (d.join("a"), d.join("b"));
        Store::create(&a, b"pw", None).unwrap();
        assert!(!on(&a) && !on(&b));
        pair(&a, "a", &b, "b");
        assert!(on(&a) && on(&b));
        set_on(&b, false).unwrap();
        set_on(&b, false).unwrap();
        assert!(!on(&b) && on(&a));
        assert_eq!(apart(&b), [("a".to_string(), 0, false)]);
        assert!(unseen(&b).is_empty());
        let mut ps = peers(&b);
        ps[0].seen = Some(now() - 31 * 86_400);
        save(&b, &ps).unwrap();
        assert_eq!(unseen(&b), [("a".to_string(), 31)]);
        let line = fs::read_to_string(net(&b).join("peers")).unwrap();
        assert_eq!(line.trim_end().split(' ').next_back(), Some("a"));
        ps[0].at =
            vec!["10.0.0.2:7".parse().unwrap(), "[::1]:8".parse().unwrap()];
        save(&b, &ps).unwrap();
        assert_eq!(peers(&b)[0].at, ps[0].at);
        assert_eq!(peers(&b)[0].seen, ps[0].seen);
        // Before `seen`: the file's own date.
        let old: Vec<&str> = line.split(' ').collect();
        let old = [&old[..3], &old[5..]].concat().join(" ");
        fs::write(net(&b).join("peers"), old).unwrap();
        assert_eq!(peers(&b)[0].seen, None);
        assert!(unseen(&b).is_empty());
        let f = fs::File::options().write(true).open(net(&b).join("peers"));
        let then =
            std::time::SystemTime::now() - Duration::from_secs(40 * 86_400);
        f.unwrap().set_modified(then).unwrap();
        assert_eq!(unseen(&b), [("a".to_string(), 40)]);
    }

    /// 70,000 names: past a stream's 2 MiB window.
    #[tokio::test(flavor = "multi_thread")]
    async fn long_lists_cross() {
        let d = crate::tests::dir("lists");
        let (a, b) = (d.join("a"), d.join("b"));
        Store::create(&a, b"pw", None).unwrap();
        pair(&a, "a", &b, "b");
        for (side, x) in [(&a, 0u32), (&b, 1)] {
            fs::create_dir_all(crate::versions(side)).unwrap();
            for i in 0..70_000u32 {
                let n = format!("{x:08x}{i:024x}");
                fs::File::create(crate::versions(side).join(n)).unwrap();
            }
        }
        let go = swap_once(&a, &b, "b", "a", ALPN);
        let took = timeout(Duration::from_secs(120), go).await;
        assert_eq!(took.expect("the lists never crossed"), (0, 0));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sync_and_revoke() {
        let d = crate::tests::dir("sync");
        let (a, b, c) = (d.join("a"), d.join("b"), d.join("c"));
        let mut sa = Store::create(&a, b"pw", None).unwrap();
        pair(&a, "a", &b, "b");
        pair(&a, "a", &c, "c");
        sa.put("x", b"1").unwrap();
        Store::open(&b, b"pw", None).unwrap().put("y", b"2").unwrap();
        fs::write(crate::versions(&a).join("stray"), b"editor backup").unwrap();
        // a listens: whoever it dials learns its lane, to wake it there.
        set_mailbox(&a, SecretKey::from_bytes(&[3; 32]).public()).unwrap();
        // An older peer, on pasa/6, still syncs; then nothing differs.
        // From b: y, and b said in the store as it opened (`DEVICES`).
        assert_eq!(swap_once(&a, &b, "b", "a", ALPN6).await, (2, 1));
        assert_eq!(swap_once(&a, &b, "b", "a", ALPN).await, (0, 0));
        let at = peers(&b).into_iter().find(|p| p.name == "a").unwrap().lane;
        assert!(at.is_some_and(|l| l.secret == lane(&a).unwrap()));
        let at = peers(&a).into_iter().find(|p| p.name == "b").unwrap().at;
        assert!(!at.is_empty(), "a dials b direct next time");
        swap_once(&a, &c, "c", "a", ALPN).await;
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
        swap_once(&a, &c, "c", "a", ALPN).await;
        assert_eq!(names(&c), ["x", "y"], "z only once paired again");
        pair(&a, "a", &c, "c");
        assert!(c.join("key.old").exists(), "the key file it had");
        assert_eq!(names(&c), ["x", "y", "z"]);
    }
}
