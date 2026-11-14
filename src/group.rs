//! Group stores: no password; each device a key of its own, made where it
//! lives and never sent. An envelope (an age file in `v/`: the store keys
//! sealed to every member) carries the member list and the hash of the one
//! before it, signed by an admin of that one: authority runs from the
//! group's creator (its root) down this chain alone, never from files that
//! any key holder could write. Admins rank by age; of two forks, the one a
//! higher admin signed in holds. PLAN.md has the design and why.

use crate::{MAX, Secret, Store, frame, name_of, rand, unframe, write};
use age_core::format::{FileKey, Stanza};
use anyhow::{Context, Result, anyhow, ensure};
use data_encoding::HEXLOWER;
use ed25519_dalek::{Signer, Verifier};
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use hpke::{
    aead::ChaCha20Poly1305 as Aead, kdf::HkdfSha256 as Kdf, kem::XWing,
};
use ml_dsa::MlDsa65;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

/// Off until reviewed again (PLAN.md). A group already held keeps opening;
/// none is made, joined or added to.
pub const ON: bool = cfg!(test);
pub const OFF: &str = "per-device groups are not on yet: their signed \
    design is to be reviewed first (PLAN.md); a store linked with its \
    password works";

const TAG: &str = "pasa-xwing";
const INFO: &[u8] = b"pasa group keys 3";
/// Every signature's context: none is taken for another protocol's.
const CTX: &[u8] = b"pasa group 3";
/// What an envelope's first stanza line starts with.
const ENVELOPE: &[u8] = b"age-encryption.org/v1\n-> pasa-xwing ";
/// Copies of envelope bodies, named by their hashes, each the link of the
/// envelope after: a device added later reads the chain from the root.
const CHAIN: &str = ".pasa/chain/";
/// Names this admin paired in and has not admitted: its own, never synced.
const INVITES: &str = "invites";

/// The most an envelope, a link or a request may take: a list of ~300
/// members; junk costs no more than this to read.
const MOST: u64 = 1 << 20;

/// A bundle: X-Wing, Ed25519 and ML-DSA-65 public keys.
const XPK: usize = 1216;
const EDPK: usize = 32;
const BUNDLE: usize = XPK + EDPK + 1952;

type Sk = <XWing as Kem>::PrivateKey;
type Pk = <XWing as Kem>::PublicKey;
type Enc = <XWing as Kem>::EncappedKey;

pub(crate) fn is_envelope(head: &[u8]) -> bool {
    head.starts_with(ENVELOPE)
}

/// A device's keys in a group, all from its seed.
struct Keys {
    x: (Sk, Pk),
    ed: ed25519_dalek::SigningKey,
    dsa: ml_dsa::SigningKey<MlDsa65>,
}

fn part(seed: &[u8], what: &[u8]) -> [u8; 32] {
    let h = Sha256::new().chain_update(b"pasa group 3 ").chain_update(what);
    h.chain_update(seed).finalize().into()
}

impl Keys {
    fn of(seed: &[u8]) -> Keys {
        Keys {
            x: XWing::derive_keypair(&part(seed, b"x-wing")),
            ed: ed25519_dalek::SigningKey::from_bytes(&part(seed, b"ed25519")),
            dsa: ml_dsa::SigningKey::from_seed(&part(seed, b"ml-dsa").into()),
        }
    }

    fn bundle(&self) -> Vec<u8> {
        let dsa = self.dsa.expanded_key().verifying_key().encode();
        let ed = self.ed.verifying_key().to_bytes();
        [&self.x.1.to_bytes()[..], &ed[..], dsa.as_slice()].concat()
    }

    fn id(&self) -> String {
        id_of(&self.bundle())
    }

    /// Ed25519 and ML-DSA-65 over `m`: both must hold.
    fn sign(&self, m: &[u8]) -> Result<Vec<u8>> {
        let a = self.ed.sign(&[CTX, m].concat()).to_bytes();
        let b = self.dsa.expanded_key().sign_deterministic(m, CTX);
        let b = b.map_err(|_| anyhow!("ml-dsa"))?;
        Ok([&a[..], b.encode().as_slice()].concat())
    }
}

fn id_of(bundle: &[u8]) -> String {
    HEXLOWER.encode(&Sha256::digest(bundle)[..16])
}

/// Both of `bundle`'s signatures over `m`.
fn verify(bundle: &[u8], m: &[u8], sig: &[u8]) -> bool {
    let ed = || {
        let k = bundle.get(XPK..XPK + EDPK)?.try_into().ok()?;
        let k = ed25519_dalek::VerifyingKey::from_bytes(k).ok()?;
        let s = ed25519_dalek::Signature::from_bytes(
            sig.get(..64)?.try_into().ok()?,
        );
        k.verify(&[CTX, m].concat(), &s).ok()
    };
    let dsa = || {
        let k = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(
            bundle.get(XPK + EDPK..)?,
        )
        .ok()?;
        let k = ml_dsa::VerifyingKey::<MlDsa65>::decode(&k);
        let s = ml_dsa::EncodedSignature::<MlDsa65>::try_from(sig.get(64..)?)
            .ok()?;
        let s = ml_dsa::Signature::<MlDsa65>::decode(&s)?;
        k.verify_with_context(m, CTX, &s).then_some(())
    };
    ed().is_some() && dsa().is_some()
}

/// `kind`, `fields`, signer's id and bundle, then their signature.
fn signed(kind: &[u8], fields: &[&[u8]], k: &Keys) -> Result<Vec<u8>> {
    let mut b = vec![];
    frame(&mut b, kind);
    fields.iter().for_each(|f| frame(&mut b, f));
    frame(&mut b, k.id().as_bytes());
    frame(&mut b, &k.bundle());
    let sig = k.sign(&b)?;
    frame(&mut b, &sig);
    Ok(b)
}

/// A signed thing's fields, signer and signer's bundle, if `kind` and its
/// signature by that bundle hold.
fn opened(
    kind: &[u8],
    b: &[u8],
    n: usize,
) -> Option<(Vec<Vec<u8>>, String, Vec<u8>)> {
    let mut at = b;
    (unframe(&mut at)? == kind).then_some(())?;
    let fields: Vec<Vec<u8>> = (0..n)
        .map(|_| unframe(&mut at).map(<[u8]>::to_vec))
        .collect::<Option<_>>()?;
    let signer = String::from_utf8(unframe(&mut at)?.to_vec()).ok()?;
    let bundle = unframe(&mut at)?.to_vec();
    let body = &b[..b.len() - at.len()];
    let sig = unframe(&mut at)?;
    (at.is_empty() && id_of(&bundle) == signer && verify(&bundle, body, sig))
        .then_some(())?;
    Some((fields, signer, bundle))
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A member's public keys, as an age recipient.
struct To(Pk, String);

impl age::Recipient for To {
    fn wrap_file_key(
        &self,
        k: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        use age::secrecy::ExposeSecret;
        let (enc, ct) = hpke::single_shot_seal::<Aead, Kdf, XWing>(
            &OpModeS::Base,
            &self.0,
            INFO,
            k.expose_secret(),
            self.1.as_bytes(),
        )
        .map_err(|e| age::EncryptError::Io(std::io::Error::other(e)))?;
        let body = [&enc.to_bytes()[..], &ct].concat();
        let s = Stanza { tag: TAG.into(), args: vec![self.1.clone()], body };
        Ok((vec![s], HashSet::new()))
    }
}

/// This device's key, as an age identity.
struct Me<'a>(&'a Sk, String);

impl age::Identity for Me<'_> {
    fn unwrap_stanza(
        &self,
        s: &Stanza,
    ) -> Option<Result<FileKey, age::DecryptError>> {
        if s.tag != TAG || s.args.first() != Some(&self.1) {
            return None;
        }
        let bad = || Some(Err(age::DecryptError::DecryptionFailed));
        let n = <Enc as Serializable>::size();
        let Some((enc, ct)) = s.body.split_at_checked(n) else { return bad() };
        let Ok(enc) = Enc::from_bytes(enc) else { return bad() };
        let Ok(k) = hpke::single_shot_open::<Aead, Kdf, XWing>(
            &OpModeR::Base,
            self.0,
            &enc,
            INFO,
            ct,
            self.1.as_bytes(),
        ) else {
            return bad();
        };
        let Ok(k) = <[u8; 16]>::try_from(&k[..]) else { return bad() };
        Some(Ok(FileKey::new(Box::new(k))))
    }
}

/// `pt` sealed to each member's X-Wing key.
fn seal_to(to: &[&Member], pt: &[u8]) -> Result<Vec<u8>> {
    let mut rs = vec![];
    for m in to {
        let pk = Pk::from_bytes(m.bundle.get(..XPK).context("a bad key")?);
        rs.push(To(pk.ok().context("a bad key")?, m.id.clone()));
    }
    let e = age::Encryptor::with_recipients(
        rs.iter().map(|t| t as &dyn age::Recipient),
    )?;
    let mut out = vec![];
    let mut w = e.wrap_output(&mut out)?;
    std::io::Write::write_all(&mut w, pt)?;
    w.finish()?;
    Ok(out)
}

/// A name as a pairing takes it.
fn sane(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && !n.contains(['\n', '/', ' '])
        && !n.chars().any(char::is_control)
}

#[derive(Clone, PartialEq)]
pub struct Member {
    pub id: String,
    pub name: String,
    pub admin: bool,
    /// The admin that added it.
    pub by: String,
    /// The epoch it joined, or (an admin) was made admin: its rank.
    since: u64,
    bundle: Vec<u8>,
}

fn list_bytes(ms: &[Member]) -> Vec<u8> {
    let mut b = vec![];
    for m in ms {
        let since = m.since.to_string();
        let role: &[u8] = if m.admin { b"admin" } else { b"member" };
        for f in [m.name.as_bytes(), role, since.as_bytes(), m.by.as_bytes()] {
            frame(&mut b, f);
        }
        frame(&mut b, &m.bundle);
    }
    b
}

fn list_of(mut b: &[u8]) -> Option<Vec<Member>> {
    let mut ms: Vec<Member> = vec![];
    while !b.is_empty() {
        let mut f = || unframe(&mut b).map(<[u8]>::to_vec);
        let (name, role, since, by, bundle) = (f()?, f()?, f()?, f()?, f()?);
        let name = String::from_utf8(name).ok().filter(|n| sane(n))?;
        let admin = match &role[..] {
            b"admin" => true,
            b"member" => false,
            _ => return None,
        };
        let since = text(&since).parse().ok()?;
        let ok =
            bundle.len() == BUNDLE && Pk::from_bytes(&bundle[..XPK]).is_ok();
        let id = id_of(&bundle);
        (ok && !ms.iter().any(|m| m.id == id || m.name == name))
            .then_some(())?;
        ms.push(Member { id, name, admin, by: text(&by), since, bundle });
    }
    Some(ms)
}

/// An envelope: every key, newest first, and the members at `epoch`,
/// built on envelope `prev` ("" at the root's first), signed.
struct Envelope {
    epoch: u64,
    prev: String,
    /// The file in `v/` holding `prev`'s body, under one of the two newest
    /// keys: the way back to the root, for a device added since.
    link: String,
    list: Vec<Member>,
    keys: Vec<Secret>,
    signer: String,
    bundle: Vec<u8>,
    hash: String,
    body: Secret,
}

fn envelope(pt: &[u8]) -> Option<Envelope> {
    let (f, signer, bundle) = opened(b"k3", pt, 5)?;
    let keys: Vec<Secret> =
        f[4].chunks(32).map(|k| Zeroizing::new(k.to_vec())).collect();
    (!keys.is_empty() && f[4].len() % 32 == 0).then_some(())?;
    Some(Envelope {
        epoch: text(&f[0]).parse().ok()?,
        prev: text(&f[1]),
        link: text(&f[2]),
        list: list_of(&f[3])?,
        keys,
        signer,
        bundle,
        hash: HEXLOWER.encode(&Sha256::digest(pt)),
        body: Zeroizing::new(pt.to_vec()),
    })
}

/// The envelope `n` is built on, from its link's bytes `ct`, if they hold
/// it (under either of `n`'s own two newest keys).
fn linked(ct: &[u8], n: &Envelope) -> Option<Envelope> {
    let pt = n.keys.iter().take(2).find_map(|k| crate::open(k, ct))?;
    let at = pt.iter().position(|&c| c == b'\n')?;
    let v = crate::Version::parse(std::str::from_utf8(&pt[..at]).ok()?, "")?;
    let body = pt.get(at + 1..)?.get(..v.size)?;
    (HEXLOWER.encode(&Sha256::digest(body)) == n.prev).then_some(())?;
    envelope(body)
}

/// A file of at most [`MOST`] bytes.
fn small(p: &Path) -> Option<Vec<u8>> {
    let f = fs::File::open(p).ok()?;
    (f.metadata().ok()?.len() <= MOST).then_some(())?;
    let mut b = vec![];
    f.take(MOST).read_to_end(&mut b).ok()?;
    Some(b)
}

/// An age file's plaintext, if sealed to `me`.
fn unsealed(me: &Me, ct: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let d = age::Decryptor::new_buffered(ct).ok()?;
    let mut pt = Zeroizing::new(vec![]);
    let r = d.decrypt(std::iter::once(me as &dyn age::Identity)).ok()?;
    r.take(MAX as u64).read_to_end(&mut pt).ok()?;
    Some(pt)
}

/// An admin's rank in `list`: lower outranks; the root first.
fn rank(list: &[Member], root: &str, id: &str) -> Option<(u64, String)> {
    let m = list.iter().find(|m| m.id == id && m.admin)?;
    Some(match id == root {
        true => (0, String::new()),
        false => (m.since.saturating_add(1), id.into()),
    })
}

/// The root's first envelope: the root alone.
fn genesis(e: &Envelope, root: &str) -> bool {
    let only = |m: &Member| {
        m.id == root
            && m.admin
            && m.since == 0
            && m.by == root
            && m.bundle == e.bundle
    };
    e.epoch == 0
        && e.prev.is_empty()
        && e.signer == root
        && matches!(&e.list[..], [m] if only(m))
}

/// Whether `n` may follow `p`: signed by an admin of `p`, the keys kept,
/// the root kept, an admin,
/// every member kept as it was but for what that admin may change: one it
/// outranks removed or demoted, a member made admin (ranked
/// last), devices added by it.
fn follows(p: &Envelope, n: &Envelope, root: &str) -> bool {
    let Some(r) = rank(&p.list, root, &n.signer) else { return false };
    let signer =
        p.list.iter().any(|m| m.id == n.signer && m.bundle == n.bundle);
    let keys = n.keys == p.keys || n.keys.get(1..) == Some(&p.keys[..]);
    let may_drop =
        |m: &Member| rank(&p.list, root, &m.id).is_none_or(|o| r < o);
    let kept =
        p.list.iter().all(|m| match n.list.iter().find(|x| x.id == m.id) {
            None => may_drop(m),
            Some(x) => {
                x.name == m.name && x.by == m.by && x.bundle == m.bundle && {
                    match (m.admin, x.admin) {
                        (false, true) => x.since == n.epoch,
                        (true, false) => x.since == m.since && may_drop(m),
                        _ => x.since == m.since,
                    }
                }
            }
        });
    let new = |x: &&Member| !p.list.iter().any(|m| m.id == x.id);
    let added = n
        .list
        .iter()
        .filter(new)
        .all(|x| x.by == n.signer && x.since == n.epoch);
    p.epoch.checked_add(1) == Some(n.epoch)
        && n.prev == p.hash
        && signer
        && keys
        && kept
        && added
        && n.list.iter().any(|m| m.id == root && m.admin)
}

/// A group store's view, from its chain.
#[derive(Default)]
pub(crate) struct State {
    epoch: u64,
    /// The newest envelope's hash.
    head: String,
    list: Vec<Member>,
    /// Who has held the newest key: every member of an envelope with it.
    known: HashSet<String>,
    /// Every device the chain has held.
    ever: HashSet<String>,
    /// Members removed along the chain.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    gone: Vec<Member>,
    /// Members asking to leave.
    leaves: Vec<String>,
    /// The newest envelope's body: the next one links a copy.
    body: Secret,
    /// Removals this device signed on a fork set aside: made again, where
    /// it still may.
    redo: Vec<String>,
}

impl Store {
    /// A new group store in `dir`, this device its root, `name`.
    pub fn create_group(dir: &Path, name: &str) -> Result<Store> {
        ensure!(ON, OFF);
        ensure!(sane(name), "{name}: a bad name");
        let fresh = !["key", "member"].iter().any(|f| dir.join(f).exists());
        ensure!(fresh, "{} holds a store", dir.display());
        let keys = vec![Zeroizing::new(rand::<32>().to_vec())];
        let mut s = Store::new(dir, keys, Default::default(), vec![])?;
        let seed = Zeroizing::new(rand::<32>().to_vec());
        let k = Keys::of(&seed);
        let id = k.id();
        (s.root, s.member) = (Some(id.clone()), Some(seed));
        let me = Member {
            id: id.clone(),
            name: name.into(),
            admin: true,
            by: id,
            since: 0,
            bundle: k.bundle(),
        };
        s.seal_envelope(0, String::new(), vec![me])?;
        Ok(s)
    }

    fn keys_mine(&self) -> Result<Keys> {
        Ok(Keys::of(self.member.as_ref().context("not a group store")?))
    }

    /// This device's id in the group.
    pub fn member_id(&self) -> Option<String> {
        self.member.as_ref().map(|s| Keys::of(s).id())
    }

    /// The group's id: its root's.
    pub fn root(&self) -> Option<&str> {
        self.root.as_deref()
    }

    /// The group store in `dir`, by this device's seed and the root it
    /// joined: every envelope sealed to it, checked from the root's first;
    /// removals applied, highest remover first; then the chain followed,
    /// the highest admin's at each step.
    pub(crate) fn open_member(
        dir: &Path,
        seed: &[u8],
        root: &str,
    ) -> Result<Store> {
        let k = Keys::of(seed);
        let me = Me(&k.x.0, k.id());
        let mut found: Vec<Envelope> = vec![];
        let mut asks = vec![];
        for e in fs::read_dir(crate::versions(dir))?.flatten() {
            let mut head = [0; ENVELOPE.len()];
            let Ok(mut f) = fs::File::open(e.path()) else { continue };
            if f.read_exact(&mut head).is_err() || !is_envelope(&head) {
                continue;
            }
            let Some(b) = small(&e.path()) else { continue };
            // Its own name, as every version: none in another's place.
            if e.file_name().to_str() != Some(&name_of(&b)) {
                continue;
            }
            let Some(pt) = unsealed(&me, &b) else { continue };
            if let Some(n) = envelope(&pt) {
                found.push(n);
            } else if let Some((f, id, bundle)) = opened(b"l3", &pt, 1) {
                (f[0] == root.as_bytes()).then(|| asks.push((id, bundle)));
            }
        }
        // Back to the root by links: each file read once.
        let mut all: BTreeMap<String, Envelope> = BTreeMap::new();
        let mut linked_ok: HashSet<String> = HashSet::new();
        // A file's bytes, not what one envelope made of them: each tries
        // them with its own keys.
        let mut read: HashMap<String, Option<Vec<u8>>> = HashMap::new();
        while let Some(n) = found.pop() {
            if all.contains_key(&n.hash) {
                continue;
            }
            if !n.link.is_empty() {
                let ct = read.entry(n.link.clone()).or_insert_with(|| {
                    let b = small(&crate::versions(dir).join(&n.link))?;
                    (name_of(&b) == n.link).then_some(b)
                });
                if let Some(p) = ct.as_deref().and_then(|ct| linked(ct, &n)) {
                    linked_ok.insert(n.hash.clone());
                    if !all.contains_key(&p.hash) {
                        found.push(p);
                    }
                }
            }
            all.insert(n.hash.clone(), n);
        }
        // Valid: the root's first, then each by an admin of the one before;
        // with its signer's rank there.
        let mut order: Vec<&Envelope> = all.values().collect();
        order.sort_by_key(|e| e.epoch);
        let mut valid: HashMap<&str, (u64, String)> = HashMap::new();
        for n in &order {
            let r = match all.get(&n.prev) {
                Some(p)
                    if valid.contains_key(p.hash.as_str())
                        && linked_ok.contains(&n.hash) =>
                {
                    rank(&p.list, root, &n.signer)
                        .filter(|_| follows(p, n, root))
                }
                None if genesis(n, root) => Some((0, String::new())),
                _ => None,
            };
            if let Some(r) = r {
                valid.insert(&n.hash, r);
            }
        }
        // Each one's best: the highest signer in it and all built on it. Of
        // two forks, the one a higher admin signed in holds: a removed
        // admin's fork, made before its removal or after, loses to the
        // branch holding the removal; a losing fork changes nothing in the
        // other.
        let mut best = valid.clone();
        for n in order.iter().rev() {
            let Some(b) = best.get(n.hash.as_str()).cloned() else { continue };
            if let Some(p) = best.get_mut(n.prev.as_str()) {
                *p = p.clone().min(b);
            }
        }
        let key = |e: &&Envelope| {
            let h = e.hash.as_str();
            (best[h].clone(), valid[h].clone(), e.hash.clone())
        };
        let ok = |e: &&Envelope| valid.contains_key(e.hash.as_str());
        let mut at = all
            .values()
            .filter(|e| e.epoch == 0 && ok(e))
            .min_by_key(key)
            .context(
                "no keys here for this device yet: sync, once an admin has \
                 added it",
            )?;
        let (mut path, mut held) = (HashSet::new(), vec![]);
        loop {
            held.extend(at.list.iter().cloned());
            path.insert(at.hash.as_str());
            let kids = all.values().filter(|n| n.prev == at.hash && ok(n));
            let Some(n) = kids.min_by_key(key) else { break };
            at = n;
        }
        let mut s =
            Store::new(dir, at.keys.clone(), Default::default(), vec![])?;
        // Keys of forks set aside: what was written with them is not read.
        let mut lost: HashSet<&[u8]> = HashSet::new();
        let aside = |n: &&Envelope| ok(n) && !path.contains(n.hash.as_str());
        for n in all.values().filter(aside) {
            if !at.keys.contains(&n.keys[0]) {
                lost.insert(&n.keys[0]);
            }
        }
        let lost = lost.len();
        (s.member, s.root) =
            (Some(Zeroizing::new(seed.to_vec())), Some(root.into()));
        let ids = |e: &Envelope| {
            e.list.iter().map(|m| m.id.clone()).collect::<Vec<_>>()
        };
        let has = |e: &&Envelope| e.keys.iter().any(|x| *x == at.keys[0]);
        let mut gone: Vec<Member> = vec![];
        for m in held.clone() {
            if !at.list.iter().any(|x| x.id == m.id) && !gone.contains(&m) {
                gone.push(m);
            }
        }
        let member = |id: &String| at.list.iter().any(|m| m.id == *id);
        // Removals this device signed on forks set aside.
        let mut redo = vec![];
        let off = |n: &&Envelope| {
            n.signer == me.1 && ok(n) && !path.contains(n.hash.as_str())
        };
        for n in all.values().filter(off) {
            let Some(p) = all.get(&n.prev) else { continue };
            let out = |m: &&Member| !n.list.iter().any(|x| x.id == m.id);
            redo.extend(p.list.iter().filter(out).map(|m| m.id.clone()));
        }
        s.g = State {
            body: at.body.clone(),
            redo,
            epoch: at.epoch,
            head: at.hash.clone(),
            list: at.list.clone(),
            known: all.values().filter(ok).filter(has).flat_map(ids).collect(),
            ever: held.iter().map(|m| m.id.clone()).collect(),
            gone,
            leaves: asks
                .into_iter()
                .filter(|(id, b)| {
                    member(id) && at.list.iter().any(|m| m.bundle == *b)
                })
                .map(|a| a.0)
                .collect(),
        };
        if lost > 0 {
            s.unopened.push(format!(
                "{lost} key(s) made beside the one taken (a higher admin's, \
                 or one removed): what was written with one is not read here; \
                 make it again"
            ));
        }
        if !at.list.iter().any(|m| m.id == me.1) {
            s.unopened.push("this device is no member of it now".into());
        }
        Ok(s)
    }

    /// Members, the root and admins by rank first.
    pub fn members(&self) -> Result<Vec<Member>> {
        let mut m = self.g.list.clone();
        m.sort_by(|a, b| {
            (!a.admin, a.since, &a.name).cmp(&(!b.admin, b.since, &b.name))
        });
        Ok(m)
    }

    fn rank_of(&self, id: &str) -> Option<(u64, String)> {
        let root = self.root.as_deref()?;
        rank(&self.g.list, root, id)
    }

    /// Whether this device may change membership.
    pub fn is_admin(&self) -> bool {
        self.member_id().is_some_and(|me| self.rank_of(&me).is_some())
    }

    /// Whether this device may remove or demote `id`.
    fn outranks(&self, id: &str) -> bool {
        let me = self.member_id().and_then(|me| self.rank_of(&me));
        me.is_some_and(|r| self.rank_of(id).is_none_or(|o| r < o))
    }

    /// The next envelope, with `list`: under a new key if a device not in
    /// it held the newest (unless this one leaves: then the next admin's).
    fn extend(&mut self, list: Vec<Member>, rotate: bool) -> Result<()> {
        let ids: HashSet<&String> = list.iter().map(|m| &m.id).collect();
        if rotate && self.g.known.iter().any(|i| !ids.contains(i)) {
            self.rotate()?;
            self.g.known.clear();
        }
        let epoch = self.g.epoch.checked_add(1).context("no epoch after")?;
        self.seal_envelope(epoch, self.g.head.clone(), list)
    }

    fn seal_envelope(
        &mut self,
        epoch: u64,
        prev: String,
        list: Vec<Member>,
    ) -> Result<()> {
        self.seal_envelope_to(epoch, prev, list, None)
    }

    /// `to`: the members it is sealed to, if not all (a test's attacker).
    fn seal_envelope_to(
        &mut self,
        epoch: u64,
        prev: String,
        list: Vec<Member>,
        to: Option<&[String]>,
    ) -> Result<()> {
        let keys: Zeroizing<Vec<u8>> = Zeroizing::new(
            self.keys.iter().flat_map(|k| k.iter().copied()).collect(),
        );
        let e = epoch.to_string();
        // The one before, kept under the newest key: whoever sealed it.
        let link = match prev.is_empty() {
            true => String::new(),
            false => {
                let at = format!("{CHAIN}{prev}");
                self.put_on(&at, &self.g.body.clone(), None)?
            }
        };
        let pt = Zeroizing::new(signed(
            b"k3",
            &[
                e.as_bytes(),
                prev.as_bytes(),
                link.as_bytes(),
                &list_bytes(&list),
                &keys,
            ],
            &self.keys_mine()?,
        )?);
        let to: Vec<&Member> = list
            .iter()
            .filter(|m| to.is_none_or(|t| t.contains(&m.id)))
            .collect();
        let ct = seal_to(&to, &pt)?;
        write(&self.v.join(name_of(&ct)), &ct)?;
        let h = HEXLOWER.encode(&Sha256::digest(&pt));
        self.g.body = pt;
        let ids = list.iter().map(|m| m.id.clone());
        self.g.ever.extend(ids.clone());
        self.g.known.extend(ids);
        (self.g.epoch, self.g.head, self.g.list) = (epoch, h, list);
        Ok(())
    }

    /// For pairing device `name` in: the group's root. Its request is
    /// admitted once, at this admin's next open.
    pub fn invite(&self, name: &str) -> Result<String> {
        ensure!(ON, OFF);
        ensure!(self.is_admin(), "only an admin adds devices");
        ensure!(sane(name), "{name}: a bad name");
        let mut i = self.invites();
        i.retain(|n| n != name);
        i.push(name.into());
        write(&self.dir.join(INVITES), i.join("\n").as_bytes())?;
        Ok(self.root().context("not a group store")?.into())
    }

    fn invites(&self) -> Vec<String> {
        let f = fs::read_to_string(self.dir.join(INVITES)).unwrap_or_default();
        f.lines().filter(|l| !l.is_empty()).map(String::from).collect()
    }

    /// Makes member `who` an admin, ranked after every admin now.
    pub fn promote(&mut self, who: &str) -> Result<()> {
        ensure!(ON, OFF);
        ensure!(self.is_admin(), "only an admin makes admins");
        let m = self.one(who)?;
        ensure!(!m.admin, "{}: an admin already", m.name);
        let next = self.g.epoch + 1;
        let mut list = self.g.list.clone();
        list.iter_mut().filter(|x| x.id == m.id).for_each(|x| {
            (x.admin, x.since) = (true, next);
        });
        self.extend(list, true)
    }

    fn one(&self, who: &str) -> Result<Member> {
        let m: Vec<&Member> = self
            .g
            .list
            .iter()
            .filter(|m| m.id == who || m.name == who)
            .collect();
        ensure!(m.len() == 1, "{who}: no such member, or several");
        Ok(m[0].clone())
    }

    /// Removes member `who` (its id, or its name): a new key, sealed to
    /// the rest alone. Its id.
    pub fn remove_member(&mut self, who: &str) -> Result<String> {
        let m = self.one(who)?;
        let me = self.member_id().context("not a group store")?;
        ensure!(m.id != me, "this device: leave by unlinking");
        ensure!(
            self.outranks(&m.id),
            "{}: only an admin above it removes it",
            m.name
        );
        let list =
            self.g.list.iter().filter(|x| x.id != m.id).cloned().collect();
        self.extend(list, true)?;
        Ok(m.id)
    }

    /// This device leaves: its signed request, sealed to the admins; one
    /// that outranks it removes it at its next open (with a new key): a
    /// removal by a higher admin is final, a device's own would not be.
    pub(crate) fn leave(&mut self) -> Result<()> {
        let me = self.member_id().context("not a group store")?;
        // Nobody outranks the root: a leave of its own would not be final.
        ensure!(
            self.root() != Some(&me),
            "the group's root stays in it: to hand it on, make a new group"
        );
        let root = self.root().context("not a group store")?;
        let pt = Zeroizing::new(signed(
            b"l3",
            &[root.as_bytes()],
            &self.keys_mine()?,
        )?);
        let admins: Vec<&Member> =
            self.g.list.iter().filter(|m| m.admin).collect();
        let ct = seal_to(&admins, &pt)?;
        write(&self.v.join(name_of(&ct)), &ct)
    }

    /// An admin's work after a sync: requests admitted, leaving members
    /// removed, a key held by one not a member replaced. Nothing on a device no admin.
    pub(crate) fn settle(&mut self) -> Result<()> {
        if !self.is_admin() {
            return Ok(());
        }
        let me = self.member_id().context("not a group store")?;
        let mut list: Vec<Member> = self.g.list.clone();
        list.retain(|m| {
            !self.g.leaves.contains(&m.id) || !self.outranks(&m.id)
        });
        // A removal or demotion of this device's, lost to a fork made at
        // once: made again.
        for id in &self.g.redo {
            if self.outranks(id) {
                list.retain(|m| m.id != *id);
            }
        }
        for (name, bundle) in self.requests()? {
            let id = id_of(&bundle);
            if !self.g.ever.contains(&id)
                && !list.iter().any(|m| m.name == name)
            {
                let since = self.g.epoch + 1;
                let by = me.clone();
                list.push(Member { id, name, admin: false, by, since, bundle });
            }
        }
        let ids: HashSet<&String> = list.iter().map(|m| &m.id).collect();
        if list != self.g.list || self.g.known.iter().any(|i| !ids.contains(i))
        {
            self.extend(list, true)?;
        }
        // Invitations taken, and pairings with devices gone, forgotten.
        let mut i = self.invites();
        let done =
            |n: &String| self.g.list.iter().any(|m| m.by == me && m.name == *n);
        if i.iter().any(done) {
            i.retain(|n| !done(n));
            write(&self.dir.join(INVITES), i.join("\n").as_bytes())?;
        }
        #[cfg(feature = "sync")]
        for m in &self.g.gone {
            let held = self.g.list.iter().any(|x| x.name == m.name);
            if m.by == me && !held && !i.contains(&m.name) {
                let _ = crate::sync::forget(&self.dir, &m.name);
            }
        }
        Ok(())
    }

    /// Requests in `v/` from devices invited and not yet admitted, sealed
    /// to their pairing's secret, which only the two hold: name, bundle.
    fn requests(&self) -> Result<Vec<(String, Vec<u8>)>> {
        #[cfg(not(feature = "sync"))]
        return Ok(vec![]);
        #[cfg(feature = "sync")]
        {
            let mut out = vec![];
            let invited = self.invites();
            let peers: Vec<crate::sync::Peer> = crate::sync::peers(&self.dir)
                .into_iter()
                .filter(|p| invited.contains(&p.name))
                .collect();
            if peers.is_empty() {
                return Ok(out);
            }
            let x = self.index()?;
            let known: HashSet<String> =
                x.heads.keys().chain(x.old.keys()).cloned().collect();
            drop(x);
            let root = self.root().context("not a group store")?.as_bytes();
            for e in fs::read_dir(&self.v)?.flatten() {
                let f = e.file_name().to_string_lossy().into_owned();
                if known.contains(&f) || !crate::is_name(&f) {
                    continue;
                }
                let Ok(b) = self.bytes(&f) else { continue };
                if is_envelope(&b) {
                    continue;
                }
                for p in &peers {
                    let Some(pt) = crate::open(&p.psk, &b) else { continue };
                    let mut at = &pt[..];
                    // Padded: what follows the frames is nothing.
                    let (Some(b"j3"), Some(r), Some(bundle)) =
                        (unframe(&mut at), unframe(&mut at), unframe(&mut at))
                    else {
                        continue;
                    };
                    let ok = bundle.len() == BUNDLE
                        && Pk::from_bytes(&bundle[..XPK]).is_ok();
                    if r == root && ok {
                        out.push((p.name.clone(), bundle.to_vec()));
                    }
                }
            }
            Ok(out)
        }
    }

    #[cfg(test)]
    pub(crate) fn add_puppet(
        &mut self,
        seed: &[u8],
        admin: bool,
    ) -> Result<()> {
        self.puppet(seed, admin, true)
    }

    /// Junk: an envelope by a stranger for each of `links`, sealed to
    /// every member this device knows, naming that file as its link.
    #[cfg(test)]
    pub(crate) fn junk_naming(&self, links: &[String]) -> Result<()> {
        let k = Keys::of(&rand::<32>());
        let to: Vec<&Member> = self.g.list.iter().collect();
        for l in links {
            let e = (self.g.epoch + 1).to_string();
            let fields: [&[u8]; 5] = [
                e.as_bytes(),
                self.g.head.as_bytes(),
                l.as_bytes(),
                &list_bytes(&self.g.list),
                &rand::<32>(),
            ];
            let ct = seal_to(&to, &signed(b"k3", &fields, &k)?)?;
            write(&self.v.join(name_of(&ct)), &ct)?;
        }
        Ok(())
    }

    /// Removes `who` without a new key, sealed to `to` alone.
    #[cfg(test)]
    pub(crate) fn remove_quietly(
        &mut self,
        who: &str,
        to: &[String],
    ) -> Result<()> {
        let id = self.one(who)?.id;
        let list = self.g.list.iter().filter(|m| m.id != id).cloned().collect();
        let epoch = self.g.epoch + 1;
        self.seal_envelope_to(epoch, self.g.head.clone(), list, Some(to))
    }

    /// A device of this one's making in the next envelope (`key`: under a
    /// new key), whether this one may add it or not.
    #[cfg(test)]
    pub(crate) fn puppet(
        &mut self,
        seed: &[u8],
        admin: bool,
        key: bool,
    ) -> Result<()> {
        let k = Keys::of(seed);
        if key {
            self.rotate()?;
            self.g.known.clear();
        }
        let mut list = self.g.list.clone();
        list.push(Member {
            id: k.id(),
            name: format!("puppet{}", list.len()),
            admin,
            by: self.member_id().context("no member")?,
            since: self.g.epoch + 1,
            bundle: k.bundle(),
        });
        self.extend(list, false)
    }
}

/// A device's request to join group `root`, sealed to the pairing secret
/// `psk`: its public keys, for the admin that paired it to admit.
pub(crate) fn request(seed: &[u8], psk: &[u8], root: &str) -> Result<Vec<u8>> {
    let mut b = vec![];
    frame(&mut b, b"j3");
    frame(&mut b, root.as_bytes());
    frame(&mut b, &Keys::of(seed).bundle());
    crate::seal(psk, &b)
}
