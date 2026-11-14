//! Group stores: no password; each device a key of its own, made where it
//! lives and never sent. Authority runs from the group's creator (its root)
//! down a strict order: the root, then admins in the order they were made.
//! Admins sign member records, removals and envelopes (the store keys
//! sealed to every member, an age file in `v/`). A device follows the chain
//! of keys from the root, one epoch at a time, each checked against the
//! records under the keys before it; where two compete, the higher signer's
//! wins. PLAN.md has the design and why.

use crate::{
    MAX, Secret, Store, Version, frame, name_of, rand, unframe, write,
};
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
const INFO: &[u8] = b"pasa group keys 2";
/// Every signature's context: none is taken for another protocol's.
const CTX: &[u8] = b"pasa group 2";
/// What an envelope's first stanza line starts with.
const ENVELOPE: &[u8] = b"age-encryption.org/v1\n-> pasa-xwing ";
pub(crate) const MEMBERS: &str = ".pasa/members/";
pub(crate) const REMOVED: &str = ".pasa/removed/";

/// A bundle: X-Wing, Ed25519 and ML-DSA-65 public keys.
const XPK: usize = 1216;
const EDPK: usize = 32;

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
    let h = Sha256::new().chain_update(b"pasa group 2 ").chain_update(what);
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

#[cfg(test)]
pub(crate) fn bundle_of(seed: &[u8]) -> Vec<u8> {
    Keys::of(seed).bundle()
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

/// An envelope: the chain's keys, newest first, at `epoch`, built on `prev`
/// (the id of the key before, "" at the root's first), signed.
struct Envelope {
    epoch: u64,
    prev: String,
    keys: Vec<Secret>,
    to: Vec<String>,
    signer: String,
    bundle: Vec<u8>,
}

fn key_id(k: &[u8]) -> String {
    HEXLOWER.encode(&Sha256::digest([b"pasa key ", k].concat())[..16])
}

/// An envelope sealed to `me`, its signature holding.
fn envelope(me: &Me, ct: &[u8]) -> Option<Envelope> {
    let d = age::Decryptor::new_buffered(ct).ok()?;
    let mut pt = Zeroizing::new(vec![]);
    let r = d.decrypt(std::iter::once(me as &dyn age::Identity)).ok()?;
    r.take(MAX as u64).read_to_end(&mut pt).ok()?;
    let (f, signer, bundle) = opened(b"k2", &pt, 4)?;
    let epoch = text(&f[0]).parse().ok()?;
    let keys: Vec<Secret> =
        f[3].chunks(32).map(|k| Zeroizing::new(k.to_vec())).collect();
    (!keys.is_empty() && f[3].len() % 32 == 0).then_some(())?;
    let to = text(&f[2]).split(',').map(String::from).collect();
    Some(Envelope { epoch, prev: text(&f[1]), keys, to, signer, bundle })
}

#[derive(Clone)]
pub struct Member {
    pub id: String,
    pub name: String,
    pub admin: bool,
    /// Its sync endpoint in this group's folder, hex, or "-".
    pub node: String,
    /// The admin that signed its record.
    pub by: String,
    /// The epoch its record was signed at: an admin's rank, after the root.
    since: u64,
    bundle: Vec<u8>,
}

/// Who may do what, as the records under a chain's keys say.
#[derive(Default)]
struct Auth {
    root: String,
    /// Valid records, removed or not.
    all: HashMap<String, Member>,
    /// Removals: the epoch from which each one's signatures count for nothing.
    removed: HashMap<String, u64>,
}

impl Auth {
    /// An admin's rank: lower outranks. None: no admin (now, at `epoch`).
    fn rank(&self, id: &str, epoch: u64) -> Option<(u64, String)> {
        let m = self.all.get(id)?;
        if self.removed.get(id).is_some_and(|&e| e <= epoch) {
            return None;
        }
        match (id == self.root, m.admin) {
            (true, _) => Some((0, String::new())),
            (false, true) => Some((m.since + 1, id.into())),
            _ => None,
        }
    }

    fn members(&self) -> Vec<Member> {
        let live = |m: &&Member| !self.removed.contains_key(&m.id);
        self.all.values().filter(live).cloned().collect()
    }
}

/// This device's sync endpoint for the store in `dir`, hex.
fn own_node(dir: &Path) -> String {
    #[cfg(feature = "sync")]
    if let Ok(n) = crate::sync::node(dir) {
        return n;
    }
    let _ = dir;
    "-".into()
}

impl Store {
    /// A new group store in `dir`, this device its root, `name`.
    pub fn create_group(dir: &Path, name: &str) -> Result<Store> {
        ensure!(ON, OFF);
        let fresh = !["key", "member"].iter().any(|f| dir.join(f).exists());
        ensure!(fresh, "{} holds a store", dir.display());
        let keys = vec![Zeroizing::new(rand::<32>().to_vec())];
        let mut s = Store::new(dir, keys, Default::default(), vec![])?;
        let seed = Zeroizing::new(rand::<32>().to_vec());
        s.root = Some(Keys::of(&seed).id());
        s.member = Some(seed);
        let me = s.keys_mine()?;
        s.record(&me.bundle(), name, true, &own_node(dir))?;
        s.seal_keys()?;
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
    /// joined: the chain of keys from the root's first, each envelope signed
    /// by an admin of the records under the keys before it; at each epoch
    /// the highest signer's.
    pub(crate) fn open_member(
        dir: &Path,
        seed: &[u8],
        root: &str,
    ) -> Result<Store> {
        let k = Keys::of(seed);
        let me = Me(&k.x.0, k.id());
        let mut all: Vec<Envelope> = vec![];
        for e in fs::read_dir(crate::versions(dir))?.flatten() {
            let Ok(b) = fs::read(e.path()) else { continue };
            // Its own name, as every version: none in another's place.
            if e.file_name().to_str() != Some(&name_of(&b)) || !is_envelope(&b)
            {
                continue;
            }
            all.extend(envelope(&me, &b));
        }
        let first = |e: &&Envelope| {
            e.epoch == 0 && e.prev.is_empty() && e.signer == root
        };
        let mut at = all
            .iter()
            .filter(first)
            .min_by(|a, b| a.keys[0][..].cmp(&b.keys[0][..]));
        ensure!(
            at.is_some(),
            "no keys here for this device yet: sync, once an admin has added it"
        );
        let mut keys: Vec<Secret> = vec![];
        let mut s = None;
        let mut lost = 0;
        while let Some(e) = at {
            keys.insert(0, e.keys[0].clone());
            let mut st =
                Store::new(dir, keys.clone(), Default::default(), vec![])?;
            (st.member, st.root, st.epoch) = (
                Some(Zeroizing::new(seed.to_vec())),
                Some(root.into()),
                e.epoch,
            );
            let auth = st.auth()?;
            let ours =
                |c: &&Envelope| c.keys[0] == e.keys[0] && c.epoch == e.epoch;
            st.sealed_to =
                all.iter().filter(ours).flat_map(|c| c.to.clone()).collect();
            // The next: built on this key, by an admin of these records,
            // the highest; the lowest key between equals.
            let prev = key_id(&e.keys[0]);
            let next: Vec<&Envelope> = all
                .iter()
                .filter(|c| c.epoch == e.epoch + 1 && c.prev == prev)
                .collect();
            let them: HashSet<&[u8]> =
                next.iter().map(|c| &c.keys[0][..]).collect();
            lost += them.len().saturating_sub(1);
            let ranked: Vec<(&Envelope, (u64, String))> = next
                .into_iter()
                .filter_map(|c| Some((c, auth.rank(&c.signer, c.epoch)?)))
                .filter(|(c, _)| {
                    auth.all
                        .get(&c.signer)
                        .is_some_and(|m| m.bundle == c.bundle)
                })
                .collect();
            at = ranked
                .into_iter()
                .min_by(|a, b| {
                    a.1.cmp(&b.1).then(a.0.keys[0][..].cmp(&b.0.keys[0][..]))
                })
                .map(|r| r.0);
            s = Some(st);
        }
        let mut s = s.context("no keys")?;
        if lost > 0 {
            s.unopened.push(format!(
                "{lost} key(s) made beside the one taken (a higher admin's, \
                 or one removed): a change made with one may need making again"
            ));
        }
        Ok(s)
    }

    /// Records under this store's keys (its own and its frozen history),
    /// the newest of each, held to the order from the root.
    fn auth(&self) -> Result<Auth> {
        let root = self.root.clone().context("not a group store")?;
        let mut newest: BTreeMap<String, Version> = BTreeMap::new();
        for v in self.versions_here()? {
            if (v.name.starts_with(MEMBERS) || v.name.starts_with(REMOVED))
                && v.size > 0
            {
                newest.insert(v.name.clone(), v);
            }
        }
        let mut members = vec![];
        let mut removals = vec![];
        for (n, v) in &newest {
            let Ok(b) = self.body(v) else { continue };
            if let Some(id) = n.strip_prefix(MEMBERS) {
                let Some((f, signer, sb)) = opened(b"m2", &b, 5) else {
                    continue;
                };
                let m = Member {
                    id: id.into(),
                    name: text(&f[0]),
                    admin: f[1] == b"admin",
                    since: text(&f[2]).parse().unwrap_or(u64::MAX),
                    node: text(&f[3]),
                    by: signer,
                    bundle: f[4].clone(),
                };
                if id_of(&m.bundle) == id
                    && Pk::from_bytes(&m.bundle[..XPK.min(m.bundle.len())])
                        .is_ok()
                {
                    members.push((m, sb));
                }
            } else if let Some(id) = n.strip_prefix(REMOVED) {
                let Some((f, signer, sb)) = opened(b"r2", &b, 1) else {
                    continue;
                };
                let Ok(e) = text(&f[0]).parse::<u64>() else { continue };
                removals.push((id.to_string(), e, signer, sb));
            }
        }
        // To a fixed point: records valid by valid admins; removals by those
        // who outrank their subject (or by it, leaving); repeat as removals
        // void the signatures of those removed.
        let mut a = Auth { root: root.clone(), ..Default::default() };
        for _ in 0..16 {
            let mut all: HashMap<String, Member> = HashMap::new();
            let self_signed = members
                .iter()
                .find(|(m, _)| m.id == root && m.by == root && m.admin);
            if let Some((m, _)) = self_signed {
                all.insert(root.clone(), m.clone());
            }
            loop {
                let before = all.len();
                for (m, sb) in &members {
                    if all.contains_key(&m.id) {
                        continue;
                    }
                    let a2 = Auth {
                        root: root.clone(),
                        all: all.clone(),
                        removed: a.removed.clone(),
                    };
                    let by = a2.rank(&m.by, m.since).and(all.get(&m.by));
                    if by.is_some_and(|s| s.bundle == *sb) {
                        all.insert(m.id.clone(), m.clone());
                    }
                }
                if all.len() == before {
                    break;
                }
            }
            let a2 = Auth {
                root: root.clone(),
                all: all.clone(),
                removed: a.removed.clone(),
            };
            let mut removed = HashMap::new();
            for (id, e, signer, sb) in &removals {
                let Some(s) = all.get(signer).filter(|s| s.bundle == *sb)
                else {
                    continue;
                };
                let outranks = match (a2.rank(signer, *e), a2.rank(id, *e)) {
                    (Some(r), Some(o)) => r < o,
                    (Some(_), None) => true,
                    _ => false,
                };
                if (outranks || signer == id)
                    && all.contains_key(id)
                    && s.id == *signer
                {
                    let at = removed.entry(id.clone()).or_insert(*e);
                    *at = (*at).min(*e);
                }
            }
            let done = removed == a.removed && all.len() == a.all.len();
            (a.all, a.removed) = (all, removed);
            if done {
                break;
            }
        }
        Ok(a)
    }

    /// Members, valid and not removed.
    pub fn members(&self) -> Result<Vec<Member>> {
        let mut m = self.auth()?.members();
        m.sort_by(|a, b| (a.since, &a.name).cmp(&(b.since, &b.name)));
        Ok(m)
    }

    /// Whether this device may change membership.
    pub fn is_admin(&self) -> bool {
        let (Some(me), Ok(a)) = (self.member_id(), self.auth()) else {
            return false;
        };
        a.rank(&me, self.epoch).is_some()
    }

    pub(crate) fn record(
        &self,
        bundle: &[u8],
        name: &str,
        admin: bool,
        node: &str,
    ) -> Result<()> {
        let bad = [name, node].iter().any(|f| f.chars().any(char::is_control));
        ensure!(!bad && !name.trim().is_empty(), "a bad name");
        let role: &[u8] = if admin { b"admin" } else { b"member" };
        let epoch = self.epoch.to_string();
        let b = signed(
            b"m2",
            &[name.as_bytes(), role, epoch.as_bytes(), node.as_bytes(), bundle],
            &self.keys_mine()?,
        )?;
        self.put(&format!("{MEMBERS}{}", id_of(bundle)), &b)
    }

    /// An envelope of every key to every member, signed by this admin.
    fn seal_keys(&mut self) -> Result<()> {
        let ms = self.members()?;
        let to: Vec<&Member> = ms.iter().collect();
        let ids: Vec<String> = ms.iter().map(|m| m.id.clone()).collect();
        let prev = self.keys.get(1).map(|k| key_id(k)).unwrap_or_default();
        let keys: Vec<u8> = self.keys.iter().flat_map(|k| k.to_vec()).collect();
        let epoch = self.epoch.to_string();
        let pt = Zeroizing::new(signed(
            b"k2",
            &[
                epoch.as_bytes(),
                prev.as_bytes(),
                ids.join(",").as_bytes(),
                &keys,
            ],
            &self.keys_mine()?,
        )?);
        let ct = seal_to(&to, &pt)?;
        write(&self.v.join(name_of(&ct)), &ct)?;
        self.sealed_to = ids;
        Ok(())
    }

    /// Admits the device whose request pairing secret `psk` opens, named
    /// `name`, if not removed. Its id.
    fn admit(
        &mut self,
        name: &str,
        bundle: &[u8],
        node: &str,
    ) -> Result<String> {
        let id = id_of(bundle);
        let a = self.auth()?;
        ensure!(
            !a.removed.contains_key(&id),
            "{name}: removed from this group"
        );
        if !a.all.contains_key(&id) {
            self.record(bundle, name, false, node)?;
        }
        Ok(id)
    }

    /// For pairing a device in: the group's root, if this device is an admin
    /// (an admin signs the record of the device it pairs, once it asks).
    pub fn invite(&self) -> Result<String> {
        ensure!(ON, OFF);
        ensure!(self.is_admin(), "only an admin adds devices");
        Ok(self.root().context("not a group store")?.into())
    }

    /// Makes member `who` an admin, ranked after this one.
    pub fn promote(&mut self, who: &str) -> Result<()> {
        let m = self.one(who)?;
        ensure!(ON, OFF);
        ensure!(self.is_admin(), "only an admin makes admins");
        self.record(&m.bundle, &m.name, true, &m.node)
    }

    fn one(&self, who: &str) -> Result<Member> {
        let ms = self.members()?;
        let m: Vec<&Member> =
            ms.iter().filter(|m| m.id == who || m.name == who).collect();
        ensure!(m.len() == 1, "{who}: no such member, or several");
        Ok(m[0].clone())
    }

    /// Removes member `who` (its id, or its name) and rotates: the new key
    /// is sealed to the rest alone. Its id.
    pub fn remove_member(&mut self, who: &str) -> Result<String> {
        let m = self.one(who)?;
        let me = self.member_id().context("not a group store")?;
        ensure!(m.id != me, "this device: leave by unlinking");
        let a = self.auth()?;
        let next = self.epoch + 1;
        let outranks = match (a.rank(&me, next), a.rank(&m.id, next)) {
            (Some(r), Some(o)) => r < o,
            (Some(_), None) => true,
            _ => false,
        };
        ensure!(outranks, "{}: only an admin above it removes it", m.name);
        self.removal(&m.id, next)?;
        self.rotate_members()?;
        self.forget_removed()?;
        Ok(m.id)
    }

    fn removal(&self, id: &str, epoch: u64) -> Result<()> {
        let e = epoch.to_string();
        let b = signed(b"r2", &[e.as_bytes()], &self.keys_mine()?)?;
        self.put(&format!("{REMOVED}{id}"), &b)
    }

    /// This device leaves: its removal, signed by itself; an admin's next
    /// open rotates the key past it.
    pub(crate) fn leave(&self) -> Result<()> {
        let me = self.member_id().context("not a group store")?;
        let a = self.auth()?;
        let others = a
            .members()
            .iter()
            .any(|m| m.id != me && a.rank(&m.id, self.epoch + 1).is_some());
        ensure!(
            self.root() != Some(&me) || others,
            "the group's root leaves once another member is an admin"
        );
        self.removal(&me, self.epoch + 1)
    }

    /// A new key at the next epoch, sealed to the members.
    pub(crate) fn rotate_members(&mut self) -> Result<()> {
        self.rotate()?;
        self.epoch += 1;
        self.seal_keys()
    }

    /// An admin's work after a sync: requests admitted, a member removed
    /// while the newest key is sealed to it rotated past, members since
    /// sealed to. Nothing on a device no admin, or removed.
    pub(crate) fn settle(&mut self) -> Result<()> {
        if self.retired() || !self.is_admin() {
            return self.forget_removed();
        }
        let mut added = false;
        for (name, bundle, node) in self.requests()? {
            if let Ok(id) = self.admit(&name, &bundle, &node) {
                added |= !self.sealed_to.contains(&id);
            }
        }
        let ids: HashSet<String> =
            self.members()?.into_iter().map(|m| m.id).collect();
        if self.sealed_to.iter().any(|i| !ids.contains(i)) {
            self.rotate_members()?;
        } else if added || ids.iter().any(|i| !self.sealed_to.contains(i)) {
            self.seal_keys()?;
        }
        self.forget_removed()
    }

    /// Requests in `v/` from devices this one paired: a bundle and a node,
    /// sealed to the pairing's secret, which only the two hold.
    fn requests(&self) -> Result<Vec<(String, Vec<u8>, String)>> {
        #[cfg(feature = "sync")]
        {
            let peers = crate::sync::peers(&self.dir);
            if peers.is_empty() {
                return Ok(vec![]);
            }
            let x = self.index()?;
            let known: HashSet<String> =
                x.heads.keys().chain(x.old.keys()).cloned().collect();
            drop(x);
            let mut out = vec![];
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
                    let (Some(kind), Some(bundle), Some(node)) =
                        (unframe(&mut at), unframe(&mut at), unframe(&mut at))
                    else {
                        continue;
                    };
                    if kind == b"j2" {
                        out.push((p.name.clone(), bundle.to_vec(), text(node)));
                    }
                }
            }
            return Ok(out);
        }
        #[allow(unreachable_code)]
        Ok(vec![])
    }

    /// No pairing here with a removed member's device: it fetched sealed
    /// files and could fill the disk; it now reaches nobody of the group.
    fn forget_removed(&self) -> Result<()> {
        #[cfg(feature = "sync")]
        {
            let a = self.auth()?;
            let held: HashSet<String> =
                a.members().into_iter().map(|m| m.node).collect();
            let mine = own_node(&self.dir);
            for id in a.removed.keys() {
                let Some(m) = a.all.get(id) else { continue };
                if m.node != "-" && m.node != mine && !held.contains(&m.node) {
                    crate::sync::forget_node(&self.dir, &m.node)?;
                }
            }
        }
        Ok(())
    }
}

/// A device's request to join, sealed to the pairing secret `psk`: its
/// bundle and node, for the admin that paired it to sign.
pub(crate) fn request(seed: &[u8], psk: &[u8], node: &str) -> Result<Vec<u8>> {
    let mut b = vec![];
    frame(&mut b, b"j2");
    frame(&mut b, &Keys::of(seed).bundle());
    frame(&mut b, node.as_bytes());
    crate::seal(psk, &b)
}

/// The device's node, for a request.
pub(crate) fn node_of(dir: &Path) -> String {
    own_node(dir)
}
