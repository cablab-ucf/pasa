//! Group stores: a key pair per device (X-Wing), and the store keys sealed
//! to every member's in an age file in `v/` (an envelope), which syncs as
//! any version. Removing a member is a rotation sealed to the rest: nobody
//! pairs again, and no group password exists to change.

use crate::{Secret, Store, name_of, rand, write};
use age_core::format::{FileKey, Stanza};
use anyhow::{Context, Result, ensure};
use data_encoding::HEXLOWER;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use hpke::{
    aead::ChaCha20Poly1305 as Aead, kdf::HkdfSha256 as Kdf, kem::XWing,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

const TAG: &str = "pasa-xwing";
const INFO: &[u8] = b"pasa group keys 1";
const HEAD: &[u8] = b"pasa keys\n";
/// What an envelope's first stanza line starts with.
const ENVELOPE: &[u8] = b"age-encryption.org/v1\n-> pasa-xwing ";
/// `MEMBERS` + id: name, line; who added it (an id, or -), line; public key.
pub(crate) const MEMBERS: &str = ".pasa/members/";

type Sk = <XWing as Kem>::PrivateKey;
type Pk = <XWing as Kem>::PublicKey;
type Enc = <XWing as Kem>::EncappedKey;

fn public(seed: &[u8]) -> Vec<u8> {
    XWing::derive_keypair(seed).1.to_bytes().to_vec()
}

fn id_of(pk: &[u8]) -> String {
    HEXLOWER.encode(&Sha256::digest(pk)[..8])
}

pub(crate) fn is_envelope(head: &[u8]) -> bool {
    head.starts_with(ENVELOPE)
}

/// A member's public key, as an age recipient.
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
struct Me(Sk, String);

impl age::Identity for Me {
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
            &self.0,
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

/// The store keys, newest first, sealed to each public key.
fn seal(pks: &[Vec<u8>], keys: &[Secret]) -> Result<Vec<u8>> {
    let mut to = vec![];
    for pk in pks {
        to.push(To(
            Pk::from_bytes(pk).ok().context("a bad member key")?,
            id_of(pk),
        ));
    }
    let to = to.iter().map(|t| t as &dyn age::Recipient);
    let e = age::Encryptor::with_recipients(to)?;
    let mut out = vec![];
    let mut w = e.wrap_output(&mut out)?;
    std::io::Write::write_all(&mut w, HEAD)?;
    keys.iter().try_for_each(|k| std::io::Write::write_all(&mut w, k))?;
    w.finish()?;
    Ok(out)
}

/// An envelope's keys and the members it is sealed to, if it is to `me`.
fn open(me: &Me, ct: &[u8]) -> Option<(Vec<Secret>, Vec<String>)> {
    let d = age::Decryptor::new_buffered(ct).ok()?;
    let mut pt = Zeroizing::new(vec![]);
    let r = d.decrypt(std::iter::once(me as &dyn age::Identity)).ok()?;
    r.take(crate::MAX as u64).read_to_end(&mut pt).ok()?;
    let keys = pt.strip_prefix(HEAD)?;
    if keys.is_empty() || keys.len() % 32 != 0 {
        return None;
    }
    // The ids sealed to: each stanza's line, in the header.
    let head = ct.split(|&b| b == b'\n').take_while(|l| !l.starts_with(b"---"));
    let ids = head
        .filter_map(|l| l.strip_prefix(format!("-> {TAG} ").as_bytes()))
        .map(|id| String::from_utf8_lossy(id).into_owned())
        .collect();
    let keys = keys.chunks(32).map(|k| Zeroizing::new(k.to_vec())).collect();
    Some((keys, ids))
}

pub struct Member {
    pub id: String,
    pub name: String,
    /// The id of the member that added it, or "-".
    pub by: String,
    pk: Vec<u8>,
}

impl Store {
    /// A new group store in `dir`, its first member this device, `name`.
    /// No password: its members open it, each with a key of its own.
    pub fn create_group(dir: &Path, name: &str) -> Result<Store> {
        let fresh = !dir.join("key").exists() && !dir.join("member").exists();
        ensure!(fresh, "{} holds a store", dir.display());
        let keys = vec![Zeroizing::new(rand::<32>().to_vec())];
        let mut s = Store::new(dir, keys, Default::default(), vec![])?;
        s.member = Some(Zeroizing::new(rand::<32>().to_vec()));
        s.record(&s.my_key()?, name, "-")?;
        s.seal_keys()?;
        Ok(s)
    }

    /// The group store in `dir`, by this device's member key: every
    /// envelope to it, its keys newest first.
    /// `known`: the newest key this device held: an envelope counts only
    /// if it holds that one too, so no key comes from a member removed
    /// before it was made (it never had the one before).
    /// `handed`: the key pairing handed, kept to open what was sealed to it
    /// before this device's own was known (its record is gone: no new
    /// key is sealed to it).
    pub(crate) fn open_member(
        dir: &Path,
        seed: &[u8],
        known: Option<&[u8]>,
        handed: Option<&[u8]>,
    ) -> Result<Store> {
        let me: Vec<Me> = std::iter::once(seed)
            .chain(handed)
            .map(|s| {
                let (sk, pk) = XWing::derive_keypair(s);
                Me(sk, id_of(&pk.to_bytes()))
            })
            .collect();
        let mut found: Vec<(Vec<Secret>, Vec<String>)> = vec![];
        let mut other = vec![];
        for e in fs::read_dir(crate::versions(dir))?.flatten() {
            let Ok(b) = fs::read(e.path()) else { continue };
            let mine = |me| is_envelope(&b).then(|| open(me, &b)).flatten();
            let Some(f) = me.iter().find_map(mine) else { continue };
            match known.is_none_or(|k| f.0.iter().any(|m| m[..] == *k)) {
                true => found.push(f),
                false => other.push(f),
            }
        }
        // Not built on the known key: older (its newest key is known), or
        // a fork, which counts for nothing and is said.
        let held = |k: &Secret| found.iter().any(|f| f.0.contains(k));
        let forks = other.iter().filter(|f| !held(&f.0[0])).count();
        ensure!(
            !found.is_empty(),
            "no keys here for this device yet: sync, once the member that \
             added it has"
        );
        // The longest list first: each rotation's holds every key before.
        found.sort_by_key(|f| std::cmp::Reverse(f.0.len()));
        let inner = |k: &Secret| found.iter().any(|f| f.0[1..].contains(k));
        let mut keys: Vec<Secret> = vec![];
        // Heads: newest keys no other envelope knows of. Two mean two
        // rotations at once: both are current until the next rotation.
        let mut heads: Vec<&Secret> =
            found.iter().map(|f| &f.0[0]).filter(|k| !inner(k)).collect();
        heads.sort_by(|a, b| a[..].cmp(&b[..]));
        heads.dedup();
        keys.extend(heads.iter().map(|k| (*k).clone()));
        for k in found.iter().flat_map(|f| &f.0) {
            if !keys.contains(k) {
                keys.push(k.clone());
            }
        }
        let current = heads.len().max(1);
        // Whom the newest keys are sealed to: every envelope of theirs.
        let newest = |f: &&(Vec<Secret>, Vec<String>)| heads.contains(&&f.0[0]);
        let mut sealed_to: Vec<String> =
            found.iter().filter(newest).flat_map(|f| f.1.clone()).collect();
        sealed_to.sort();
        sealed_to.dedup();
        let mut s = Store::new(dir, keys, Default::default(), vec![])?;
        (s.member, s.current, s.sealed_to) =
            (Some(Zeroizing::new(seed.to_vec())), current, sealed_to);
        s.handed = handed.map(|h| Zeroizing::new(h.to_vec()));
        if forks > 0 {
            s.unopened.push(format!(
                "{forks} key(s) not built on this device's: a removed \
                 member's, or two removals at once (remove again here)"
            ));
        }
        Ok(s)
    }

    fn my_key(&self) -> Result<Vec<u8>> {
        Ok(public(self.member.as_ref().context("not a group store")?))
    }

    /// This device's id in the group.
    pub fn member_id(&self) -> Option<String> {
        self.member.as_ref().map(|s| id_of(&public(s)))
    }

    /// Members, but any ever removed: a removal is never undone, so two
    /// rotations at once merge to what neither removed.
    pub fn members(&self) -> Result<Vec<Member>> {
        let gone: HashSet<String> = (self.versions_here()?.into_iter())
            .filter(|v| v.size == 0)
            .filter_map(|v| v.name.strip_prefix(MEMBERS).map(Into::into))
            .collect();
        let mut out = vec![];
        for n in self.live(MEMBERS)? {
            let Some(id) = n.strip_prefix(MEMBERS) else { continue };
            if gone.contains(id) {
                continue;
            }
            let b = self.get(&n)?;
            let mut l = b.splitn(3, |&c| c == b'\n');
            let (name, by) =
                (l.next().unwrap_or_default(), l.next().unwrap_or_default());
            let pk = l.next().unwrap_or_default().to_vec();
            if id_of(&pk) == id {
                let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
                out.push(Member {
                    id: id.into(),
                    name: s(name),
                    by: s(by),
                    pk,
                });
            }
        }
        Ok(out)
    }

    fn record(&self, pk: &[u8], name: &str, by: &str) -> Result<()> {
        ensure!(!name.contains('\n') && !by.contains('\n'), "a bad name");
        let body = [format!("{name}\n{by}\n").as_bytes(), pk].concat();
        self.put(&format!("{MEMBERS}{}", id_of(pk)), &body)
    }

    /// An envelope of every key to every member.
    fn seal_keys(&mut self) -> Result<()> {
        let ms = self.members()?;
        let pks: Vec<Vec<u8>> = ms.iter().map(|m| m.pk.clone()).collect();
        let ct = seal(&pks, &self.keys)?;
        write(&self.v.join(name_of(&ct)), &ct)?;
        self.sealed_to = ms.into_iter().map(|m| m.id).collect();
        Ok(())
    }

    /// A member key for a device named `name`, which pairing hands it; it
    /// makes one of its own once it opens the store.
    pub fn add_member(&mut self, name: &str) -> Result<Secret> {
        let me = self.member_id().context("not a group store")?;
        let seed = Zeroizing::new(rand::<32>().to_vec());
        self.record(&public(&seed), name, &me)?;
        self.seal_keys()?;
        Ok(seed)
    }

    /// Removes member `id` (or the one named so) and rotates: the new key is
    /// sealed to the rest alone.
    pub fn remove_member(&mut self, who: &str) -> Result<String> {
        let ms = self.members()?;
        let gone: Vec<&Member> =
            ms.iter().filter(|m| m.id == who || m.name == who).collect();
        ensure!(gone.len() == 1, "{who}: no such member, or several");
        let gone = gone[0].id.clone();
        ensure!(
            Some(&gone) != self.member_id().as_ref(),
            "this device: leave by unlinking"
        );
        self.put(&format!("{MEMBERS}{gone}"), b"")?;
        self.rotate_members(
            &ms.iter().filter(|m| m.id != gone).collect::<Vec<_>>(),
        )?;
        Ok(gone)
    }

    /// A new key, then the members recorded anew under it and sealed to.
    pub(crate) fn rotate_members(&mut self, keep: &[&Member]) -> Result<()> {
        self.rotate()?;
        self.current = 1;
        for m in keep {
            self.record(&m.pk, &m.name, &m.by)?;
        }
        self.seal_keys()
    }

    /// A key of this device's own for the one pairing handed it: the old
    /// one's record goes. The new seed, for the caller to keep sealed.
    pub(crate) fn rekey(&mut self) -> Result<Secret> {
        let old = self.my_key()?;
        let ms = self.members()?;
        let me =
            ms.iter().find(|m| m.pk == old).context("not a member here")?;
        let seed = Zeroizing::new(rand::<32>().to_vec());
        self.handed = self.member.replace(seed.clone());
        self.claim(&me.name.clone(), &id_of(&old))?;
        Ok(seed)
    }

    /// This device's key recorded in place of `old` (`by`: ~old), and sealed.
    fn claim(&mut self, name: &str, old: &str) -> Result<()> {
        self.record(&self.my_key()?, name, &format!("~{old}"))?;
        self.put(&format!("{MEMBERS}{old}"), b"")?;
        self.seal_keys()
    }

    /// After a sync: a member removed while the newest key is sealed to it,
    /// or two rotations at once, rotate again; a member added since, seal.
    pub(crate) fn settle(&mut self) -> Result<()> {
        let Some(me) = self.member_id() else { return Ok(()) };
        let ms = self.members()?;
        let ids: HashSet<&String> = ms.iter().map(|m| &m.id).collect();
        // On a retired key: nothing to seal, never a key.
        if self.retired() {
            return Ok(());
        }
        if !ids.contains(&me) {
            // Known by the handed key alone (this one's own was recorded
            // under a key since retired): claim it anew. Else removed.
            let h = self.handed.as_ref().map(|h| id_of(&public(h)));
            let Some(h) = h.filter(|h| ids.contains(h)) else { return Ok(()) };
            let name = ms.iter().find(|m| m.id == h).map(|m| m.name.clone());
            self.claim(&name.unwrap_or_default(), &h)?;
            return self.settle();
        }
        // A key replaced by its holder's own (~id) is no removal.
        let replaced: HashSet<&str> =
            ms.iter().filter_map(|m| m.by.strip_prefix('~')).collect();
        let gone = (self.sealed_to.iter())
            .any(|i| !ids.contains(i) && !replaced.contains(i.as_str()));
        if gone || self.current > 1 {
            return self.rotate_members(&ms.iter().collect::<Vec<_>>());
        }
        if ids.iter().any(|i| !self.sealed_to.contains(i)) {
            self.seal_keys()?;
        }
        Ok(())
    }
}
