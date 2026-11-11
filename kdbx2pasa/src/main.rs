//! `kdbx2pasa A.kdbx [B.kdbx ...] [-k KEYFILE] | pasa load`: every entry
//! with its history, dated as KeePass dated it, its attachments, and
//! `.kdbx.json` (the first database, whole), as tar.
//!
//! Several databases are copies of one that went apart (sync conflicts):
//! an entry is the same by its id in each, and its versions from all of
//! them make one history by time, the newest being the entry.

use anyhow::{Context, Result};
use keepass::{Database, DatabaseKey, db::Entry, db::GroupRef};
use std::collections::{BTreeMap, HashSet};
use std::{fmt::Write, fs::File};

/// What goes into the tar: a name, a time in seconds, the bytes.
type Item = (String, u64, Vec<u8>);

fn text(e: &Entry) -> Result<String> {
    let mut b = format!("{}\n", e.get_password().unwrap_or(""));
    let mut fields: Vec<_> = e.fields.iter().collect();
    fields.sort_by_key(|f| f.0);
    for (k, v) in fields {
        if !["Title", "Password", "Notes"].contains(&k.as_str())
            && !v.is_empty()
        {
            // A name pasa saves as it is: letters, digits and _.
            let plain =
                |c: char| if c.is_ascii_alphanumeric() { c } else { '_' };
            let k = match k.as_str() {
                "UserName" => "user".into(),
                k => k.to_lowercase().chars().map(plain).collect::<String>(),
            };
            writeln!(b, "{k}: {}", v.trim().replace('\n', "\n  "))?;
        }
    }
    if !e.tags.is_empty() {
        writeln!(b, "tags: {}", e.tags.join(", "))?;
    }
    // An empty line, then the notes: notes whatever they say.
    if let Some(n) = e.get("Notes").filter(|n| !n.is_empty()) {
        writeln!(b, "\n{n}")?;
    }
    Ok(b)
}

fn at(e: &Entry) -> u64 {
    let t = e.times.last_modification.or(e.times.creation);
    t.map_or(0, |t| t.and_utc().timestamp().max(0) as u64)
}

/// One entry as the databases have it: each version (when, where, its
/// text), and the newest one's attachments.
#[derive(Default)]
struct Seen {
    versions: Vec<(u64, String, String)>,
    files: (u64, Vec<(String, Vec<u8>)>),
}

fn walk(
    g: GroupRef,
    dir: &str,
    bin: Option<uuid::Uuid>,
    to: &mut BTreeMap<uuid::Uuid, Seen>,
) -> Result<()> {
    // What was deleted there stays deleted here.
    if Some(g.id().uuid()) == bin {
        return Ok(());
    }
    for e in g.entries() {
        let name = format!("{dir}{}", e.get_title().unwrap_or("untitled"));
        let seen = to.entry(e.id().uuid()).or_default();
        for h in (0..).map_while(|i| e.historical(i)) {
            seen.versions.push((at(&h), name.clone(), text(&h)?));
        }
        seen.versions.push((at(&e), name.clone(), text(&e)?));
        if at(&e) >= seen.files.0 {
            let files = e.attachments_named();
            let files = files.map(|(f, a)| (f.to_string(), a.data.to_vec()));
            seen.files = (at(&e), files.collect());
        }
    }
    for c in g.groups() {
        let dir = format!("{dir}{}/", c.name);
        walk(c, &dir, bin, to)?;
    }
    Ok(())
}

/// The entries of `dbs` as one: each one's versions oldest first, under
/// the name its newest version has.
fn merge(dbs: &[Database]) -> Result<Vec<Item>> {
    let mut seen = BTreeMap::new();
    for db in dbs {
        walk(db.root(), "", db.meta.recyclebin_uuid, &mut seen)?;
    }
    let (mut out, mut names) = (vec![], HashSet::new());
    for mut e in seen.into_values() {
        e.versions.sort();
        // The copies share most versions; a save that changed nothing
        // tells nothing.
        e.versions.dedup_by(|b, a| a.2 == b.2);
        let Some(last) = e.versions.last() else { continue };
        let dots = |c: &str| {
            if c == "." || c == ".." { format!("_{c}") } else { c.into() }
        };
        let name: Vec<String> = last.1.split('/').map(dots).collect();
        // Two entries of one title in one group are two entries here too.
        let free = |i: &u32| match i {
            0 => name.join("/"),
            i => format!("{} ({})", name.join("/"), i + 1),
        };
        let name = (0..).map(|i| free(&i)).find(|n| !names.contains(n));
        let name = name.context("no name")?;
        names.insert(name.clone());
        for (at, _, text) in &e.versions {
            out.push((name.clone(), *at, text.clone().into_bytes()));
        }
        for (f, data) in e.files.1 {
            out.push((format!("{name}/.files/{f}"), e.files.0, data));
        }
    }
    Ok(out)
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let key = a.iter().position(|x| x == "-k").map(|i| a.get(i + 1));
    let dbs = a.iter().filter(|x| *x != "-k" && Some(Some(*x)) != key);
    let dbs: Vec<&String> = dbs.collect();
    let usage = "usage: kdbx2pasa A.kdbx [B.kdbx ...] [-k KEYFILE] | pasa load";
    anyhow::ensure!(!dbs.is_empty() && key != Some(None), usage);
    let pw = rpassword::prompt_password("KeePass password: ")?;
    let open = |db: &&String| {
        let mut k = DatabaseKey::new().with_password(&pw);
        if let Some(Some(f)) = key {
            k = k.with_keyfile(&mut File::open(f)?)?;
        }
        Database::open(&mut File::open(db)?, k).with_context(|| db.to_string())
    };
    let dbs: Vec<Database> = dbs.iter().map(open).collect::<Result<_>>()?;
    let mut items = merge(&dbs)?;
    items.push((".kdbx.json".into(), 0, serde_json::to_vec(&dbs[0])?));
    let mut t = tar::Builder::new(std::io::stdout().lock());
    for (name, at, body) in items {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o600);
        h.set_mtime(at);
        t.append_data(&mut h, name, &body[..])?;
    }
    Ok(t.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;
    use keepass::db::Value;

    /// The entry as it is becomes history; then it is `pw` at `day`.
    fn change(db: &mut Database, id: keepass::db::EntryId, pw: &str, day: i64) {
        let mut root = db.root_mut();
        let mut e = root.entry_mut(id).unwrap();
        let old: Entry = (*e).clone();
        e.history.as_mut().unwrap().add_entry(old);
        e.set("Password", Value::unprotected(pw));
        let t = DateTime::from_timestamp(day * 86_400, 0).unwrap().naive_utc();
        e.times.last_modification = Some(t);
    }

    #[test]
    fn conflict_copies_make_one_history() {
        let mut base = Database::new();
        let mut root = base.root_mut();
        let mut e = root.add_entry();
        e.set("Title", Value::unprotected("mail"));
        e.set("UserName", Value::unprotected("ada"));
        e.times.last_modification =
            DateTime::from_timestamp(0, 0).map(|t| t.naive_utc());
        let id = e.id();
        change(&mut base, id, "one", 1);
        change(&mut base, id, "two", 2);
        // Two devices go on from there, apart.
        let (mut a, mut b) = (base.clone(), base.clone());
        change(&mut a, id, "three-on-a", 3);
        change(&mut b, id, "four-on-b", 4);
        change(&mut a, id, "five-on-a", 5);
        {
            let mut root = b.root_mut();
            let mut moved = root.entry_mut(id).unwrap();
            moved.set("Title", Value::unprotected("post"));
        }
        // As files, as they would come: written, and read back.
        let dir = std::env::temp_dir();
        let filed = |(i, db): (usize, Database)| {
            let key = || DatabaseKey::new().with_password("kdbx");
            let p =
                dir.join(format!("kdbx2pasa-{}-{i}.kdbx", std::process::id()));
            db.save(&mut File::create(&p).unwrap(), key()).unwrap();
            let db = Database::open(&mut File::open(&p).unwrap(), key());
            std::fs::remove_file(p).unwrap();
            db.unwrap()
        };
        let dbs: Vec<Database> =
            [base, a, b].into_iter().enumerate().map(filed).collect();
        let items = merge(&dbs).unwrap();
        let got: Vec<(String, u64, String)> = items
            .into_iter()
            .map(|(n, at, b)| {
                let pw = String::from_utf8(b).unwrap();
                (n, at / 86_400, pw.lines().next().unwrap().to_string())
            })
            .collect();
        // One entry, under its newest version's name; every version once,
        // by time, whichever copy had it; the newest is the entry.
        let want = ["one", "two", "three-on-a", "four-on-b", "five-on-a"];
        let pws: Vec<&str> = got.iter().skip(1).map(|g| &*g.2).collect();
        assert_eq!(pws, want);
        assert!(got.iter().all(|g| g.0 == "mail"), "{got:?}");
        let days: Vec<u64> = got.iter().skip(1).map(|g| g.1).collect();
        assert_eq!(days, [1, 2, 3, 4, 5]);
    }
}
