//! `kdbx2pasa DB.kdbx [KEYFILE] | pasa load`: entries (history first),
//! attachments, and `.kdbx.json` (the whole database), as tar.

use anyhow::{Context, Result};
use keepass::{Database, DatabaseKey, db::Entry, db::GroupRef};
use std::{fmt::Write, fs::File};

type Tar<'a> = tar::Builder<std::io::StdoutLock<'a>>;

fn put(t: &mut Tar, name: &str, b: &[u8]) -> Result<()> {
    let dots = |c: &str| {
        if c == "." || c == ".." { format!("_{c}") } else { c.into() }
    };
    let name = name.split('/').map(dots).collect::<Vec<_>>().join("/");
    let mut h = tar::Header::new_gnu();
    h.set_size(b.len() as u64);
    h.set_mode(0o600);
    Ok(t.append_data(&mut h, name, b)?)
}

fn text(e: &Entry) -> Result<String> {
    let mut b = format!("{}\n", e.get_password().unwrap_or(""));
    let mut fields: Vec<_> = e.fields.iter().collect();
    fields.sort_by_key(|f| f.0);
    for (k, v) in fields {
        if !["Title", "Password", "Notes"].contains(&k.as_str())
            && !v.is_empty()
        {
            let k =
                if k == "UserName" { "user".into() } else { k.to_lowercase() };
            writeln!(b, "{k}: {}", v.replace('\n', "\n  "))?;
        }
    }
    if !e.tags.is_empty() {
        writeln!(b, "tags: {}", e.tags.join(", "))?;
    }
    if let Some(n) = e.get("Notes").filter(|n| !n.is_empty()) {
        writeln!(b, "notes:\n{n}")?;
    }
    Ok(b)
}

fn walk(t: &mut Tar, g: GroupRef, dir: &str) -> Result<()> {
    for e in g.entries() {
        let name = format!("{dir}{}", e.get_title().unwrap_or("untitled"));
        let old = (0..).map_while(|i| e.historical(i));
        for h in old {
            put(t, &name, text(&h)?.as_bytes())?;
        }
        put(t, &name, text(&e)?.as_bytes())?;
        for (f, a) in e.attachments_named() {
            put(t, &format!("{name}/{f}"), &a.data)?;
        }
    }
    for c in g.groups() {
        let d = format!("{dir}{}/", c.name);
        walk(t, c, &d)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let db =
        a.first().context("usage: kdbx2pasa DB.kdbx [KEYFILE] | pasa load")?;
    let pw = rpassword::prompt_password("KeePass password: ")?;
    let mut key = DatabaseKey::new().with_password(&pw);
    if let Some(k) = a.get(1) {
        key = key.with_keyfile(&mut File::open(k)?)?;
    }
    let db = Database::open(&mut File::open(db)?, key)?;
    let mut t = tar::Builder::new(std::io::stdout().lock());
    walk(&mut t, db.root(), "")?;
    put(&mut t, ".kdbx.json", &serde_json::to_vec(&db)?)?;
    Ok(t.finish()?)
}
