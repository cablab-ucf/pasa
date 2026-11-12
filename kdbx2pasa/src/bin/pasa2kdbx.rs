//! `pasa dump` to KDBX4: entries as they are now (no history), files attached.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use anyhow::{Context, Result, ensure};
use keepass::config::KdfConfig;
use keepass::db::{GroupMut, Value};
use keepass::{Database, DatabaseKey};
use pasa::{FILES, Form};
use std::collections::BTreeMap;
use std::io::Read;

const KDF: (u64, u64) = if cfg!(test) { (1 << 20, 1) } else { (256 << 20, 4) };

#[derive(Default)]
struct Group {
    groups: BTreeMap<String, Group>,
    entries: BTreeMap<String, Item>,
}

#[derive(Default)]
struct Item {
    text: String,
    at: u64,
    files: Vec<(String, Vec<u8>)>,
}

impl Group {
    fn item(&mut self, name: &str) -> &mut Item {
        let (dirs, title) = name.rsplit_once('/').unwrap_or(("", name));
        let dirs = dirs.split('/').filter(|d| !d.is_empty());
        let g = dirs.fold(self, |g, d| g.groups.entry(d.into()).or_default());
        g.entries.entry(title.into()).or_default()
    }
}

/// Hidden names other than `NAME/.files/` (`.kdbx.json`) stay out.
fn read(tar: impl Read) -> Result<Group> {
    let mut root = Group::default();
    for e in tar::Archive::new(tar).entries()? {
        let mut e = e?;
        if !e.header().entry_type().is_file() {
            continue;
        }
        let name = e.path()?.to_string_lossy().into_owned();
        let at = e.header().mtime().unwrap_or(0);
        let mut b = vec![];
        e.read_to_end(&mut b)?;
        match name.split_once(FILES) {
            Some((n, f)) => root.item(n).files.push((f.into(), b)),
            None if name.split('/').any(|c| c.starts_with('.')) => {}
            None => {
                let it = root.item(&name);
                it.text = String::from_utf8(b).with_context(|| name.clone())?;
                it.at = at;
            }
        }
    }
    Ok(root)
}

/// `key: value` lines; an indented line continues the value.
fn fields(more: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = vec![];
    for l in more.lines() {
        match (l.strip_prefix("  "), out.last_mut()) {
            (Some(rest), Some(last)) => last.1 = format!("{}\n{rest}", last.1),
            _ => {
                if let Some((k, v)) = l.split_once(':') {
                    out.push((k.trim().into(), v.trim_start().into()));
                }
            }
        }
    }
    out
}

/// `YYYY-MM-DD` at midnight.
fn day(s: &str) -> Option<chrono::NaiveDateTime> {
    let mut d = s.trim().splitn(3, '-').map(|p| p.parse::<u32>().ok());
    let (y, m, d) = (d.next()??, d.next()??, d.next()??);
    chrono::NaiveDate::from_ymd_opt(y as i32, m, d)?.and_hms_opt(0, 0, 0)
}

fn fill(g: &mut GroupMut, from: &Group) {
    for (title, it) in &from.entries {
        let f = Form::parse(&it.text);
        let mut e = g.add_entry();
        e.set_unprotected("Title", title.as_str());
        e.set_unprotected("UserName", f.user.as_str());
        e.set_protected("Password", f.pass.as_str());
        e.set_unprotected("URL", f.url.as_str());
        e.set_unprotected("Notes", f.notes.as_str());
        if !f.otp.is_empty() {
            e.set_protected("otp", f.otp.as_str());
        }
        for (k, v) in fields(&f.more) {
            e.set_unprotected(k, v);
        }
        let tags = f.tags.split(',').map(str::trim).filter(|t| !t.is_empty());
        e.tags = tags.map(String::from).collect();
        if let Some(t) = day(&f.expires) {
            (e.times.expiry, e.times.expires) = (t, Some(true));
        }
        let at = chrono::DateTime::from_timestamp(it.at as i64, 0);
        let at = at.map(|t| t.naive_utc()).filter(|_| it.at > 0);
        (e.times.creation, e.times.last_modification) = (at, at);
        for (n, b) in &it.files {
            e.add_attachment(n.as_str(), Value::protected(b.clone()));
        }
    }
    for (name, sub) in &from.groups {
        let mut s = g.add_group();
        s.name = name.clone();
        fill(&mut s, sub);
    }
}

/// Argon2id at pasa's strength, not KeePass's default 1 MiB.
fn database(root: &Group) -> Database {
    let mut db = Database::new();
    if let KdfConfig::Argon2 { version, .. } = &db.config.kdf_config {
        let (memory, iterations) = KDF;
        let version = *version;
        db.config.kdf_config =
            KdfConfig::Argon2id { iterations, memory, parallelism: 4, version };
    }
    let mut r = db.root_mut();
    r.name = "pasa".into();
    fill(&mut r, root);
    db
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let [out] = &a[..] else {
        anyhow::bail!("usage: pasa dump | pasa2kdbx OUT.kdbx")
    };
    let db = database(&read(std::io::stdin().lock())?);
    let pw = rpassword::prompt_password("New KeePass password: ")?;
    ensure!(!pw.is_empty(), "no password");
    ensure!(pw == rpassword::prompt_password("Again: ")?, "they differ");
    let mut o = std::fs::OpenOptions::new();
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f =
        o.write(true).create_new(true).open(out).context(out.clone())?;
    db.save(&mut f, DatabaseKey::new().with_password(&pw))?;
    Ok(f.sync_all()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn a_dump_opens_as_a_keepass_database() {
        let mut t = tar::Builder::new(vec![]);
        let mut add = |name: &str, at: u64, body: &[u8]| {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mtime(at);
            h.set_mode(0o600);
            t.append_data(&mut h, name, body).unwrap();
        };
        let mail = "hunter2\nuser: ada\nurl: https://mail.example\n\
                    otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\n\
                    tags: work, mail\nexpires: 2030-01-31\n\
                    pin: 1234\nrecovery: a\n  b\n\nfirst note\nsecond";
        add("mail/work", 86_400, mail.as_bytes());
        add("mail/work/.files/key.pem", 86_400, b"PEM");
        add("bank", 0, b"Tr0ub4dor&3\n");
        add(".kdbx.json", 0, b"{}");
        let tar = t.into_inner().unwrap();
        let p = std::env::temp_dir()
            .join(format!("pasa2kdbx-{}", std::process::id()));
        let key = || DatabaseKey::new().with_password("kdbx");
        let db = database(&read(&tar[..]).unwrap());
        db.save(&mut File::create(&p).unwrap(), key()).unwrap();
        let db = Database::open(&mut File::open(&p).unwrap(), key()).unwrap();
        std::fs::remove_file(&p).unwrap();
        assert!(matches!(db.config.kdf_config, KdfConfig::Argon2id { .. }));
        let root = db.root();
        assert_eq!(root.name, "pasa");
        let titles: Vec<_> =
            root.entries().map(|e| e.get_title().map(String::from)).collect();
        assert_eq!(titles, [Some("bank".into())], ".kdbx.json stays out");
        let mail = root.groups().find(|g| g.name == "mail").unwrap();
        let e = mail.entries().next().unwrap();
        let get = |k: &str| e.get(k).unwrap_or_default().to_string();
        assert_eq!(e.get_title(), Some("work"));
        assert_eq!(e.get_password(), Some("hunter2"));
        assert_eq!(get("UserName"), "ada");
        assert_eq!(get("URL"), "https://mail.example");
        assert!(get("otp").starts_with("otpauth://totp/"));
        assert_eq!(
            (get("pin"), get("recovery")),
            ("1234".into(), "a\nb".into())
        );
        assert_eq!(get("Notes"), "first note\nsecond");
        assert_eq!(e.tags, ["work", "mail"]);
        assert_eq!(e.times.expires, Some(true));
        assert_eq!(e.times.expiry, day("2030-01-31").unwrap());
        assert_eq!(e.times.last_modification, day("1970-01-02"));
        let files: Vec<_> = e
            .attachments_named()
            .map(|(n, a)| (n.to_string(), a.data.to_vec()))
            .collect();
        assert_eq!(files, [("key.pem".to_string(), b"PEM".to_vec())]);
    }
}
