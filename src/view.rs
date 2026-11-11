//! What the terminal and the window both show: the names a filter leaves,
//! one of them chosen, and what was last done.

use crate::{aside, clip, record, text};
use anyhow::{Context, Result, ensure};
use pasa::{Secret, Store, field};
use std::time::Duration;

/// A view left alone this long locks.
pub const IDLE: Duration = Duration::from_secs(300);

pub struct View {
    pub s: Store,
    pub filter: String,
    pub names: Vec<String>,
    /// Each name's newest version, by its file: what a cache keys on.
    pub files: Vec<String>,
    /// When each name last changed (ms), and how many files it keeps.
    pub ms: Vec<u64>,
    pub kept: Vec<usize>,
    pub at: usize,
    pub note: String,
}

impl View {
    pub fn new(s: Store) -> View {
        let (filter, note) = Default::default();
        let mut v = View {
            s,
            filter,
            names: vec![],
            files: vec![],
            ms: vec![],
            kept: vec![],
            at: 0,
            note,
        };
        v.load();
        v
    }

    /// The names holding every word of the filter, as `v/` is now.
    pub fn load(&mut self) {
        let f = self.filter.to_lowercase();
        let has = |n: &String| {
            let n = n.to_lowercase();
            !n.split('/').any(|c| c.starts_with('.'))
                && f.split_whitespace().all(|w| n.contains(w))
        };
        let all = self.s.entries().unwrap_or_default();
        let kept = |n: &str| {
            let at = format!("{n}{}", pasa::FILES);
            all.range(at.clone()..).take_while(|e| e.0.starts_with(&at)).count()
        };
        self.kept = all.keys().filter(|n| has(n)).map(|n| kept(n)).collect();
        let shown = all.iter().filter(|e| has(e.0));
        self.ms = shown.clone().map(|e| e.1.ms).collect();
        (self.names, self.files) =
            shown.map(|(n, v)| (n.clone(), v.file.clone())).unzip();
        self.at = self.at.min(self.names.len().saturating_sub(1));
    }

    pub fn name(&self) -> Option<&str> {
        self.names.get(self.at).map(String::as_str)
    }

    pub fn body(&self) -> Secret {
        self.name().and_then(|n| self.s.get(n).ok()).unwrap_or_default()
    }

    /// Do `f` and say what it did, or why not.
    fn act(&mut self, f: impl FnOnce(&View) -> Result<String>) {
        self.note = f(self).unwrap_or_else(|e| format!("{e:#}"));
        self.load();
    }

    pub fn copy(&mut self, f: &str) {
        self.act(|v| {
            let n = v.name().context("nothing chosen")?;
            clip(&field(text(&v.s.get(n)?)?, f).context("no such field")?)?;
            Ok(format!("{n}: {f} copied, cleared in 45 s"))
        })
    }

    /// Empty: deleted.
    pub fn put(&mut self, name: &str, body: &[u8]) {
        self.act(|v| {
            v.s.put(name, body)?;
            news();
            let did = if body.is_empty() { "deleted" } else { "saved" };
            Ok(format!("{name}: {did}; pasa log {name} has every version"))
        })
    }

    /// `pw` as `name`'s new password, copied.
    pub fn generate(&mut self, name: &str, pw: String) {
        self.act(|v| {
            ensure!(!name.trim().is_empty(), "type a name first");
            let pw = crate::generate(&v.s, name.trim(), pw)?;
            news();
            clip(&pw)?;
            Ok(format!("{name}: new password copied, cleared in 45 s"))
        })
    }

    /// Something done to the store: said, recorded, the peers told.
    pub fn change(&mut self, f: impl FnOnce(&pasa::Store) -> Result<String>) {
        self.act(|v| {
            let said = f(&v.s)?;
            news();
            Ok(said)
        })
    }
}

/// A change: recorded, and the peers told.
fn news() {
    record();
    aside(true);
}
