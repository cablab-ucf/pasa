//! State shared by the terminal and the window.

use crate::{aside_in, clip, record_in, text};
use anyhow::{Context, Result, ensure};
use pasa::{Secret, Store, field};
use std::time::Duration;

pub const IDLE: Duration = Duration::from_secs(300);

pub struct View {
    pub s: Store,
    pub filter: String,
    pub names: Vec<String>,
    /// Each name's newest version file: what caches key on.
    pub files: Vec<String>,
    /// Per name: last change (ms), and how many attached files.
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
        if v.s.retired() {
            v.note = pasa::RETIRED_SAY.into();
        }
        if let Some(u) = v.s.unopened.first() {
            v.note = u.clone();
        }
        v
    }

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

    /// An empty body deletes.
    pub fn put(&mut self, name: &str, body: &[u8]) {
        self.act(|v| {
            v.s.put(name, body)?;
            news(&v.s);
            let did = if body.is_empty() { "deleted" } else { "saved" };
            Ok(format!("{name}: {did}; pasa log {name} has every version"))
        })
    }

    pub fn generate(&mut self, name: &str, pw: String) {
        self.act(|v| {
            ensure!(!name.trim().is_empty(), "type a name first");
            let pw = crate::generate(&v.s, name.trim(), pw)?;
            news(&v.s);
            clip(&pw)?;
            Ok(format!("{name}: new password copied, cleared in 45 s"))
        })
    }

    pub fn change(&mut self, f: impl FnOnce(&pasa::Store) -> Result<String>) {
        self.act(|v| {
            let said = f(&v.s)?;
            news(&v.s);
            Ok(said)
        })
    }
}

/// Commit the change (git, if any) and sync it to the peers, in each
/// store: the one written to, linked or not.
fn news(s: &Store) {
    for d in s.dirs() {
        record_in(d);
        aside_in(d, true);
    }
}
