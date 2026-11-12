use crate::view::{IDLE, View};
use anyhow::Result;
use crossterm::event::{
    Event, KeyCode::*, KeyEventKind, KeyModifiers, poll, read,
};
use crossterm::style::{Attribute, Print, SetAttribute};
use crossterm::terminal::{self, Clear, ClearType::All};
use crossterm::{cursor::MoveTo, execute, queue};
use std::io::{Write, stdout};

const HELP: &str = "Enter pass ^U user ^O otp Tab show ^E edit ^G regen ^N new \
                    ^D del ^S sync Esc";

fn screen(on: bool) -> Result<()> {
    match on {
        true => {
            terminal::enable_raw_mode()?;
            execute!(stdout(), terminal::EnterAlternateScreen)?
        }
        false => {
            execute!(stdout(), terminal::LeaveAlternateScreen)?;
            terminal::disable_raw_mode()?
        }
    }
    Ok(())
}

pub fn run(s: pasa::Store) -> Result<()> {
    screen(true)?;
    crate::aside(false);
    let mut v = View::new(s);
    v.note = checkin();
    let r = browse(v);
    screen(false)?;
    r
}

fn checkin() -> String {
    #[cfg(feature = "sync")]
    {
        let h = pasa::home();
        if let Some((who, d)) = pasa::sync::unseen(&h).first() {
            return format!(
                "Not synced with {who} for {d} days: check in (^S: sync on)"
            );
        }
        if !pasa::sync::peers(&h).is_empty() {
            let on = pasa::sync::on(&h);
            return (if on {
                "Sync on (^S: off)"
            } else {
                "Offline (^S: sync on)"
            })
            .into();
        }
    }
    String::new()
}

fn draw(v: &View, shown: bool) -> Result<()> {
    let (w, h) = terminal::size()?;
    let (w, rows) = (w as usize, (h as usize).saturating_sub(2));
    let mut o = stdout().lock();
    let mut line = |y: usize, s: &str, bold: bool| {
        let a = if bold { Attribute::Reverse } else { Attribute::Reset };
        let s: String = s.chars().filter(|c| !c.is_control()).take(w).collect();
        queue!(
            o,
            MoveTo(0, y as u16),
            SetAttribute(a),
            Print(s),
            SetAttribute(Attribute::Reset)
        )
    };
    let body = v.body();
    let body = String::from_utf8_lossy(&body);
    let top = v.at.saturating_sub(rows.saturating_sub(1));
    queue!(stdout(), Clear(All))?;
    match shown {
        true => body
            .lines()
            .take(rows)
            .enumerate()
            .try_for_each(|(i, l)| line(i + 1, l, false))?,
        false => (top..v.names.len().min(top + rows))
            .try_for_each(|i| line(i + 1 - top, &v.names[i], i == v.at))?,
    }
    line(
        h as usize - 1,
        if v.note.is_empty() { HELP } else { &v.note },
        false,
    )?;
    line(0, &format!("> {}", v.filter), false)?;
    Ok(o.flush()?)
}

fn browse(mut v: View) -> Result<()> {
    let (mut shown, mut armed) = (false, false);
    loop {
        draw(&v, shown)?;
        // Idle: returning drops the store, which locks it.
        if !poll(IDLE)? {
            return Ok(());
        }
        let Event::Key(k) = read()? else { continue };
        if k.kind != KeyEventKind::Press {
            continue;
        }
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let name = v.name().map(String::from);
        let (was, del) = (shown, armed);
        (shown, armed, v.note) = Default::default();
        match (k.code, name) {
            (Esc, _) | (Char('c'), _) if k.code == Esc || ctrl => return Ok(()),
            (Up, _) => v.at = v.at.saturating_sub(1),
            (Down, _) => v.at += 1,
            (Enter, _) => v.copy("pass"),
            (Char('u'), _) if ctrl => v.copy("user"),
            (Char('o'), _) if ctrl => v.copy("otp"),
            (Tab, _) => shown = !was,
            (Char('n'), _) if ctrl => {
                v.generate(&v.filter.clone(), pasa::generate(24, true))
            }
            (Char('g'), Some(n)) if ctrl => {
                v.generate(&n, pasa::generate(24, true))
            }
            (Char('e'), Some(n)) if ctrl => {
                let old = v.body();
                screen(false)?;
                let new = crate::edit(&old);
                screen(true)?;
                match new {
                    Ok(new) if *new != *old => v.put(&n, &new),
                    Ok(_) => {}
                    Err(e) => v.note = format!("{e:#}"),
                }
            }
            (Char('d'), Some(n)) if ctrl && del => v.change(|s| {
                s.remove(&n)?;
                Ok(format!("{n}: deleted; pasa log {n} has every version"))
            }),
            (Char('d'), Some(n)) if ctrl => {
                armed = true;
                v.note = format!("^D again deletes {n}");
            }
            #[cfg(feature = "sync")]
            (Char('s'), _) if ctrl => {
                let h = pasa::home();
                let on = !pasa::sync::on(&h);
                v.note = match pasa::sync::set_on(&h, on) {
                    Ok(()) if on => {
                        crate::aside(false);
                        "Sync on: paired devices sync with this one".into()
                    }
                    Ok(()) => "Offline: pasa opens no connection".into(),
                    Err(e) => format!("{e:#}"),
                };
            }
            (Backspace, _) => drop(v.filter.pop()),
            (Char(c), _) if !ctrl => v.filter.push(c),
            _ => {}
        }
        v.load();
    }
}
