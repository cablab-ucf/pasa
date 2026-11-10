//! `pasa gui`: the same view in a window.

use crate::view::{IDLE, View};
use eframe::egui::{CentralPanel, Key, Panel, ScrollArea, TextEdit, Ui};
use std::time::Instant;
use zeroize::{Zeroize, Zeroizing};

#[derive(Default)]
struct App {
    v: Option<View>,
    pw: Zeroizing<String>,
    /// The password is in: unlock at the next frame, once this one says so.
    busy: bool,
    said: String,
    /// The entry the rest is about; its text while edited.
    on: Option<String>,
    edit: Option<Zeroizing<String>>,
    shown: bool,
    armed: bool,
    used: Option<Instant>,
}

pub fn run() -> anyhow::Result<()> {
    let o = eframe::NativeOptions::default();
    eframe::run_native("pasa", o, Box::new(|_| Ok(Box::<App>::default())))
        .map_err(|e| anyhow::anyhow!("{e}"))
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _: &mut eframe::Frame) {
        // Left alone: locked, the store and what was typed dropped.
        if ui.input(|i| !i.events.is_empty() || i.pointer.is_moving()) {
            self.used = Some(Instant::now());
        }
        if self.used.is_some_and(|t| t.elapsed() > IDLE) {
            *self = App::default();
        }
        ui.ctx().request_repaint_after(IDLE);
        CentralPanel::default().show(ui, |ui| match self.v.take() {
            Some(v) => self.browse(ui, v),
            None => self.locked(ui),
        });
    }
}

impl App {
    fn locked(&mut self, ui: &mut Ui) {
        if std::mem::take(&mut self.busy) {
            match crate::unlock(self.pw.as_bytes()) {
                Ok(s) => self.v = Some(View::new(s)),
                Err(e) => self.said = format!("{e:#}"),
            }
            self.pw.zeroize();
            return ui.ctx().request_repaint();
        }
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() / 3.0);
            ui.heading("pasa");
            let pw = TextEdit::singleline(&mut *self.pw).password(true);
            let r = ui.add(pw.hint_text("Password"));
            if r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                self.busy = true;
                self.said = "Unlocking: touch your YubiKey if it blinks".into();
                ui.ctx().request_repaint();
            }
            r.request_focus();
            ui.label(&self.said);
        });
    }

    fn browse(&mut self, ui: &mut Ui, mut v: View) {
        let mut lock = false;
        let enter = ui.input(|i| i.key_pressed(Key::Enter));
        Panel::top("bar").show(ui, |ui| {
            ui.horizontal(|ui| {
                let f = TextEdit::singleline(&mut v.filter);
                let f = ui.add(f.hint_text("Filter, or a new name"));
                if f.lost_focus() && enter {
                    v.copy("pass");
                }
                if ui.memory(|m| m.focused().is_none()) {
                    f.request_focus();
                }
                let new = ui.button("New").on_hover_text(
                    "An entry named as typed, with a new password, copied",
                );
                if new.clicked() {
                    v.generate(&v.filter.clone());
                }
                lock = ui.button("Lock").clicked();
            })
        });
        Panel::bottom("note").show(ui, |ui| ui.label(&v.note));
        if self.edit.is_none() {
            let (up, down) = (Key::ArrowUp, Key::ArrowDown);
            let step = |k| ui.input(|i| i.key_pressed(k)) as usize;
            v.at = (v.at + step(down)).saturating_sub(step(up));
        }
        v.load();
        let moved = v.name() != self.on.as_deref();
        if moved {
            self.on = v.name().map(Into::into);
            (self.edit, self.shown, self.armed) = Default::default();
        }
        Panel::left("names").default_size(240.0).show(ui, |ui| {
            ScrollArea::vertical().show(ui, |ui| {
                for i in 0..v.names.len() {
                    let r = ui.selectable_label(i == v.at, &v.names[i]);
                    if r.clicked() {
                        v.at = i;
                    }
                    if moved && i == v.at {
                        r.scroll_to_me(None);
                    }
                }
            })
        });
        CentralPanel::default().show(ui, |ui| self.entry(ui, &mut v));
        if !lock {
            self.v = Some(v);
        }
    }

    fn entry(&mut self, ui: &mut Ui, v: &mut View) {
        let Some(n) = self.on.clone() else {
            return drop(ui.label("Nothing here: type a name, then New."));
        };
        let body = v.body();
        let text = Zeroizing::new(String::from_utf8_lossy(&body).into_owned());
        ui.heading(&n);
        ui.horizontal(|ui| {
            for f in ["pass", "user", "otp"] {
                if pasa::field(&text, f).is_some()
                    && ui.button(format!("Copy {f}")).clicked()
                {
                    v.copy(f);
                }
            }
        });
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.shown, "Show");
            if ui.button("Edit").clicked() {
                self.edit = Some(text.clone());
            }
            if ui.button("New password").clicked() {
                v.generate(&n);
            }
            let del = if self.armed { "Really delete" } else { "Delete" };
            if ui.button(del).clicked() {
                if self.armed {
                    v.put(&n, b"");
                }
                self.armed ^= true;
            }
        });
        let Some(e) = &mut self.edit else {
            return drop(self.shown.then(|| ui.monospace(&**text)));
        };
        let wide = TextEdit::multiline(&mut **e).desired_width(f32::INFINITY);
        ui.add(wide.code_editor());
        let (mut save, mut done) = (false, false);
        ui.horizontal(|ui| {
            save = ui.button("Save").clicked();
            done = save || ui.button("Cancel").clicked();
        });
        if save {
            v.put(&n, e.as_bytes());
        }
        if done {
            self.edit = None;
        }
    }
}
