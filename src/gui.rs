//! `pasa gui`: the store in a window. A first run asks for the password
//! and, if wanted, a hardware key; joining another device's store waits in
//! the corner. Then groups, entries and the chosen one's fields, as the
//! Android app lays them out.

use crate::view::View;
use anyhow::{Context as _, Result};
use eframe::egui::{
    self, Align, Align2, Area, Button, CentralPanel, Color32, ComboBox,
    Context, FontId, Frame, Grid, Id, Key, Layout, Margin, Modal, Panel,
    Response, RichText, ScrollArea, Sense, Slider, Stroke, TextEdit, TextStyle,
    Theme, ThemePreference, Ui, Visuals, pos2, vec2,
};
use pasa::{Form, Store, home, sync};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};
use zeroize::Zeroizing;

/// The colours both apps share.
struct Look {
    bg: Color32,
    card: Color32,
    line: Color32,
    accent: Color32,
    on_accent: Color32,
    text: Color32,
    muted: Color32,
    bad: Color32,
}

const fn rgb(c: u32) -> Color32 {
    Color32::from_rgb((c >> 16) as u8, (c >> 8) as u8, c as u8)
}

const DARK: Look = Look {
    bg: rgb(0x101512),
    card: rgb(0x18201C),
    line: rgb(0x2A3530),
    accent: rgb(0x5FB89A),
    on_accent: rgb(0x06281E),
    text: rgb(0xE6ECE8),
    muted: rgb(0x9AA8A1),
    bad: rgb(0xF2877B),
};
const LIGHT: Look = Look {
    bg: rgb(0xF6F8F6),
    card: rgb(0xFFFFFF),
    line: rgb(0xD5DDD8),
    accent: rgb(0x2E5E4E),
    on_accent: rgb(0xFFFFFF),
    text: rgb(0x17201B),
    muted: rgb(0x5C6B63),
    bad: rgb(0xB3261E),
};

fn look(ui: &Ui) -> &'static Look {
    if ui.visuals().dark_mode { &DARK } else { &LIGHT }
}

fn style(ctx: &Context) {
    for (theme, l, mut v) in [
        (Theme::Dark, &DARK, Visuals::dark()),
        (Theme::Light, &LIGHT, Visuals::light()),
    ] {
        (v.panel_fill, v.window_fill, v.extreme_bg_color) =
            (l.bg, l.card, l.card);
        (v.override_text_color, v.hyperlink_color) = (Some(l.text), l.accent);
        v.selection.bg_fill = l.accent.gamma_multiply(0.35);
        v.selection.stroke = Stroke::new(1.0, l.accent);
        v.window_stroke = Stroke::new(1.0, l.line);
        v.window_corner_radius = 12.into();
        v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, l.line);
        v.widgets.inactive.bg_stroke = Stroke::new(1.0, l.line);
        v.widgets.inactive.weak_bg_fill = l.card;
        v.widgets.hovered.weak_bg_fill = l.line;
        for w in [
            &mut v.widgets.noninteractive,
            &mut v.widgets.inactive,
            &mut v.widgets.hovered,
            &mut v.widgets.active,
            &mut v.widgets.open,
        ] {
            w.corner_radius = 7.into();
        }
        ctx.set_visuals_of(theme, v);
    }
    ctx.all_styles_mut(|s| {
        s.spacing.item_spacing = vec2(8.0, 8.0);
        s.spacing.button_padding = vec2(12.0, 6.0);
        s.spacing.interact_size.y = 30.0;
        let p = FontId::proportional;
        s.text_styles = [
            (TextStyle::Heading, p(22.0)),
            (TextStyle::Body, p(15.0)),
            (TextStyle::Button, p(15.0)),
            (TextStyle::Small, p(12.5)),
            (TextStyle::Monospace, FontId::monospace(14.0)),
        ]
        .into();
    });
}

/// What is kept between runs, in `~/.pasa/ui`: minutes left alone before
/// locking, and the theme.
#[derive(Clone)]
struct Prefs {
    lock: u64,
    theme: ThemePreference,
}

const THEMES: [(&str, ThemePreference); 3] = [
    ("system", ThemePreference::System),
    ("light", ThemePreference::Light),
    ("dark", ThemePreference::Dark),
];

impl Default for Prefs {
    fn default() -> Prefs {
        let t = std::fs::read_to_string(home().join("ui")).unwrap_or_default();
        let get = |k| t.lines().find_map(|l| l.strip_prefix(k).map(str::trim));
        let theme = THEMES.iter().find(|t| Some(t.0) == get("theme "));
        Prefs {
            lock: get("lock ").and_then(|m| m.parse().ok()).unwrap_or(5),
            theme: theme.map_or(ThemePreference::System, |t| t.1),
        }
    }
}

impl Prefs {
    fn save(&self) {
        let theme =
            THEMES.iter().find(|t| t.1 == self.theme).map_or("system", |t| t.0);
        let _ = pasa::write(
            &home().join("ui"),
            format!("lock {}\ntheme {theme}\n", self.lock).as_bytes(),
        );
    }
}

enum Job {
    Create,
    Unlock,
    Join,
}

#[derive(Default, PartialEq)]
enum Win {
    #[default]
    None,
    Generator,
    Devices,
    Settings,
}

/// An entry in the form; `old`: its name before, or empty for a new one.
struct Edit {
    old: String,
    name: String,
    f: Form,
    show: bool,
}

struct Generator {
    len: usize,
    symbols: bool,
    pw: Zeroizing<String>,
}

impl Default for Generator {
    fn default() -> Generator {
        Generator {
            len: 24,
            symbols: true,
            pw: Zeroizing::new(pasa::generate(24, true)),
        }
    }
}

/// A device being added: what it must type, and how that ends.
struct Pairing {
    name: String,
    code: String,
    pw: String,
    end: Option<tokio::task::JoinHandle<pairir::End>>,
    state: String,
}

#[derive(Default)]
struct App {
    v: Option<View>,
    prefs: Prefs,
    used: Option<Instant>,
    // Before the store is open.
    pw: Zeroizing<String>,
    pw2: Zeroizing<String>,
    yk: bool,
    joining: bool,
    peer: String,
    code: String,
    pair_pw: Zeroizing<String>,
    /// A joined pairing's hand-over key, until the unlock that seals it.
    hand: Option<(String, Zeroizing<Vec<u8>>)>,
    /// Done at the next frame, once this one has said so.
    job: Option<Job>,
    said: String,
    // The open store.
    group: Option<String>,
    users: HashMap<String, String>,
    shown: bool,
    armed: bool,
    edit: Option<Edit>,
    win: Win,
    generator: Generator,
    device: String,
    pairing: Option<Pairing>,
    synced: Arc<Mutex<Option<String>>>,
    rt: Option<tokio::runtime::Runtime>,
}

pub fn run() -> Result<()> {
    let view = egui::ViewportBuilder::default()
        .with_title("pasa")
        .with_app_id("pasa")
        .with_inner_size([1000.0, 660.0])
        .with_min_inner_size([680.0, 440.0]);
    let o = eframe::NativeOptions { viewport: view, ..Default::default() };
    let app = |c: &eframe::CreationContext<'_>| {
        style(&c.egui_ctx);
        let a = App { peer: "home".into(), ..App::default() };
        c.egui_ctx.set_theme(a.prefs.theme);
        Ok(Box::new(a) as Box<dyn eframe::App>)
    };
    eframe::run_native("pasa", o, Box::new(app))
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// A muted label over a field as wide as its place.
fn field(
    ui: &mut Ui,
    label: &str,
    text: &mut String,
    secret: bool,
) -> Response {
    ui.label(RichText::new(label).small().color(look(ui).muted));
    let t = TextEdit::singleline(text)
        .password(secret)
        .desired_width(f32::INFINITY);
    ui.add(t.margin(Margin::symmetric(8, 6)))
}

/// A dialog's frame: the window's, with room around what it holds.
fn sheet(ctx: &Context) -> Frame {
    Frame::window(&ctx.global_style()).inner_margin(20)
}

/// The one button a screen is for.
fn primary(ui: &mut Ui, text: &str, wide: bool) -> Response {
    let l = look(ui);
    let b = Button::new(RichText::new(text).color(l.on_accent).strong())
        .fill(l.accent);
    match wide {
        true => ui.add_sized([ui.available_width(), 36.0], b),
        false => ui.add(b),
    }
}

/// The name, then one card in the middle: what the app wants first.
fn card(ui: &mut Ui, about: &str, title: &str, body: impl FnOnce(&mut Ui)) {
    let l = look(ui);
    CentralPanel::default().show(ui, |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space((ui.available_height() * 0.14).max(20.0));
            ui.label(RichText::new("pasa").size(36.0).strong().color(l.accent));
            ui.label(RichText::new(about).color(l.muted));
            ui.add_space(16.0);
            let f = Frame::new().fill(l.card).stroke(Stroke::new(1.0, l.line));
            f.corner_radius(12).inner_margin(22).show(ui, |ui| {
                ui.set_width(360.0);
                ui.with_layout(Layout::top_down(Align::Min), |ui| {
                    ui.label(RichText::new(title).size(18.0).strong());
                    ui.add_space(4.0);
                    body(ui);
                });
            });
        });
    });
}

/// The other way in, small, in the corner.
fn corner(ui: &Ui, ask: &str, link: &str) -> bool {
    let a = Area::new(Id::unique("corner"))
        .anchor(Align2::RIGHT_BOTTOM, [-20.0, -16.0]);
    let r = a.show(ui.ctx(), |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(ask).small().color(look(ui).muted));
            ui.link(RichText::new(link).small()).clicked()
        })
    });
    r.inner.inner
}

fn entered(ui: &Ui, r: &Response) -> bool {
    r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter))
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _: &mut eframe::Frame) {
        // Left alone: locked, the store and what was typed dropped.
        if ui.input(|i| !i.events.is_empty() || i.pointer.is_moving()) {
            self.used = Some(Instant::now());
        }
        let idle = Duration::from_secs(self.prefs.lock * 60);
        if self.v.is_some() && self.used.is_some_and(|t| t.elapsed() > idle) {
            self.lock();
        }
        ui.ctx().request_repaint_after(idle);
        if let Some(job) = self.job.take() {
            self.said = self
                .work(job)
                .err()
                .map(|e| format!("{e:#}"))
                .unwrap_or_default();
            ui.ctx().request_repaint();
        }
        match self.v.take() {
            Some(v) => self.store(ui, v),
            None if home().join("key").exists() => self.unlock(ui),
            None if self.joining => self.join(ui),
            None => self.create(ui),
        }
    }
}

impl App {
    fn lock(&mut self) {
        *self = App {
            prefs: self.prefs.clone(),
            peer: "home".into(),
            ..App::default()
        };
    }

    fn rt(&mut self) -> Result<&tokio::runtime::Runtime> {
        if self.rt.is_none() {
            self.rt = Some(tokio::runtime::Runtime::new()?);
        }
        self.rt.as_ref().context("no runtime")
    }

    fn begin(&mut self, ui: &Ui, job: Job, say: &str) {
        (self.job, self.said) = (Some(job), say.into());
        ui.ctx().request_repaint();
    }

    fn work(&mut self, job: Job) -> Result<()> {
        match job {
            Job::Create => {
                let c = pasa::rand::<32>();
                let r = self.yk.then(|| crate::yubikey(&c)).transpose()?;
                let yk = r.as_ref().map(|r| (&c[..], &r[..]));
                self.v = Some(View::new(Store::create(
                    &home(),
                    self.pw.as_bytes(),
                    yk,
                )?));
            }
            Job::Unlock => {
                let mut s = crate::unlock(self.pw.as_bytes())?;
                if let Some((name, hand)) = self.hand.take() {
                    sync::keep_hand(&mut s, &name, &hand)?;
                }
                self.v = Some(View::new(s));
            }
            Job::Join => {
                let (peer, code, pw) = (
                    self.peer.clone(),
                    self.code.clone(),
                    self.pair_pw.clone(),
                );
                let hand = self.rt()?.block_on(sync::join(
                    &home(),
                    peer.trim(),
                    &code,
                    &pw,
                ))?;
                self.hand = Some((peer.trim().into(), hand));
            }
        }
        (self.pw, self.pw2, self.pair_pw) = Default::default();
        Ok(())
    }

    fn said(&self, ui: &mut Ui) {
        if !self.said.is_empty() {
            let working = self.job.is_some();
            let c = if working { look(ui).muted } else { look(ui).bad };
            ui.label(RichText::new(&self.said).small().color(c));
        }
    }

    fn create(&mut self, ui: &mut Ui) {
        card(ui, "A small password store", "Create your store", |ui| {
            let l = look(ui);
            let first = field(ui, "Password", &mut self.pw, true);
            if ui.memory(|m| m.focused().is_none()) {
                first.request_focus();
            }
            let again = field(ui, "Password, again", &mut self.pw2, true);
            ui.add_space(4.0);
            ui.checkbox(&mut self.yk, "Require a hardware key (YubiKey)");
            let why = "Its answer (HMAC-SHA1, slot 2) joins the password in the lock: \
                       the store then opens only with both.";
            ui.label(RichText::new(why).small().color(l.muted));
            ui.add_space(6.0);
            let ok = !self.pw.is_empty() && *self.pw == *self.pw2;
            let go = ui
                .add_enabled_ui(ok, |ui| primary(ui, "Create store", true))
                .inner;
            if ok && (go.clicked() || entered(ui, &again)) {
                let say =
                    if self.yk { "Touch your YubiKey" } else { "Creating" };
                self.begin(ui, Job::Create, say);
            } else if !self.pw2.is_empty() && !ok {
                self.said = "The passwords differ".into();
            } else if self.job.is_none() && self.said == "The passwords differ"
            {
                self.said.clear();
            }
            self.said(ui);
        });
        if corner(ui, "A store on another device already?", "Join it") {
            (self.joining, self.said) = (true, String::new());
        }
    }

    fn join(&mut self, ui: &mut Ui) {
        card(ui, "A small password store", "Join a store", |ui| {
            let l = look(ui);
            let how = "On the device that has it: Devices, Add a device \
                       (or pasa pair NAME). It shows a code and a password.";
            ui.label(RichText::new(how).small().color(l.muted));
            field(ui, "A name for that device", &mut self.peer, false);
            field(ui, "Code", &mut self.code, false);
            let pw = field(ui, "Pairing password", &mut self.pair_pw, true);
            ui.add_space(6.0);
            let ok =
                !self.peer.trim().is_empty() && !self.code.trim().is_empty();
            let go =
                ui.add_enabled_ui(ok, |ui| primary(ui, "Join", true)).inner;
            if ok && (go.clicked() || entered(ui, &pw)) {
                self.begin(ui, Job::Join, "Joining");
            }
            self.said(ui);
        });
        if corner(ui, "No store yet?", "Create one") {
            (self.joining, self.said) = (false, String::new());
        }
    }

    fn unlock(&mut self, ui: &mut Ui) {
        let key = std::fs::read(home().join("key")).unwrap_or_default();
        let yk = pasa::challenge(&key).is_some();
        let title = if self.hand.is_some() {
            "Joined: now its password"
        } else {
            "Unlock"
        };
        card(ui, "A small password store", title, |ui| {
            let pw = field(ui, "Password", &mut self.pw, true);
            let enter = entered(ui, &pw);
            if ui.memory(|m| m.focused().is_none()) {
                pw.request_focus();
            }
            if yk {
                let l = look(ui);
                ui.label(
                    RichText::new("Then touch your YubiKey")
                        .small()
                        .color(l.muted),
                );
            }
            ui.add_space(6.0);
            if primary(ui, "Unlock", true).clicked() || enter {
                let say = if yk { "Touch your YubiKey" } else { "Unlocking" };
                self.begin(ui, Job::Unlock, say);
            }
            self.said(ui);
        });
    }

    /// The entry's user name, read once per version.
    fn user(&mut self, v: &View, i: usize) -> String {
        let read = || {
            let b = v.s.get(&v.names[i]).unwrap_or_default();
            Form::parse(&String::from_utf8_lossy(&b)).user
        };
        self.users.entry(v.files[i].clone()).or_insert_with(read).clone()
    }

    fn store(&mut self, ui: &mut Ui, mut v: View) {
        let l = look(ui);
        let ctx = ui.ctx().clone();
        if let Some(s) = self.synced.lock().unwrap().take() {
            v.note = s;
        }
        v.load();
        let dir = |n: &str| n.rsplit_once('/').map(|d| d.0.to_string());
        let groups: BTreeSet<String> =
            v.names.iter().filter_map(|n| dir(n)).collect();
        if self.group.as_ref().is_some_and(|g| !groups.contains(g)) {
            self.group = None;
        }
        let within = |n: &String| self.group.is_none() || dir(n) == self.group;
        let rows: Vec<usize> =
            (0..v.names.len()).filter(|i| within(&v.names[*i])).collect();
        let was = v.at;
        if !rows.contains(&v.at) {
            v.at = rows.first().copied().unwrap_or(0);
        }
        let chosen = rows.contains(&v.at).then(|| v.names[v.at].clone());
        let modal = self.edit.is_some() || self.win != Win::None;
        let typing = ctx.memory(|m| m.focused().is_some());
        let key = |k: Key, ctrl: bool| {
            !modal
                && ctx
                    .input(|i| i.key_pressed(k) && i.modifiers.command == ctrl)
        };
        let (mut lock, mut find) = (key(Key::L, true), key(Key::F, true));
        if key(Key::N, true) {
            self.new_entry();
        }
        if let (Some(p), false) = (rows.iter().position(|i| *i == v.at), modal)
        {
            let step = |k| ctx.input(|i| i.key_pressed(k)) as usize;
            let to =
                (p + step(Key::ArrowDown)).saturating_sub(step(Key::ArrowUp));
            v.at = rows[to.min(rows.len() - 1)];
        }
        if chosen.is_some() && !modal {
            if key(Key::B, true) {
                v.copy("user");
            }
            if key(Key::C, true) && !typing {
                v.copy("pass");
            }
        }

        let bar =
            Frame::new().fill(l.card).inner_margin(Margin::symmetric(12, 8));
        Panel::top("bar").frame(bar).show(ui, |ui| {
            ui.horizontal(|ui| {
                if primary(ui, "+  New", false)
                    .on_hover_text("Ctrl+N")
                    .clicked()
                {
                    self.new_entry();
                }
                ui.add_enabled_ui(chosen.is_some(), |ui| {
                    if ui.button("Edit").clicked() {
                        self.edit_entry(&v);
                    }
                    if ui.button("Copy user").on_hover_text("Ctrl+B").clicked()
                    {
                        v.copy("user");
                    }
                    if ui
                        .button("Copy password")
                        .on_hover_text("Ctrl+C")
                        .clicked()
                    {
                        v.copy("pass");
                    }
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    lock |= ui.button("Lock").on_hover_text("Ctrl+L").clicked();
                    for (name, win) in [
                        ("Settings", Win::Settings),
                        ("Devices", Win::Devices),
                        ("Generator", Win::Generator),
                    ] {
                        if ui.button(name).clicked() {
                            self.win = win;
                        }
                    }
                    let search = TextEdit::singleline(&mut v.filter)
                        .hint_text("Search  (Ctrl+F)");
                    let search = ui.add(
                        search
                            .desired_width(220.0)
                            .margin(Margin::symmetric(8, 6)),
                    );
                    find |= !typing
                        && !modal
                        && was == 0
                        && v.filter.is_empty()
                        && self.used.is_none();
                    if find {
                        search.request_focus();
                    }
                    if entered(ui, &search) && chosen.is_some() {
                        v.copy("pass");
                    }
                });
            })
        });

        let foot =
            Frame::new().fill(l.card).inner_margin(Margin::symmetric(12, 5));
        Panel::bottom("status").frame(foot).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(&v.note).small().color(l.muted));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let n =
                        format!("{} of {} entries", rows.len(), v.names.len());
                    ui.label(RichText::new(n).small().color(l.muted));
                });
            })
        });

        Panel::left("groups").default_size(190.0).show(ui, |ui| {
            ui.add_space(4.0);
            ui.label(RichText::new("GROUPS").small().color(l.muted));
            ScrollArea::vertical().show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                let all =
                    ui.selectable_label(self.group.is_none(), "All entries");
                if all.clicked() {
                    self.group = None;
                }
                for g in &groups {
                    let on = self.group.as_ref() == Some(g);
                    if ui.selectable_label(on, g).clicked() {
                        self.group = Some(g.clone());
                    }
                }
            })
        });

        Panel::bottom("entry")
            .resizable(true)
            .min_size(190.0)
            .default_size(240.0)
            .show(ui, |ui| {
                self.entry(ui, &mut v, chosen.as_deref());
            });

        CentralPanel::default().show(ui, |ui| {
            let width = ui.available_width();
            let cols = |ui: &mut Ui, h: f32| {
                let (rect, r) =
                    ui.allocate_exact_size(vec2(width, h), Sense::click());
                (rect, r, rect.left() + rect.width() * 0.55)
            };
            let put = |ui: &Ui,
                       x: f32,
                       max: f32,
                       y: f32,
                       t: &str,
                       c: Color32,
                       small: bool| {
                let f = FontId::proportional(if small { 12.5 } else { 15.0 });
                let clip = egui::Rect::from_min_max(
                    pos2(x, y - 15.0),
                    pos2(max, y + 15.0),
                );
                ui.painter().with_clip_rect(clip).text(
                    pos2(x, y),
                    Align2::LEFT_CENTER,
                    t,
                    f,
                    c,
                );
            };
            let (rect, _, mid) = cols(ui, 22.0);
            let y = rect.center().y;
            put(ui, rect.left() + 10.0, mid - 8.0, y, "TITLE", l.muted, true);
            put(ui, mid, rect.right(), y, "USERNAME", l.muted, true);
            ui.separator();
            if rows.is_empty() {
                let none = if v.names.is_empty() && v.filter.is_empty() {
                    "No entries yet. New adds the first."
                } else {
                    "Nothing matches."
                };
                ui.add_space(24.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new(none).color(l.muted))
                });
            }
            ScrollArea::vertical().auto_shrink(false).show_rows(
                ui,
                30.0,
                rows.len(),
                |ui, shown| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    for i in shown {
                        let at = rows[i];
                        let user = self.user(&v, at);
                        let (rect, r, mid) = cols(ui, 30.0);
                        let fill = match (at == v.at, r.hovered()) {
                            (true, _) => l.accent.gamma_multiply(0.28),
                            (_, true) => l.line.gamma_multiply(0.6),
                            _ => Color32::TRANSPARENT,
                        };
                        ui.painter().rect_filled(rect, 7, fill);
                        let name = &v.names[at];
                        let title = match &self.group {
                            Some(g) => &name[g.len() + 1..],
                            None => name,
                        };
                        let y = rect.center().y;
                        put(
                            ui,
                            rect.left() + 10.0,
                            mid - 8.0,
                            y,
                            title,
                            l.text,
                            false,
                        );
                        put(
                            ui,
                            mid,
                            rect.right() - 6.0,
                            y,
                            &user,
                            l.muted,
                            false,
                        );
                        if r.clicked() {
                            v.at = at;
                        }
                        if r.double_clicked() {
                            v.at = at;
                            v.copy("pass");
                        }
                    }
                },
            );
        });

        if v.at != was {
            (self.shown, self.armed) = (false, false);
        }
        self.form(&ctx, &mut v);
        self.windows(&ctx, &mut v);
        match lock {
            true => self.lock(),
            false => self.v = Some(v),
        }
    }

    fn new_entry(&mut self) {
        let name =
            self.group.as_ref().map(|g| format!("{g}/")).unwrap_or_default();
        let f = Form {
            pass: pasa::generate(self.generator.len, self.generator.symbols),
            ..Form::default()
        };
        self.edit = Some(Edit { old: String::new(), name, f, show: false });
    }

    fn edit_entry(&mut self, v: &View) {
        if let Some(n) = v.name() {
            let f = Form::parse(&String::from_utf8_lossy(&v.body()));
            self.edit =
                Some(Edit { old: n.into(), name: n.into(), f, show: false });
        }
    }

    /// The chosen entry's fields, each with its copy.
    fn entry(&mut self, ui: &mut Ui, v: &mut View, chosen: Option<&str>) {
        let l = look(ui);
        let Some(name) = chosen else {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("No entry chosen").color(l.muted))
            });
            return;
        };
        let text =
            Zeroizing::new(String::from_utf8_lossy(&v.body()).into_owned());
        let f = Form::parse(&text);
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new(name).size(19.0).strong());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let del = if self.armed { "Really delete" } else { "Delete" };
                if ui.button(RichText::new(del).color(l.bad)).clicked() {
                    if self.armed {
                        v.put(name, b"");
                    }
                    self.armed ^= true;
                }
                if ui.button("Edit").clicked() {
                    self.edit_entry(v);
                }
            });
        });
        ScrollArea::vertical().show(ui, |ui| {
            Grid::new("fields").num_columns(3).spacing([14.0, 8.0]).show(
                ui,
                |ui| {
                    let label = |ui: &mut Ui, t: &str| {
                        ui.label(RichText::new(t).small().color(l.muted));
                    };
                    if !f.user.is_empty() {
                        label(ui, "Username");
                        ui.label(&f.user);
                        if ui.small_button("Copy").clicked() {
                            v.copy("user");
                        }
                        ui.end_row();
                    }
                    label(ui, "Password");
                    let dots =
                        "\u{2022}".repeat(f.pass.chars().count().min(24));
                    ui.label(
                        RichText::new(if self.shown { &f.pass } else { &dots })
                            .monospace(),
                    );
                    ui.horizontal(|ui| {
                        if ui.small_button("Copy").clicked() {
                            v.copy("pass");
                        }
                        let show = if self.shown { "Hide" } else { "Show" };
                        if ui.small_button(show).clicked() {
                            self.shown ^= true;
                        }
                    });
                    ui.end_row();
                    if let Some(code) = pasa::field(&text, "otp") {
                        let left = 30
                            - UNIX_EPOCH
                                .elapsed()
                                .map_or(0, |t| t.as_secs() % 30);
                        let (a, b) = code.split_at(code.len() / 2);
                        label(ui, "One-time code");
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("{a} {b}")).monospace(),
                            );
                            ui.label(
                                RichText::new(format!("{left} s"))
                                    .small()
                                    .color(l.muted),
                            );
                        });
                        if ui.small_button("Copy").clicked() {
                            v.copy("otp");
                        }
                        ui.end_row();
                        ui.ctx().request_repaint_after(Duration::from_secs(1));
                    }
                    if !f.url.is_empty() {
                        label(ui, "URL");
                        ui.label(&f.url);
                        if ui.small_button("Copy").clicked() {
                            v.copy("url");
                        }
                        ui.end_row();
                    }
                    if !f.notes.is_empty() {
                        label(ui, "Notes");
                        ui.label(&f.notes);
                        ui.end_row();
                    }
                },
            );
        });
    }

    /// The entry being made or changed.
    fn form(&mut self, ctx: &Context, v: &mut View) {
        let Some(e) = &mut self.edit else { return };
        let (mut save, mut close) = (false, false);
        let r =
            Modal::new(Id::unique("edit")).frame(sheet(ctx)).show(ctx, |ui| {
                ui.set_width(440.0);
                let l = look(ui);
                ui.heading(if e.old.is_empty() {
                    "New entry"
                } else {
                    "Edit entry"
                });
                let title = field(
                    ui,
                    "Title (a / makes a group: mail/work)",
                    &mut e.name,
                    false,
                );
                if e.old.is_empty() && ui.memory(|m| m.focused().is_none()) {
                    title.request_focus();
                }
                field(ui, "Username", &mut e.f.user, false);
                ui.label(RichText::new("Password").small().color(l.muted));
                ui.horizontal(|ui| {
                    if ui.button("Generate").clicked() {
                        e.f.pass = pasa::generate(
                            self.generator.len,
                            self.generator.symbols,
                        );
                    }
                    if ui.button(if e.show { "Hide" } else { "Show" }).clicked()
                    {
                        e.show ^= true;
                    }
                    let t =
                        TextEdit::singleline(&mut e.f.pass).password(!e.show);
                    ui.add(
                        t.desired_width(f32::INFINITY)
                            .margin(Margin::symmetric(8, 6)),
                    );
                });
                field(ui, "URL", &mut e.f.url, false);
                field(
                    ui,
                    "One-time code: its otpauth:// address",
                    &mut e.f.otp,
                    false,
                );
                ui.label(RichText::new("Notes").small().color(l.muted));
                ui.add(
                    TextEdit::multiline(&mut e.f.notes)
                        .desired_rows(4)
                        .desired_width(f32::INFINITY),
                );
                ui.add_space(6.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let ok =
                        !e.name.trim().is_empty() && !e.name.ends_with('/');
                    save = ui
                        .add_enabled_ui(ok, |ui| primary(ui, "Save", false))
                        .inner
                        .clicked();
                    close = ui.button("Cancel").clicked();
                });
            });
        if save {
            let (name, old) = (e.name.trim().to_string(), e.old.clone());
            v.put(&name, e.f.text().as_bytes());
            if !old.is_empty() && old != name {
                v.put(&old, b"");
            }
            v.filter.clear();
            v.load();
            v.at = v.names.iter().position(|n| *n == name).unwrap_or(0);
            self.group = name.rsplit_once('/').map(|d| d.0.into());
        }
        if save || close || r.should_close() {
            self.edit = None;
        }
    }

    fn windows(&mut self, ctx: &Context, v: &mut View) {
        if self.win == Win::None {
            return;
        }
        let mut close = false;
        let r = Modal::new(Id::unique("window")).frame(sheet(ctx)).show(
            ctx,
            |ui| {
                ui.set_width(420.0);
                match self.win {
                    Win::Generator => self.generate(ui, v),
                    Win::Devices => self.devices(ui, v),
                    _ => self.settings(ui),
                }
                ui.add_space(6.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    close = ui.button("Close").clicked();
                });
            },
        );
        if close || r.should_close() {
            self.prefs.save();
            self.win = Win::None;
        }
    }

    fn generate(&mut self, ui: &mut Ui, v: &mut View) {
        let g = &mut self.generator;
        ui.heading("Password generator");
        let f =
            Frame::new().fill(look(ui).bg).corner_radius(8).inner_margin(12);
        f.show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(&**g.pw).monospace().size(16.0));
        });
        let mut again = ui
            .add(Slider::new(&mut g.len, 8..=64).text("characters"))
            .changed();
        again |= ui.checkbox(&mut g.symbols, "Symbols").changed();
        ui.horizontal(|ui| {
            again |= ui.button("Another").clicked();
            if primary(ui, "Copy", false).clicked() {
                v.note = match crate::clip(&g.pw) {
                    Ok(()) => {
                        "Generated password copied, cleared in 45 s".into()
                    }
                    Err(e) => format!("{e:#}"),
                };
            }
        });
        if again {
            g.pw = Zeroizing::new(pasa::generate(g.len, g.symbols));
        }
        let note = "New entries start with a password of this length.";
        ui.label(RichText::new(note).small().color(look(ui).muted));
    }

    fn devices(&mut self, ui: &mut Ui, v: &mut View) {
        let l = look(ui);
        ui.heading("Devices");
        let about = "Devices that hold this store sync with each other directly, \
                     sealed end to end. No account, no server keeps a copy.";
        ui.label(RichText::new(about).small().color(l.muted));
        let peers = sync::peers(&home());
        if peers.is_empty() {
            ui.label(RichText::new("No other device yet.").color(l.muted));
        }
        for p in &peers {
            ui.horizontal(|ui| {
                ui.label(&p.name);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.small_button("Forget").clicked() {
                        v.note = match sync::forget(&home(), &p.name) {
                            Ok(()) => format!("{}: forgotten", p.name),
                            Err(e) => format!("{e:#}"),
                        };
                    }
                });
            });
        }
        if !peers.is_empty() && ui.button("Sync now").clicked() {
            v.note = "Syncing".into();
            let (out, ctx) = (self.synced.clone(), ui.ctx().clone());
            std::thread::spawn(move || {
                let run = std::env::current_exe().and_then(|p| {
                    std::process::Command::new(p)
                        .arg("sync")
                        .stdin(std::process::Stdio::null())
                        .output()
                });
                let said = match run {
                    Ok(o) => String::from_utf8_lossy(&o.stderr)
                        .trim()
                        .replace('\n', "   "),
                    Err(e) => e.to_string(),
                };
                *out.lock().unwrap() = Some(said);
                ctx.request_repaint();
            });
        }
        ui.separator();
        ui.label(RichText::new("Add a device").strong());
        field(ui, "A name for it", &mut self.device, false);
        let ok = !self.device.trim().is_empty();
        if ui.add_enabled(ok, Button::new("Show a pairing code")).clicked() {
            let (name, pw) =
                (self.device.trim().to_string(), pairir::password());
            let made = self.rt().and_then(|rt| {
                rt.block_on(sync::pair(&mut v.s, &name, &pw, false))
            });
            match made {
                Ok((code, end)) => {
                    let state = "Waiting for it".into();
                    self.pairing = Some(Pairing { name, code, pw, end, state });
                }
                Err(e) => v.note = format!("{e:#}"),
            }
        }
        let Some(p) = &mut self.pairing else { return };
        if p.end.as_ref().is_some_and(|e| e.is_finished()) {
            let end = p
                .end
                .take()
                .zip(self.rt.as_ref())
                .map(|(e, rt)| rt.block_on(e));
            p.state = match end {
                Some(Ok(pairir::End::Taken)) => {
                    format!("{} took it: syncing", p.name)
                }
                Some(Ok(pairir::End::Expired)) => {
                    "Nobody came: show a new code".into()
                }
                Some(Ok(pairir::End::Spent)) => {
                    format!(
                        "Someone used the code without the password: forget {}, pair again",
                        p.name
                    )
                }
                _ => "The pairing broke off: try again".into(),
            };
            crate::aside(false);
        }
        ui.ctx().request_repaint_after(Duration::from_secs(1));
        let f = Frame::new().fill(l.bg).corner_radius(8).inner_margin(12);
        f.show(ui, |ui| {
            ui.set_width(ui.available_width());
            let how = format!("On {}: Join a store, then type", p.name);
            ui.label(RichText::new(how).small().color(l.muted));
            Grid::new("pairing").num_columns(2).spacing([14.0, 6.0]).show(
                ui,
                |ui| {
                    ui.label(RichText::new("Code").small().color(l.muted));
                    ui.label(RichText::new(&p.code).monospace().size(17.0));
                    ui.end_row();
                    ui.label(RichText::new("Password").small().color(l.muted));
                    ui.label(RichText::new(&p.pw).monospace().size(17.0));
                    ui.end_row();
                },
            );
            ui.label(RichText::new(&p.state).small().color(l.accent));
        });
    }

    fn settings(&mut self, ui: &mut Ui) {
        let l = look(ui);
        ui.heading("Settings");
        Grid::new("settings").num_columns(2).spacing([14.0, 10.0]).show(
            ui,
            |ui| {
                ui.label("Lock when left alone for");
                let minutes = |m: u64| {
                    if m == 1 {
                        "1 minute".into()
                    } else {
                        format!("{m} minutes")
                    }
                };
                ComboBox::from_id_salt("lock")
                    .selected_text(minutes(self.prefs.lock))
                    .show_ui(ui, |ui| {
                        for m in [1, 5, 15, 60] {
                            ui.selectable_value(
                                &mut self.prefs.lock,
                                m,
                                minutes(m),
                            );
                        }
                    });
                ui.end_row();
                ui.label("Theme");
                let name = |t| {
                    THEMES.iter().find(|x| x.1 == t).map_or("system", |x| x.0)
                };
                ComboBox::from_id_salt("theme")
                    .selected_text(name(self.prefs.theme))
                    .show_ui(ui, |ui| {
                        for (n, t) in THEMES {
                            if ui
                                .selectable_value(&mut self.prefs.theme, t, n)
                                .clicked()
                            {
                                ui.ctx().set_theme(t);
                            }
                        }
                    });
                ui.end_row();
            },
        );
        ui.separator();
        let about = format!(
            "pasa {}  ·  GPL-3.0-or-later\nStore: {}\nCopied secrets leave the clipboard after 45 s.",
            env!("CARGO_PKG_VERSION"),
            home().display()
        );
        ui.label(RichText::new(about).small().color(l.muted));
    }
}
