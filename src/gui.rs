//! `pasa gui`: the store in a window. A first run asks for the password
//! and, if wanted, a hardware key; joining another device's store waits in
//! the corner. Then groups, entries and the chosen one's fields, as the
//! Android app lays them out.

use crate::view::View;
use anyhow::{Context as _, Result};
use eframe::egui::{
    self, Align, Align2, Area, Button, CentralPanel, Color32, ColorImage,
    ComboBox, Context, FontId, Frame, Grid, Id, Key, Layout, Margin, Modal,
    Panel, Response, RichText, ScrollArea, Sense, Slider, Stroke, TextEdit,
    TextStyle, Theme, ThemePreference, Ui, Visuals, pos2, vec2,
};
use pasa::{Form, Store, home, sync};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
    /// Which of [`COLS`] the table shows; the title always.
    cols: [bool; 9],
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
            cols: std::array::from_fn(|i| {
                let on =
                    get("cols ").and_then(|c| c.as_bytes().get(i).copied());
                on.map_or([0, 1, 2, 4, 7].contains(&i), |b| b == b'1')
            }),
            theme: theme.map_or(ThemePreference::System, |t| t.1),
        }
    }
}

impl Prefs {
    fn save(&self) {
        let cols: String =
            self.cols.iter().map(|on| if *on { '1' } else { '0' }).collect();
        let theme =
            THEMES.iter().find(|t| t.1 == self.theme).map_or("system", |t| t.0);
        let _ = pasa::write(
            &home().join("ui"),
            format!("lock {}\ntheme {theme}\ncols {cols}\n", self.lock)
                .as_bytes(),
        );
    }
}

/// Entries whose password breaches hold, and how often.
type Breached = Vec<(String, u64)>;

/// The table's columns: what each is called, and how wide.
const COLS: [(&str, f32); 9] = [
    ("Title", 230.0),
    ("Username", 190.0),
    ("URL", 220.0),
    ("Tags", 130.0),
    ("Strength", 110.0),
    ("Expires", 100.0),
    ("Files", 60.0),
    ("Changed", 140.0),
    ("Notes", 260.0),
];

/// What a row shows of an entry, and a search looks through.
#[derive(Clone, Default)]
struct Meta {
    user: String,
    url: String,
    tags: String,
    notes: String,
    expires: String,
    bits: u32,
}

enum Job {
    Create,
    Unlock,
    /// By the YubiKey and the PIN.
    Quick,
    /// Quick unlock on for the open store, or off.
    SetQuick(bool),
    /// By a security key (FIDO2) and its PIN, if it has one.
    Fido,
    /// The security key plugged in opens the open store from now on.
    AddFido,
    Join,
}

#[derive(Default, PartialEq)]
enum Win {
    #[default]
    None,
    Generator,
    History,
    Health,
    Devices,
    Settings,
}

/// An entry in the form; `old`: its name before, or empty for a new one.
struct Edit {
    old: String,
    name: String,
    f: Form,
    show: bool,
    /// The Advanced tab, not the entry's.
    advanced: bool,
    /// How its password is made shows, to choose.
    making: bool,
}

struct Generator {
    /// Speakable words, else characters.
    words: bool,
    len: usize,
    symbols: bool,
    count: usize,
    /// What may stand between two words: one of these.
    seps: &'static str,
    leet: bool,
    pw: Zeroizing<String>,
}

impl Default for Generator {
    fn default() -> Generator {
        let pw = Zeroizing::new(pasa::generate(24, true));
        let (len, count) = (24, 4);
        let (words, symbols, seps, leet) = (false, true, "", false);
        Generator { words, len, symbols, count, seps, leet, pw }
    }
}

impl Generator {
    fn make(&self) -> String {
        match self.words {
            true => pasa::speakable(self.count, self.seps, self.leet),
            false => pasa::generate(self.len, self.symbols),
        }
    }

    /// How passwords are made, to choose; whether something was chosen.
    fn options(&mut self, ui: &mut Ui) -> bool {
        let (g, l) = (self, look(ui));
        let mut again = false;
        ui.horizontal(|ui| {
            again |= ui
                .selectable_value(&mut g.words, false, "Characters")
                .clicked();
            again |= ui
                .selectable_value(&mut g.words, true, "Speakable words")
                .clicked();
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let bits = format!("made of {} bits", g.bits());
                ui.label(RichText::new(bits).small().color(l.muted));
            });
        });
        match g.words {
            true => {
                let n = Slider::new(&mut g.count, 3..=8).text("words");
                again |= ui.add(n).changed();
                ui.horizontal(|ui| {
                    let between = [
                        ("", "Nothing: CapitalWords"),
                        ("-", "A dash"),
                        (".", "A period"),
                        ("_", "An underscore"),
                        ("-_.", "A dash, underscore or period"),
                        (pasa::SEPS, "Any symbol"),
                    ];
                    let now = between.iter().find(|b| b.0 == g.seps);
                    let now = now.map_or("", |b| b.1);
                    ui.label("Between words");
                    ComboBox::from_id_salt("seps").selected_text(now).show_ui(
                        ui,
                        |ui| {
                            for (seps, name) in between {
                                let r = ui.selectable_value(
                                    &mut g.seps,
                                    seps,
                                    name,
                                );
                                again |= r.clicked();
                            }
                        },
                    );
                    let leet = ui.checkbox(&mut g.leet, "1337");
                    again |= leet
                        .on_hover_text("Some letters as @ 3 1 0 $ 7")
                        .changed();
                });
            }
            false => {
                let n = Slider::new(&mut g.len, 8..=64).text("characters");
                again |= ui.add(n).changed();
                again |= ui.checkbox(&mut g.symbols, "Symbols").changed();
            }
        }
        again
    }

    /// The bits of chance that go into a password made this way.
    fn bits(&self) -> u32 {
        let abc: f64 = if self.symbols { 80.0 } else { 62.0 };
        match self.words {
            true => pasa::speakable_bits(self.count, self.seps),
            false => (self.len as f64 * abc.log2()) as u32,
        }
    }
}

/// A device being added: for a QR code, its password first (never shown
/// beside the code), then the code; and how a short code ends.
struct Pairing {
    name: String,
    /// The QR code's password, while it is chosen.
    pw: Option<Zeroizing<String>>,
    code: String,
    /// The QR code, once shown.
    img: Option<egui::TextureHandle>,
    /// How a short code ended, from the network side.
    end: Option<Arc<Mutex<Option<String>>>>,
    state: String,
}

/// The camera looking for a QR code, beside the window: the frame it last
/// saw, and what it found or why it stopped.
struct Scanning {
    frame: Arc<Mutex<Option<crate::scan::Frame>>>,
    found: Arc<Mutex<Option<Result<String, String>>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    img: Option<egui::TextureHandle>,
}

impl Scanning {
    fn start(ctx: &Context) -> Scanning {
        let s = Scanning {
            frame: Default::default(),
            found: Default::default(),
            stop: Default::default(),
            img: None,
        };
        let (frame, found, stop) =
            (s.frame.clone(), s.found.clone(), s.stop.clone());
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let go = || -> Result<String> {
                let mut c = crate::scan::Camera::open()?;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let f = c.frame()?;
                    if let Some(t) = crate::scan::read(&f) {
                        return Ok(t);
                    }
                    *frame.lock().unwrap_or_else(|p| p.into_inner()) = Some(f);
                    ctx.request_repaint();
                }
                anyhow::bail!("stopped")
            };
            let r = go().map_err(|e| format!("{e:#}"));
            *found.lock().unwrap_or_else(|p| p.into_inner()) = Some(r);
            ctx.request_repaint();
        });
        s
    }
}

impl Drop for Scanning {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// `text` as a QR code, a module a pixel, with its quiet zone.
fn qr_image(ctx: &Context, text: &str) -> Result<egui::TextureHandle> {
    let c = qrcode::QrCode::new(text)?;
    let (w, dark, q) = (c.width(), c.to_colors(), 4);
    let n = w + 2 * q;
    let at = |i: usize| {
        let (x, y) = ((i % n).wrapping_sub(q), (i / n).wrapping_sub(q));
        let on = x < w && y < w && dark[y * w + x] == qrcode::Color::Dark;
        if on { 0 } else { 255 }
    };
    let img = egui::ColorImage::from_gray_iter([n, n], (0..n * n).map(at));
    Ok(ctx.load_texture("pairing", img, egui::TextureOptions::NEAREST))
}

#[derive(Default)]
struct App {
    v: Option<View>,
    prefs: Prefs,
    /// By the clock that runs while the machine sleeps.
    used: Option<SystemTime>,
    // Before the store is open.
    pw: Zeroizing<String>,
    pw2: Zeroizing<String>,
    yk: bool,
    /// The secret of the key just set up, for a spare.
    key_secret: Option<Zeroizing<Vec<u8>>>,
    /// The key opens the store quickly, beside the password; else it is
    /// needed with the password, every time.
    quick: bool,
    pin: Zeroizing<String>,
    /// The store's password as generated here, and its bits.
    made: (Zeroizing<String>, u32),
    /// At the unlock: the password, though quick unlock is on.
    joining: bool,
    peer: String,
    code: String,
    pair_pw: Zeroizing<String>,
    /// A pairing taken: the store comes, and its password opens it.
    joined: bool,
    /// Done at the next frame, once this one has said so.
    job: Option<Job>,
    said: String,
    // The open store.
    group: Option<String>,
    /// Each version's user, address and tags, read once: what rows show
    /// and a search looks through.
    meta: HashMap<String, Meta>,
    /// The store in numbers, while its tab shows.
    stats: Option<Vec<(&'static str, String)>>,
    numbers: bool,
    tag: Option<String>,
    /// What a breach check found, entry by entry, once it is back.
    breached: Arc<Mutex<Option<Breached>>>,
    health: Option<pasa::Health>,
    shown: bool,
    armed: bool,
    edit: Option<Edit>,
    win: Win,
    /// In History: the version looked at, the one it is compared with,
    /// and whether passwords show.
    hist: (usize, usize, bool),
    generator: Generator,
    device: String,
    pairing: Option<Pairing>,
    /// The camera, while it looks for a QR code.
    scanning: Option<Scanning>,
    /// What syncs said, beside the window, until shown.
    synced: Arc<Mutex<Option<String>>>,
    /// Whether this window serves (from the first pairing on).
    serving: bool,
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
        let a = App { peer: "home".into(), quick: true, ..App::default() };
        c.egui_ctx.set_theme(a.prefs.theme);
        Ok(Box::new(a) as Box<dyn eframe::App>)
    };
    eframe::run_native("pasa", o, Box::new(app))
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// A muted label over a field as wide as its place. A secret is hidden,
/// with an eye beside it to show it: which, the field's label remembers.
fn field(
    ui: &mut Ui,
    label: &str,
    text: &mut String,
    secret: bool,
) -> Response {
    let l = look(ui);
    ui.label(RichText::new(label).small().color(l.muted));
    if !secret {
        let t = TextEdit::singleline(text).desired_width(f32::INFINITY);
        return ui.add(t.margin(Margin::symmetric(8, 6)));
    }
    let id = ui.scope_id().with(("shown", label));
    let mut shown = ui.data(|d| d.get_temp::<bool>(id)).unwrap_or(false);
    let r = ui.horizontal(|ui| {
        let (rect, eye) =
            ui.allocate_exact_size(vec2(30.0, 30.0), Sense::click());
        // An eye, struck through while what it watches is hidden.
        let (c, ink) = (rect.center(), Stroke::new(1.6, l.muted));
        let lid = [
            vec2(-9.0, 0.0),
            vec2(-4.5, -5.0),
            vec2(4.5, -5.0),
            vec2(9.0, 0.0),
            vec2(4.5, 5.0),
            vec2(-4.5, 5.0),
        ];
        let lid = lid.iter().map(|v| c + *v).collect();
        ui.painter().add(egui::Shape::closed_line(lid, ink));
        ui.painter().circle_filled(c, 2.6, l.muted);
        if !shown {
            ui.painter()
                .line_segment([c + vec2(-8.0, 8.0), c + vec2(8.0, -8.0)], ink);
        }
        if eye.on_hover_text(if shown { "Hide" } else { "Show" }).clicked() {
            shown ^= true;
        }
        let t = TextEdit::singleline(text).password(!shown);
        ui.add(t.desired_width(f32::INFINITY).margin(Margin::symmetric(8, 6)))
    });
    ui.data_mut(|d| d.insert_temp(id, shown));
    r.inner
}

/// `body` as `file` in the downloads folder, under a name not yet there.
fn saved(file: &str, body: &[u8]) -> Result<String> {
    // A name, never a path: an entry's name is whatever a device wrote.
    let file = std::path::Path::new(file).file_name().context("no name")?;
    let file = &*file.to_string_lossy();
    let dir =
        std::env::var_os("XDG_DOWNLOAD_DIR").map(std::path::PathBuf::from);
    let home = || std::env::home_dir().unwrap_or_default().join("Downloads");
    let dir = dir.unwrap_or_else(home);
    let free = |i: &u32| {
        let name = if *i == 0 { file.into() } else { format!("{i}-{file}") };
        Some(dir.join(name)).filter(|p| !p.exists())
    };
    let to = (0..1000).find_map(|i| free(&i)).context("no free name")?;
    pasa::write(&to, body)?;
    Ok(format!("{file}: saved as {}", to.display()))
}

/// In the browser.
fn open_url(url: &str) {
    let with = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
    let _ = std::process::Command::new(with).arg(url).spawn();
}

/// The day `days` from now, as YYYY-MM-DD.
fn day(days: u64) -> String {
    let at = std::time::SystemTime::now() + Duration::from_secs(days * 86_400);
    humantime::format_rfc3339_seconds(at).to_string()[..10].into()
}

/// A time in milliseconds, as a date and a minute.
fn date(ms: u64) -> String {
    let at = UNIX_EPOCH + Duration::from_millis(ms);
    let at = humantime::format_rfc3339_seconds(at).to_string();
    at[..16].replace('T', " ")
}

/// What so many bits are called, and their colour: under 40 poor, under
/// 65 weak, under 100 good.
fn grade(bits: u32) -> (&'static str, Color32) {
    match bits {
        0..40 => ("Poor", rgb(0xE5604F)),
        40..65 => ("Weak", rgb(0xE0A040)),
        65..100 => ("Good", rgb(0x9CC25A)),
        _ => ("Excellent", rgb(0x4FB286)),
    }
}

/// A bar that fills and turns from red to green as a password's bits grow.
fn meter(ui: &mut Ui, bits: u32) {
    meter_to(ui, bits, 0)
}

/// [`meter`], full at `goal` and saying how far that is (0: no goal). The
/// store's own password has one, 256: a suggestion, nothing is refused.
fn meter_to(ui: &mut Ui, bits: u32, goal: u32) {
    let (name, colour) = grade(bits);
    let full = if goal > 0 { goal } else { 128 } as f32;
    let (rect, _) =
        ui.allocate_exact_size(vec2(ui.available_width(), 6.0), Sense::hover());
    ui.painter().rect_filled(rect, 3, look(ui).line);
    let mut filled = rect;
    filled.set_width(rect.width() * (bits as f32 / full).min(1.0));
    ui.painter().rect_filled(filled, 3, colour);
    let said = match goal {
        0 => format!("{name}: about {bits} bits"),
        g if bits >= g => {
            format!("About {bits} bits: the {g} suggested, and more")
        }
        g => format!("About {bits} bits of the {g} suggested"),
    };
    ui.label(RichText::new(said).small().color(colour));
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
        let top = (ui.available_height() * 0.14).max(20.0);
        let scroll = ScrollArea::vertical().auto_shrink(false);
        scroll.show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(top);
                ui.label(
                    RichText::new("pasa").size(36.0).strong().color(l.accent),
                );
                ui.label(RichText::new(about).color(l.muted));
                ui.add_space(16.0);
                let f =
                    Frame::new().fill(l.card).stroke(Stroke::new(1.0, l.line));
                f.corner_radius(12).inner_margin(22).show(ui, |ui| {
                    ui.set_width(360.0);
                    ui.with_layout(Layout::top_down(Align::Min), |ui| {
                        ui.label(RichText::new(title).size(18.0).strong());
                        ui.add_space(4.0);
                        body(ui);
                    });
                });
                ui.add_space(40.0);
            })
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
        if ui.input(|i| i.modifiers.command && i.key_pressed(Key::Q)) {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
        // Left alone: locked, the store and what was typed dropped.
        if ui.input(|i| !i.events.is_empty() || i.pointer.is_moving()) {
            self.used = Some(SystemTime::now());
        }
        let idle = Duration::from_secs(self.prefs.lock * 60);
        // Asleep counts as left alone; so does a clock set back.
        let left = |t: SystemTime| t.elapsed().map_or(true, |e| e > idle);
        if self.v.is_some() && self.used.is_some_and(left) {
            self.lock();
        }
        ui.ctx().request_repaint_after(idle);
        self.serve(&ui.ctx().clone());
        if let Some(job) = self.job.take() {
            let was = (self.v.is_some(), self.joined);
            self.said = self
                .work(job)
                .err()
                .map(|e| format!("{e:#}"))
                .unwrap_or_default();
            // Just joined, or opened: a sync, which shows what it brought
            // when done. Joined, the store comes before the password.
            if was != (self.v.is_some(), self.joined) {
                self.sync_now(ui.ctx(), false);
            }
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
            synced: self.synced.clone(),
            serving: self.serving,
            peer: "home".into(),
            quick: true,
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
                let both = self.yk && !self.quick;
                let r = both.then(|| crate::yubikey(&c)).transpose()?;
                let yk = r.as_ref().map(|r| (&c[..], &r[..]));
                let s = Store::create(&home(), self.pw.as_bytes(), yk)?;
                if self.yk && self.quick {
                    crate::quick_on(&s, self.pin.as_bytes())?;
                }
                (self.v, self.key_secret) = (Some(View::new(s)), None);
            }
            Job::Quick => {
                let (c, _) =
                    pasa::quick(&home()).context("quick unlock is off")?;
                let s = crate::unlock_quick(&c, self.pin.as_bytes())?;
                self.v = Some(View::new(s));
            }
            Job::Fido => {
                let s = crate::unlock_fido(Some(self.pin.as_bytes()))?;
                self.v = Some(View::new(s));
            }
            Job::AddFido => {
                let v = self.v.as_ref().context("locked")?;
                crate::fido_add(&v.s, Some(self.pin.as_bytes()))?;
            }
            Job::SetQuick(on) => {
                let v = self.v.as_ref().context("locked")?;
                match on {
                    true => crate::quick_on(&v.s, self.pin.as_bytes())?,
                    false => std::fs::remove_file(home().join("quick"))?,
                }
            }
            Job::Unlock => {
                let s = crate::unlock(self.pw.as_bytes())?;
                (self.v, self.pairing) = (Some(View::new(s)), None);
            }
            Job::Join => {
                let (peer, code, pw) = (
                    self.peer.trim().to_string(),
                    self.code.trim().to_string(),
                    self.pair_pw.clone(),
                );
                // A QR code opens here, offline; a short code is the
                // network side's to take.
                let got = match code.starts_with("PAIRIR1:") {
                    true => self.rt()?.block_on(sync::unqr(&code, &pw))?,
                    false => {
                        let mut c = crate::net(&["take", &code])?;
                        let l = crate::lines(&mut c).next();
                        let l =
                            l.context("no answer: is the code still shown?")?;
                        Zeroizing::new(crate::B64.decode(l.as_bytes())?)
                    }
                };
                sync::take(&home(), &peer, &got)?;
                self.joined = true;
            }
        }
        (self.pw, self.pw2, self.pair_pw) = Default::default();
        self.pin = Default::default();
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
            let small = |ui: &mut Ui, t: &str, c: Color32| {
                ui.label(RichText::new(t).small().color(c));
            };
            small(
                ui,
                "Its password opens everything, and is the way back in when all \
                 else is lost: a long one. 256 bits is the suggestion.",
                l.muted,
            );
            let first = field(ui, "Password", &mut self.pw, true);
            if ui.memory(|m| m.focused().is_none()) {
                first.request_focus();
            }
            // A generated one's bits are known; a typed one's are guessed.
            let ours = !self.pw.is_empty() && *self.pw == *self.made.0;
            if !self.pw.is_empty() {
                let bits =
                    if ours { self.made.1 } else { pasa::strength(&self.pw) };
                meter_to(ui, bits, 256);
            }
            if ui.button("Generate one and show it").clicked() {
                let pw = Zeroizing::new(pasa::speakable(12, "-", false));
                (self.pw, self.pw2) = (pw.clone(), pw.clone());
                self.made = (pw, 12 * 22);
            }
            if ours {
                let f =
                    Frame::new().fill(l.bg).corner_radius(8).inner_margin(10);
                f.show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(&**self.pw).monospace().size(15.0));
                });
                small(
                    ui,
                    "Twelve made-up words, 264 bits. Write it down and keep it \
                     somewhere safe before going on.",
                    l.accent,
                );
            }
            let again = field(ui, "Password, again", &mut self.pw2, true);
            // What is wrong with it, right under it.
            if !self.pw2.is_empty() && *self.pw != *self.pw2 {
                small(ui, "The passwords differ", l.bad);
            }
            ui.add_space(4.0);
            ui.checkbox(&mut self.yk, "Use a hardware key (YubiKey)");
            if self.yk {
                self.new_key(ui);
                ui.radio_value(&mut self.quick, true, "To unlock quickly");
                small(
                    ui,
                    "A tap and a PIN open the store. The password still opens \
                     it alone if the key is lost.",
                    l.muted,
                );
                if self.quick {
                    field(ui, "PIN (empty: none)", &mut self.pin, true);
                }
                ui.radio_value(&mut self.quick, false, "As a second factor");
                small(
                    ui,
                    "Needed together with the password, every time.",
                    l.muted,
                );
            }
            ui.add_space(6.0);
            let ok = !self.pw.is_empty() && *self.pw == *self.pw2;
            let go = ui
                .add_enabled_ui(ok, |ui| primary(ui, "Create store", true))
                .inner;
            if ok && (go.clicked() || entered(ui, &again)) {
                let say =
                    if self.yk { "Touch your YubiKey" } else { "Creating" };
                self.begin(ui, Job::Create, say);
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
                       (or pasa pair NAME). It shows a code to type, or a \
                       QR code after its password.";
            ui.label(RichText::new(how).small().color(l.muted));
            field(ui, "A name for that device", &mut self.peer, false);
            let mut pw = field(ui, "Code", &mut self.code, false);
            self.scan(ui);
            // A QR code's text asks for its password; a typed code has none.
            if self.code.trim().starts_with("PAIRIR1:") {
                pw = field(
                    ui,
                    "The QR code's password",
                    &mut self.pair_pw,
                    true,
                );
            }
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

    /// Scan the other device's QR code with the camera, offline: its
    /// text goes in the Code field, and its password is asked for.
    fn scan(&mut self, ui: &mut Ui) {
        let l = look(ui);
        // A picture of the code (a photo of the other screen), dropped on
        // the window: read here, as camera frames are.
        let dropped = ui.ctx().input(|i| i.raw.dropped_files.clone());
        if let Some(p) = dropped.first().map(|f| f.path().to_path_buf()) {
            let got = crate::scan::picture(&p).map(|f| crate::scan::read(&f));
            match got {
                Ok(Some(t)) => (self.code, self.said) = (t, String::new()),
                Ok(None) => {
                    self.said = "No QR code read in that picture".into()
                }
                Err(e) => self.said = format!("{e:#}"),
            }
            self.scanning = None;
        }
        let Some(s) = &mut self.scanning else {
            let tip = "The camera reads the code the other device shows: \
                       nothing goes online, no frame is kept";
            if ui.button("Scan with the camera").on_hover_text(tip).clicked() {
                self.scanning = Some(Scanning::start(ui.ctx()));
            }
            let or = "Or drop a picture of the code on this window";
            ui.label(RichText::new(or).small().color(l.muted));
            return;
        };
        // Taken out of the lock first: the result outlives the guard.
        let r = s.found.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(r) = r {
            match r {
                Ok(t) => (self.code, self.said) = (t, String::new()),
                Err(e) if e == "stopped" => {}
                Err(e) => self.said = e,
            }
            self.scanning = None;
            return;
        }
        if let Some(f) =
            s.frame.lock().unwrap_or_else(|p| p.into_inner()).take()
        {
            let img = ColorImage::from_gray([f.w, f.h], &f.px);
            match &mut s.img {
                Some(t) => t.set(img, egui::TextureOptions::LINEAR),
                None => {
                    let o = egui::TextureOptions::LINEAR;
                    s.img = Some(ui.ctx().load_texture("camera", img, o));
                }
            }
        }
        let say = "Hold the other device's QR code to the camera";
        ui.label(RichText::new(say).small().color(l.muted));
        if let Some(t) = &s.img {
            let [w, h] = t.size();
            let h = 352.0 * h as f32 / w.max(1) as f32;
            ui.image((t.id(), vec2(352.0, h)));
        }
        if ui.button("Stop the camera").clicked() {
            self.scanning = None;
        }
    }

    fn unlock(&mut self, ui: &mut Ui) {
        let key = std::fs::read(home().join("key")).unwrap_or_default();
        let yk = pasa::challenge(&key).is_some();
        let title =
            if self.joined { "Joined: now its password" } else { "Unlock" };
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
            // Every other way in is here too: the quick-unlock YubiKey, a
            // security key (CTAP2). One PIN field serves whichever is used.
            let (quick, keys) = (pasa::quick(&home()), pasa::fido(&home()));
            if quick.is_some() || keys.is_some() {
                ui.separator();
                let l = look(ui);
                ui.label(RichText::new("Or a key").small().color(l.muted));
                let pin = quick.as_ref().is_some_and(|q| q.1);
                if pin
                    || keys.as_ref().is_some_and(|f| f.keys.iter().any(|k| k.1))
                {
                    field(ui, "PIN", &mut self.pin, true);
                }
                ui.horizontal_wrapped(|ui| {
                    if keys.is_some()
                        && ui.button("Unlock with a security key").clicked()
                    {
                        let say = "Plug in your security key and touch it";
                        self.begin(ui, Job::Fido, say);
                    }
                    if quick.is_some()
                        && ui.button("Unlock with the YubiKey").clicked()
                    {
                        self.begin(ui, Job::Quick, "Touch your YubiKey");
                    }
                });
            }
            self.said(ui);
        });
    }

    /// What a row shows of the entry, read once per version.
    fn meta(&mut self, v: &View, i: usize) -> &Meta {
        let read = || {
            let b = v.s.get(&v.names[i]).unwrap_or_default();
            let f = Form::parse(&String::from_utf8_lossy(&b));
            let notes = f.notes.lines().next().unwrap_or_default().into();
            let bits = pasa::strength(&f.pass);
            Meta {
                user: f.user,
                url: f.url,
                tags: f.tags,
                notes,
                expires: f.expires,
                bits,
            }
        };
        self.meta.entry(v.files[i].clone()).or_insert_with(read)
    }

    /// The user names most entries have, the commonest first.
    fn users(&self) -> Vec<String> {
        let mut n: HashMap<&str, usize> = HashMap::new();
        for m in self.meta.values().filter(|m| !m.user.is_empty()) {
            *n.entry(&m.user).or_default() += 1;
        }
        let mut by: Vec<(usize, &str)> =
            n.into_iter().map(|(u, n)| (n, u)).collect();
        by.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
        by.into_iter().take(5).map(|u| u.1.to_string()).collect()
    }

    fn store(&mut self, ui: &mut Ui, mut v: View) {
        let l = look(ui);
        let ctx = ui.ctx().clone();
        if let Some(s) =
            self.synced.lock().unwrap_or_else(|p| p.into_inner()).take()
        {
            v.note = s;
        }
        // The search looks through names, users, addresses and tags; View's
        // own filter (names alone, for the terminal) is left empty here.
        let query = std::mem::take(&mut v.filter);
        v.load();
        v.filter = query;
        let dir = |n: &str| n.rsplit_once('/').map(|d| d.0.to_string());
        let groups: BTreeSet<String> =
            v.names.iter().filter_map(|n| dir(n)).collect();
        if self.group.as_ref().is_some_and(|g| !groups.contains(g)) {
            self.group = None;
        }
        let words: Vec<String> = v
            .filter
            .to_lowercase()
            .split_whitespace()
            .map(Into::into)
            .collect();
        let mut tags = BTreeSet::new();
        let mut rows = vec![];
        for i in 0..v.names.len() {
            let name = v.names[i].clone();
            let m = self.meta(&v, i).clone();
            let of: Vec<&str> = m.tags.split(',').map(str::trim).collect();
            tags.extend(
                of.iter().filter(|t| !t.is_empty()).map(|t| t.to_string()),
            );
            let hay =
                format!("{name} {} {} {} {}", m.user, m.url, m.tags, m.notes);
            let hay = hay.to_lowercase();
            let tagged = self.tag.as_ref().is_none_or(|t| of.contains(&&**t));
            let within = self.group.is_none() || dir(&name) == self.group;
            if tagged && within && words.iter().all(|w| hay.contains(w)) {
                rows.push(i);
            }
        }
        if self.tag.as_ref().is_some_and(|t| !tags.contains(t)) {
            self.tag = None;
        }
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
                    lock |= ui
                        .button("Lock")
                        .on_hover_text("Ctrl+L; Ctrl+Q quits")
                        .clicked();
                    for (name, win) in [
                        ("Settings", Win::Settings),
                        ("Devices", Win::Devices),
                        ("Health", Win::Health),
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
                if !tags.is_empty() {
                    ui.add_space(10.0);
                    ui.label(RichText::new("TAGS").small().color(l.muted));
                }
                for t in &tags {
                    let on = self.tag.as_ref() == Some(t);
                    if ui.selectable_label(on, t).clicked() {
                        self.tag = (!on).then(|| t.clone());
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

        let mut act = None;
        CentralPanel::default().show(ui, |ui| {
            let shown: Vec<usize> = (0..COLS.len())
                .filter(|c| *c == 0 || self.prefs.cols[*c])
                .collect();
            let wide: f32 =
                shown.iter().map(|c| COLS[*c].1).sum::<f32>() + 20.0;
            let put = |ui: &Ui,
                       x: f32,
                       w: f32,
                       y: f32,
                       t: &str,
                       c: Color32,
                       small: bool| {
                let f = FontId::proportional(if small { 12.5 } else { 15.0 });
                let clip = egui::Rect::from_min_max(
                    pos2(x, y - 15.0),
                    pos2(x + w - 12.0, y + 15.0),
                );
                ui.painter()
                    .with_clip_rect(clip.intersect(ui.clip_rect()))
                    .text(pos2(x, y), Align2::LEFT_CENTER, t, f, c);
            };
            let today = pasa::today();
            ScrollArea::horizontal().auto_shrink(false).show(ui, |ui| {
                let width = wide.max(ui.available_width());
                let (rect, head) =
                    ui.allocate_exact_size(vec2(width, 22.0), Sense::click());
                let mut x = rect.left() + 10.0;
                for c in &shown {
                    let title = COLS[*c].0.to_uppercase();
                    put(
                        ui,
                        x,
                        COLS[*c].1,
                        rect.center().y,
                        &title,
                        l.muted,
                        true,
                    );
                    x += COLS[*c].1;
                }
                // The header's menu: which columns show.
                head.on_hover_text("Right-click: columns").context_menu(|ui| {
                    ui.label(RichText::new("COLUMNS").small().color(l.muted));
                    for (c, col) in COLS.iter().enumerate().skip(1) {
                        ui.checkbox(&mut self.prefs.cols[c], col.0);
                    }
                });
                ui.separator();
                if rows.is_empty() {
                    let none = if v.names.is_empty() {
                        "No entries yet. New adds the first."
                    } else {
                        "Nothing matches."
                    };
                    ui.add_space(24.0);
                    ui.label(RichText::new(none).color(l.muted));
                }
                ScrollArea::vertical().auto_shrink(false).show_rows(
                    ui,
                    30.0,
                    rows.len(),
                    |ui, range| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        for i in range {
                            let at = rows[i];
                            // Deleted this frame (in the entry pane, drawn
                            // first), or by a sync since: the list is
                            // shorter; the next frame draws it anew.
                            if at >= v.names.len() {
                                continue;
                            }
                            let m = self.meta(&v, at).clone();
                            let (rect, r) = ui.allocate_exact_size(
                                vec2(width, 30.0),
                                Sense::click(),
                            );
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
                            let (mut x, y) =
                                (rect.left() + 10.0, rect.center().y);
                            for c in &shown {
                                let w = COLS[*c].1;
                                let grey = |t: &str| {
                                    put(ui, x, w, y, t, l.muted, false)
                                };
                                match *c {
                                    0 => put(ui, x, w, y, title, l.text, false),
                                    1 => grey(&m.user),
                                    2 => grey(&m.url),
                                    3 => grey(&m.tags),
                                    4 => {
                                        // A short bar in the grade's colour, then the bits.
                                        let (_, colour) = grade(m.bits);
                                        let full = egui::Rect::from_min_size(
                                            pos2(x, y - 3.0),
                                            vec2(44.0, 6.0),
                                        );
                                        let mut bar = full;
                                        bar.set_width(
                                            44.0 * (m.bits as f32 / 128.0)
                                                .min(1.0),
                                        );
                                        ui.painter()
                                            .rect_filled(full, 3, l.line);
                                        ui.painter()
                                            .rect_filled(bar, 3, colour);
                                        put(
                                            ui,
                                            x + 52.0,
                                            w - 52.0,
                                            y,
                                            &m.bits.to_string(),
                                            l.muted,
                                            true,
                                        );
                                    }
                                    5 if !m.expires.is_empty()
                                        && m.expires < today =>
                                    {
                                        put(
                                            ui, x, w, y, &m.expires, l.bad,
                                            false,
                                        )
                                    }
                                    5 => grey(&m.expires),
                                    6 if v.kept[at] > 0 => {
                                        grey(&v.kept[at].to_string())
                                    }
                                    7 => grey(&date(v.ms[at])),
                                    8 => grey(&m.notes),
                                    _ => {}
                                }
                                x += w;
                            }
                            if r.clicked() || r.secondary_clicked() {
                                v.at = at;
                            }
                            if r.double_clicked() {
                                act = Some((at, "pass"));
                            }
                            // What can be done with an entry, under the pointer.
                            r.context_menu(|ui| {
                                let web = m.url.starts_with("http");
                                for (what, text, on) in [
                                    (
                                        "user",
                                        "Copy username",
                                        !m.user.is_empty(),
                                    ),
                                    ("pass", "Copy password", true),
                                    ("otp", "Copy one-time code", true),
                                    ("url", "Copy URL", !m.url.is_empty()),
                                    ("open", "Open URL", web),
                                    ("edit", "Edit", true),
                                    ("history", "History", true),
                                    ("delete", "Delete", true),
                                ] {
                                    if matches!(what, "edit" | "delete") {
                                        ui.separator();
                                    }
                                    if ui
                                        .add_enabled(on, Button::new(text))
                                        .clicked()
                                    {
                                        act = Some((at, what));
                                        ui.close();
                                    }
                                }
                            });
                        }
                    },
                );
            });
        });
        if let Some((at, what)) = act {
            v.at = at;
            match what {
                "edit" => self.edit_entry(&v),
                "history" => {
                    (self.win, self.hist) = (Win::History, (0, 0, false))
                }
                "open" => open_url(&self.meta(&v, at).url.clone()),
                "delete" => {
                    self.armed = true;
                    v.note =
                        format!("{}: Really delete, to delete it", v.names[at]);
                }
                field => v.copy(field),
            }
        }

        if v.at != was && act.is_none() {
            (self.shown, self.armed) = (false, false);
        }
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        for (path, name) in
            dropped.iter().map(|f| f.path()).zip(chosen.iter().cycle())
        {
            v.change(|s| {
                let file = path.file_name().context("not a file")?;
                let file = file.to_string_lossy();
                let body = Zeroizing::new(std::fs::read(path)?);
                s.put(&format!("{name}{}{file}", pasa::FILES), &body)?;
                Ok(format!("{file}: kept with {name}"))
            });
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
        let f = Form { pass: self.generator.make(), ..Form::default() };
        self.edit = Some(Edit {
            old: String::new(),
            name,
            f,
            show: false,
            advanced: false,
            making: false,
        });
    }

    fn edit_entry(&mut self, v: &View) {
        if let Some(n) = v.name() {
            let f = Form::parse(&String::from_utf8_lossy(&v.body()));
            self.edit = Some(Edit {
                old: n.into(),
                name: n.into(),
                f,
                show: false,
                advanced: false,
                making: false,
            });
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
                        v.change(|s| {
                            s.remove(name)?;
                            Ok(format!("{name}: deleted; its history stays"))
                        });
                        ui.ctx().request_repaint();
                    }
                    self.armed ^= true;
                }
                if ui.button("History").clicked() {
                    (self.win, self.hist) = (Win::History, (0, 0, false));
                }
                if ui.button("Edit").clicked() {
                    self.edit_entry(v);
                }
            });
        });
        if let Ok(Some((made, changed))) = v.s.times(name) {
            let when =
                format!("Changed {}   ·   Made {}", date(changed), date(made));
            ui.label(RichText::new(when).small().color(l.muted));
        }
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
                        ui.horizontal(|ui| {
                            if ui.small_button("Copy").clicked() {
                                v.copy("url");
                            }
                            let web = f.url.starts_with("https://")
                                || f.url.starts_with("http://");
                            if web && ui.small_button("Open").clicked() {
                                open_url(&f.url);
                            }
                        });
                        ui.end_row();
                    }
                    if !f.tags.is_empty() {
                        label(ui, "Tags");
                        ui.label(&f.tags);
                        ui.end_row();
                    }
                    if !f.notes.is_empty() {
                        label(ui, "Notes");
                        ui.label(&f.notes);
                        ui.end_row();
                    }
                    for file in v.s.files(name).unwrap_or_default() {
                        let at = format!("{name}{}{file}", pasa::FILES);
                        label(ui, "File");
                        ui.label(&file);
                        ui.horizontal(|ui| {
                            if ui.small_button("Save").clicked() {
                                v.change(|s| saved(&file, &s.get(&at)?));
                            }
                            if ui.small_button("Remove").clicked() {
                                v.change(|s| {
                                    s.put(&at, b"")?;
                                    Ok(format!("{file}: removed"))
                                });
                            }
                        });
                        ui.end_row();
                    }
                },
            );
            let hint = "Drop a file on the window to keep it with this entry.";
            ui.label(RichText::new(hint).small().color(l.muted));
        });
    }

    /// Weak, shared and, if asked, breached passwords.
    fn health(&mut self, ui: &mut Ui, v: &mut View) {
        let l = look(ui);
        ui.horizontal(|ui| {
            ui.heading("Password health");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.selectable_value(&mut self.numbers, true, "Statistics");
                ui.selectable_value(&mut self.numbers, false, "Health");
            });
        });
        if self.numbers {
            if self.stats.is_none() {
                self.stats = v.s.stats().ok();
            }
            let rows = self.stats.clone().unwrap_or_default();
            ScrollArea::vertical().max_height(380.0).show(ui, |ui| {
                Grid::new("stats")
                    .num_columns(2)
                    .striped(true)
                    .spacing([24.0, 6.0])
                    .show(ui, |ui| {
                        for (what, n) in rows {
                            ui.label(what);
                            ui.label(RichText::new(n).strong());
                            ui.end_row();
                        }
                    });
            });
            return;
        }
        if self.health.is_none() {
            self.health = v.s.health().ok();
        }
        let h = self.health.clone().unwrap_or_default();
        let (weak, reused, expired) = (h.weak, h.reused, h.expired);
        let part = |ui: &mut Ui, t: String| {
            ui.add_space(4.0);
            ui.label(RichText::new(t).small().color(l.muted));
        };
        ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
            ui.set_width(ui.available_width());
            part(ui, format!("WEAK: {}", weak.len()));
            for (name, bits) in &weak {
                ui.horizontal(|ui| {
                    ui.label(name);
                    ui.label(
                        RichText::new(format!("about {bits} bits"))
                            .small()
                            .color(grade(*bits).1),
                    );
                });
            }
            part(ui, format!("SHARED BY SEVERAL ENTRIES: {}", reused.len()));
            for group in &reused {
                ui.label(group.join(",  "));
            }
            part(ui, format!("EXPIRED: {}", expired.len()));
            for name in &expired {
                ui.label(name);
            }
            if let Some(found) =
                &*self.breached.lock().unwrap_or_else(|p| p.into_inner())
            {
                let hit = found.iter().filter(|f| f.1 > 0).count();
                part(ui, format!("IN KNOWN BREACHES: {hit}"));
                for (name, times) in found {
                    let said = match times {
                        0 => "could not be checked".into(),
                        n => format!("seen {n} times"),
                    };
                    ui.horizontal(|ui| {
                        ui.label(name);
                        ui.label(RichText::new(said).small().color(l.bad));
                    });
                }
            }
        });
        ui.separator();
        let how = match std::env::var_os("PASA_PWNED") {
            Some(_) => {
                "A breach check reads the local list PASA_PWNED names: \
                 nothing leaves this machine."
            }
            None => {
                "A breach check asks haveibeenpwned.com. Of each password \
                 only the first 5 hex digits of its SHA-1 leave this \
                 machine; the site cannot tell which password was meant."
            }
        };
        ui.label(RichText::new(how).small().color(l.muted));
        if ui.button("Check for breaches").clicked() {
            v.note = "Checking for breaches".into();
            let pws: Vec<(String, String)> = v
                .names
                .iter()
                .map(|n| {
                    (
                        n.clone(),
                        Form::parse(&String::from_utf8_lossy(
                            &v.s.get(n).unwrap_or_default(),
                        ))
                        .pass,
                    )
                })
                .filter(|p| !p.1.is_empty())
                .collect();
            let (out, ctx) = (self.breached.clone(), ui.ctx().clone());
            std::thread::spawn(move || {
                let hit = |(n, pw): &(String, String)| match crate::pwned(pw) {
                    Ok(0) => None,
                    // Not asked is not clean: 0 says so.
                    Err(_) => Some((n.clone(), 0)),
                    Ok(times) => Some((n.clone(), times)),
                };
                *out.lock().unwrap_or_else(|p| p.into_inner()) =
                    Some(pws.iter().filter_map(hit).collect());
                ctx.request_repaint();
            });
        }
    }

    /// The chosen entry's versions: what it was, and a way back.
    fn history(&mut self, ui: &mut Ui, v: &mut View) {
        let l = look(ui);
        let name = v.name().unwrap_or_default().to_string();
        ui.heading("History");
        ui.label(RichText::new(&name).color(l.muted));
        let all = v.s.history(&name).unwrap_or_default();
        let last = all.len().saturating_sub(1);
        let (mut a, mut b, mut show) = self.hist;
        (a, b) = (a.min(last), b.min(last));
        let stamp = |i: usize| {
            let ms = all.get(i).map_or(0, |v| v.0);
            let at = UNIX_EPOCH + Duration::from_millis(ms);
            let at = humantime::format_rfc3339_seconds(at).to_string();
            at.trim_end_matches('Z').replace('T', "  ")
        };
        let rows = ScrollArea::vertical().id_salt("versions").max_height(190.0);
        rows.show(ui, |ui| {
            Grid::new("history").num_columns(3).spacing([14.0, 8.0]).show(
                ui,
                |ui| {
                    for (i, (_, body)) in all.iter().enumerate() {
                        let f = Form::parse(&String::from_utf8_lossy(body));
                        if ui.selectable_label(i == a, stamp(i)).clicked() {
                            a = i;
                        }
                        let what = match (i, body.is_empty()) {
                            (0, false) => "now".into(),
                            (_, true) => "deleted".into(),
                            _ => f.user.clone(),
                        };
                        ui.label(RichText::new(what).color(l.muted));
                        ui.horizontal(|ui| {
                            let with = ui.selectable_label(i == b, "Compare");
                            if with.on_hover_text("Compare with this").clicked()
                            {
                                b = i;
                            }
                            if body.is_empty() {
                                return;
                            }
                            if ui.small_button("Copy password").clicked() {
                                v.note = match crate::clip(&f.pass) {
                                    Ok(()) => "That version's password \
                                               copied, cleared in 45 s"
                                        .into(),
                                    Err(e) => format!("{e:#}"),
                                };
                            }
                            if i > 0 && ui.small_button("Restore").clicked() {
                                v.put(&name, body);
                            }
                        });
                        ui.end_row();
                    }
                },
            );
        });
        // The version looked at, as it was; against another, the older's
        // lines that went (-) and the newer's that came (+).
        if let (Some(x), Some(y)) = (all.get(a), all.get(b)) {
            ui.separator();
            let (old, new) = if a >= b { (a, b) } else { (b, a) };
            ui.horizontal(|ui| {
                ui.strong(match a == b {
                    true => format!("As it was at {}", stamp(a)),
                    false => format!("{}  to  {}", stamp(old), stamp(new)),
                });
                ui.checkbox(&mut show, "Show passwords");
            });
            let (x, y) = if a >= b { (x, y) } else { (y, x) };
            let x = Form::parse(&String::from_utf8_lossy(&x.1));
            let y = Form::parse(&String::from_utf8_lossy(&y.1));
            let lines =
                ScrollArea::vertical().id_salt("diff").max_height(230.0);
            lines.show(ui, |ui| {
                ui.set_width(ui.available_width());
                for ((field, was), (_, is)) in
                    x.fields().into_iter().zip(y.fields())
                {
                    if was.is_empty() && is.is_empty() {
                        continue;
                    }
                    ui.label(RichText::new(field).small().color(l.muted));
                    let line =
                        |ui: &mut Ui, mark: &str, t: &str, c: Color32| {
                            let t = match field == "Password" && !show {
                                true => "\u{2022}".repeat(8),
                                false => t.to_string(),
                            };
                            let t = format!("{mark} {t}");
                            ui.label(RichText::new(t).monospace().color(c));
                        };
                    let gone =
                        was.lines().filter(|w| !is.lines().any(|i| i == *w));
                    gone.for_each(|w| line(ui, "-", w, l.bad));
                    for i in is.lines() {
                        match was.lines().any(|w| w == i) {
                            true => line(ui, " ", i, l.text),
                            false => line(ui, "+", i, l.accent),
                        }
                    }
                }
            });
        }
        self.hist = (a, b, show);
        let note = "Click a date to see that version; Compare sets what it \
                    is compared with. Nothing is ever overwritten.";
        ui.label(RichText::new(note).small().color(l.muted));
    }

    /// A key never used before is set up here, and a spare with it: the
    /// same secret, which is held until the store is made and no longer.
    fn new_key(&mut self, ui: &mut Ui) {
        let l = look(ui);
        let note = "A new key must be set up first. A spare key gets the \
                    same secret right then, or never: have both at hand. \
                    Without a spare, the password is the way in if the key \
                    is lost.";
        ui.label(RichText::new(note).small().color(l.muted));
        ui.horizontal(|ui| {
            let spare = self.key_secret.is_some();
            let text = if spare { "Set up a spare key" } else { "Set up a new key" };
            if ui.button(text).clicked() {
                let secret = self.key_secret.take();
                let secret = secret.unwrap_or_else(|| Zeroizing::new(pasa::rand::<20>().to_vec()));
                self.said = match crate::key_setup(&secret) {
                    Ok(()) if spare => "The spare is set up: unplug it, and plug the first key in.".into(),
                    Ok(()) => "The key is set up. For a spare, plug that in now instead.".into(),
                    Err(e) => format!("{e:#}"),
                };
                self.key_secret = Some(secret);
            }
        });
    }

    /// The entry being made or changed: what it is, and under Advanced
    /// when it expires, its other fields and its files.
    fn form(&mut self, ctx: &Context, v: &mut View) {
        let users = self.users();
        let Some(e) = &mut self.edit else { return };
        let (mut save, mut close) = (false, false);
        let r = Modal::new(Id::unique("edit")).frame(sheet(ctx)).show(ctx, |ui| {
            ui.set_width(460.0);
            let l = look(ui);
            let small = |ui: &mut Ui, t: &str| {
                ui.label(RichText::new(t).small().color(l.muted));
            };
            ui.horizontal(|ui| {
                ui.heading(if e.old.is_empty() { "New entry" } else { "Edit entry" });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.selectable_value(&mut e.advanced, true, "Advanced");
                    ui.selectable_value(&mut e.advanced, false, "Entry");
                });
            });
            // On a low window the form scrolls; Save stays in reach.
            let tall = ui.ctx().content_rect().height() - 170.0;
            ScrollArea::vertical().max_height(tall).show(ui, |ui| {
            if e.advanced {
                small(ui, "Expires (YYYY-MM-DD; empty: never)");
                ui.horizontal(|ui| {
                    let t = TextEdit::singleline(&mut e.f.expires);
                    ui.add(t.desired_width(140.0).margin(Margin::symmetric(8, 6)));
                    for (text, days) in [("in 90 days", 90), ("in a year", 365)] {
                        if ui.button(text).clicked() {
                            e.f.expires = day(days);
                        }
                    }
                    if ui.button("never").clicked() {
                        e.f.expires.clear();
                    }
                });
                small(ui, "Other fields: one a line, as  name_of_it: value");
                let more = TextEdit::multiline(&mut e.f.more).desired_rows(5);
                ui.add(more.desired_width(f32::INFINITY).code_editor());
                small(ui, "Files");
                let files = match e.old.is_empty() {
                    true => vec![],
                    false => v.s.files(&e.old).unwrap_or_default(),
                };
                for file in &files {
                    ui.horizontal(|ui| {
                        ui.label(file);
                        if ui.small_button("Remove").clicked() {
                            let at = format!("{}{}{file}", e.old, pasa::FILES);
                            v.change(|s| {
                                s.put(&at, b"")?;
                                Ok(format!("{file}: removed"))
                            });
                        }
                    });
                }
                small(ui, "Drop a file on the window, with the entry chosen, to keep it with it.");
            } else {
                let title = field(ui, "Title (a / makes a group: mail/work)", &mut e.name, false);
                if e.old.is_empty() && ui.memory(|m| m.focused().is_none()) {
                    title.request_focus();
                }
                field(ui, "Username", &mut e.f.user, false);
                // Those most entries have, to pick.
                let fits = |u: &&String| **u != e.f.user && u.starts_with(&*e.f.user);
                let picks: Vec<&String> = users.iter().filter(fits).take(4).collect();
                if !picks.is_empty() {
                    ui.horizontal_wrapped(|ui| {
                        for u in picks {
                            if ui.small_button(u).clicked() {
                                e.f.user = u.clone();
                            }
                        }
                    });
                }
                small(ui, "Password");
                ui.horizontal(|ui| {
                    if ui.button("Generate").clicked() {
                        e.f.pass = self.generator.make();
                    }
                    ui.toggle_value(&mut e.making, "Options");
                    if ui.button(if e.show { "Hide" } else { "Show" }).clicked() {
                        e.show ^= true;
                    }
                    let t = TextEdit::singleline(&mut e.f.pass).password(!e.show);
                    ui.add(t.desired_width(f32::INFINITY).margin(Margin::symmetric(8, 6)));
                });
                meter(ui, pasa::strength(&e.f.pass));
                if e.making && self.generator.options(ui) {
                    e.f.pass = self.generator.make();
                    e.show = true;
                }
                field(ui, "URL", &mut e.f.url, false);
                field(ui, "Tags (commas between)", &mut e.f.tags, false);
                field(ui, "One-time code: its otpauth:// address", &mut e.f.otp, false);
                small(ui, "Notes");
                let notes = TextEdit::multiline(&mut e.f.notes).desired_rows(3);
                ui.add(notes.desired_width(f32::INFINITY));
            }
            });
            ui.add_space(6.0);
            // Saved only as what it reads back as: said, not mended.
            let wrong = e.f.problem();
            if let Some(w) = &wrong {
                ui.label(RichText::new(w).small().color(l.bad));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let ok = !e.name.trim().is_empty() && !e.name.ends_with('/');
                let ok = ok && wrong.is_none();
                save = ui.add_enabled_ui(ok, |ui| primary(ui, "Save", false)).inner.clicked();
                close = ui.button("Cancel").clicked();
            });
        });
        if save {
            let (name, old) = (e.name.trim().to_string(), e.old.clone());
            if !old.is_empty() && old != name {
                v.change(|s| s.rename(&old, &name).map(|_| String::new()));
            }
            if v.note.is_empty() || old.is_empty() || old == name {
                v.put(&name, e.f.text().as_bytes());
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
                    Win::History => self.history(ui, v),
                    Win::Health => self.health(ui, v),
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
            (self.health, self.stats) = (None, None);
        }
    }

    fn generate(&mut self, ui: &mut Ui, v: &mut View) {
        let g = &mut self.generator;
        let l = look(ui);
        ui.heading("Password generator");
        let f = Frame::new().fill(l.bg).corner_radius(8).inner_margin(12);
        f.show(ui, |ui| {
            ui.set_width(ui.available_width());
            let t = TextEdit::singleline(&mut *g.pw).frame(Frame::NONE);
            ui.add(
                t.font(FontId::monospace(16.0)).desired_width(f32::INFINITY),
            );
        });
        // Of the password as it stands, at every change of it.
        meter(ui, pasa::strength(&g.pw));
        let mut again = g.options(ui);
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
            g.pw = Zeroizing::new(g.make());
        }
        let note = "The bar estimates the password as it stands, at every \
                    change. New entries start with one made this way.";
        ui.label(RichText::new(note).small().color(l.muted));
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
                    let lost = "Lost or stolen: forget it and make a new \
                                store key; then pair the other devices again";
                    if ui.small_button("Revoke").on_hover_text(lost).clicked() {
                        v.note = match sync::revoke(&mut v.s, &p.name) {
                            Ok(()) => format!(
                                "{}: revoked. A new store key: pair the other \
                                 devices again, and forget {} on each",
                                p.name, p.name
                            ),
                            Err(e) => format!("{e:#}"),
                        };
                        crate::record();
                        crate::aside(true);
                    }
                });
            });
        }
        if !peers.is_empty() && ui.button("Sync now").clicked() {
            v.note = "Syncing".into();
            self.sync_now(ui.ctx(), true);
        }
        ui.separator();
        ui.label(RichText::new("Add a device").strong());
        field(ui, "A name for it", &mut self.device, false);
        let (name, ok) =
            (self.device.trim().to_string(), !self.device.trim().is_empty());
        if let Some(qr) = self.shows(ui, ok) {
            let pw = qr.then(|| Zeroizing::new(pasa::speakable(2, "-", false)));
            let (code, img, end, state) = Default::default();
            self.pairing = Some(Pairing { name, pw, code, img, end, state });
            if !qr && let Err(e) = self.show_code(ui.ctx()) {
                (self.pairing, v.note) = (None, format!("{e:#}"));
            }
        }
        if let Err(e) = self.pairing(ui) {
            (self.pairing, v.note) = (None, format!("{e:#}"));
        }
    }

    /// `pasa sync` beside the window: those that serve are dialed (with
    /// `news`, those that listen woken to dial here); what it said, shown
    /// once back.
    fn sync_now(&self, ctx: &Context, news: bool) {
        if !sync::net(&home()).join("peers").exists() {
            return;
        }
        let (out, ctx) = (self.synced.clone(), ctx.clone());
        std::thread::spawn(move || {
            let run = std::env::current_exe().and_then(|p| {
                std::process::Command::new(p)
                    .arg("sync")
                    .args(news.then_some("--news"))
                    .stdin(std::process::Stdio::null())
                    .output()
            });
            let said = match run {
                Ok(o) => String::from_utf8_lossy(&o.stderr)
                    .trim()
                    .replace('\n', "   "),
                Err(e) => e.to_string(),
            };
            *out.lock().unwrap_or_else(|p| p.into_inner()) = Some(said);
            ctx.request_repaint();
        });
    }

    /// Serve while the window is open, once paired: devices dial here. The
    /// network side is a process of its own that sees `v/` and `net/`
    /// alone; what it brings shows at once, and is said.
    fn serve(&mut self, ctx: &Context) {
        if self.serving || !sync::net(&home()).join("peers").exists() {
            return;
        }
        self.serving = true;
        let (out, ctx) = (self.synced.clone(), ctx.clone());
        std::thread::spawn(move || {
            // Another process may serve this store: then it does.
            let Ok(mut c) = crate::net(&["serve"]) else { return };
            for (who, r) in crate::results(&mut c) {
                if let Ok(n @ 1..) = r {
                    *out.lock().unwrap_or_else(|p| p.into_inner()) =
                        Some(format!("{who}: {n} new"));
                }
                crate::report(&who, r);
                ctx.request_repaint();
            }
            let _ = c.wait();
        });
    }

    /// The two ways to show a pairing; which was chosen: true, the QR code.
    fn shows(&self, ui: &mut Ui, ok: bool) -> Option<bool> {
        ui.horizontal(|ui| {
            let qr = ui.add_enabled(ok, Button::new("Show a QR code"));
            let code = ui.add_enabled(ok, Button::new("Show a code to type"));
            let qr = qr.on_hover_text("Offline: nothing goes online");
            let code = code.on_hover_text("For a device without a camera");
            (qr.clicked() || code.clicked()).then(|| qr.clicked())
        })
        .inner
    }

    /// The short code, from the network side, which takes what the
    /// pairing hands over (all of it sealed) and waits for its taker.
    fn show_code(&mut self, ctx: &Context) -> Result<()> {
        let p = self.pairing.as_mut().context("no pairing")?;
        let got = sync::offer(&home(), &p.name)?;
        let mut c = crate::net(&["give"])?;
        let mut i = c.stdin.take().context("stdin")?;
        std::io::Write::write_all(&mut i, crate::B64.encode(&got).as_bytes())?;
        std::io::Write::write_all(&mut i, b"\n")?;
        let mut l = crate::lines(&mut c);
        p.code = l.next().context("no code: is the relay reachable?")?;
        let (end, repaint) = (Arc::new(Mutex::new(None)), ctx.clone());
        p.end = Some(end.clone());
        std::thread::spawn(move || {
            let said = l.next().unwrap_or_default();
            drop((i, c));
            *end.lock().unwrap_or_else(|p| p.into_inner()) = Some(said);
            repaint.request_repaint();
        });
        p.state = "Waiting for it".into();
        self.serve(ctx);
        Ok(())
    }

    /// The pairing: a QR code's password, then the code alone; or the
    /// short code; and how it is going.
    fn pairing(&mut self, ui: &mut Ui) -> Result<()> {
        let l = look(ui);
        let ctx = ui.ctx().clone();
        let Some(p) = &mut self.pairing else { return Ok(()) };
        let mut show = false;
        let f = Frame::new().fill(l.bg).corner_radius(8).inner_margin(12);
        f.show(ui, |ui| {
            ui.set_width(ui.available_width());
            let muted = |ui: &mut Ui, t: &str| {
                ui.label(RichText::new(t).small().color(l.muted));
            };
            if let Some(pw) = &mut p.pw {
                field(ui, "QR code password: type one, or keep this", pw, false);
                let how = format!(
                    "Remember it. The QR code comes next, without it: \
                     on {}, type it after scanning.",
                    p.name
                );
                muted(ui, &how);
                show = !pw.is_empty() && ui.button("Show the QR code").clicked();
                return;
            }
            let what = if p.img.is_some() { "scan this" } else { "type this" };
            muted(ui, &format!("On {}: {what} where it asks for a code", p.name));
            match &p.img {
                Some(img) => drop(ui.image((img.id(), vec2(240.0, 240.0)))),
                None => drop(ui.label(RichText::new(&p.code).monospace().size(17.0))),
            }
            if let Some(end) = p.end.as_ref().and_then(|e| e.lock().unwrap_or_else(|p| p.into_inner()).take()) {
                p.state = match end.as_str() {
                    "taken" => format!("{} took it: it syncs now", p.name),
                    "spent" => format!(
                        "Someone used the code without proving it: forget {}, pair again",
                        p.name
                    ),
                    _ => "Nobody came: show a new code".into(),
                };
            }
            ui.label(RichText::new(&p.state).small().color(l.accent));
        });
        ui.ctx().request_repaint_after(Duration::from_secs(1));
        if show {
            let pw = p.pw.take().unwrap_or_default();
            let got = sync::offer(&home(), &p.name)?;
            let qr = self.rt()?.block_on(sync::qr(&got, &pw))?;
            let p = self.pairing.as_mut().context("no pairing")?;
            (p.img, p.code) = (Some(qr_image(&ctx, &qr)?), qr);
            p.state = "Waiting for it to sync".into();
            self.serve(&ctx);
        }
        Ok(())
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
        ui.label(
            RichText::new("Security keys: CTAP2 (FIDO2 without the network)")
                .strong(),
        );
        let how = "A security key of any make (a YubiKey is one) opens the \
                   store on this machine, beside the password, plugged in. \
                   Only this machine and the key take part, over USB: no \
                   server, no account, no network, nothing to install. The \
                   key's secret never leaves it. Keys added on a phone come \
                   along when it pairs this machine. Add a spare at any time.";
        ui.label(RichText::new(how).small().color(l.muted));
        let keys = pasa::fido(&home()).map_or(0, |f| f.keys.len());
        ui.horizontal(|ui| {
            ui.label(match keys {
                0 => "None".into(),
                1 => "1 key".to_string(),
                n => format!("{n} keys"),
            });
            let pin = TextEdit::singleline(&mut *self.pin).password(true);
            ui.add(
                pin.hint_text("Its PIN, if it has one").desired_width(150.0),
            );
            if ui.button("Add the key plugged in").clicked() {
                self.begin(ui, Job::AddFido, "Touch your security key, twice");
            }
            if keys > 0 && ui.button("Remove all").clicked() {
                self.said = match pasa::fido_off(&home(), None) {
                    Ok(()) => "No security key opens the store now".into(),
                    Err(e) => format!("{e:#}"),
                };
            }
        });
        ui.separator();
        ui.label(RichText::new("Quick unlock").strong());
        let how = "A tap of your YubiKey and a PIN open the store on this \
                   machine, by its slot 2 (ykman). The password still opens \
                   it alone: keep it long.";
        #[cfg(target_os = "macos")]
        let how = format!(
            "{how} On a Mac ykman reads slot 2 through the key's keyboard \
             side, which macOS guards (Input Monitoring): add the YubiKey \
             as a security key above instead, which asks for nothing."
        );
        ui.label(RichText::new(how).small().color(l.muted));
        match pasa::quick(&home()) {
            Some((_, pin)) => {
                ui.horizontal(|ui| {
                    ui.label(if pin { "On, with a PIN" } else { "On, no PIN" });
                    if ui.button("Turn off").clicked() {
                        self.begin(ui, Job::SetQuick(false), "");
                    }
                });
            }
            None => {
                ui.horizontal(|ui| {
                    let pin =
                        TextEdit::singleline(&mut *self.pin).password(true);
                    ui.add(
                        pin.hint_text("PIN (empty: none)").desired_width(160.0),
                    );
                    if ui.button("Turn on").clicked() {
                        self.begin(
                            ui,
                            Job::SetQuick(true),
                            "Touch your YubiKey",
                        );
                    }
                });
            }
        }
        self.said(ui);
        ui.separator();
        let about = format!(
            "pasa {}  ·  GPL-3.0-or-later\nStore: {}\nCopied secrets leave the clipboard after 45 s.",
            env!("CARGO_PKG_VERSION"),
            home().display()
        );
        ui.label(RichText::new(about).small().color(l.muted));
    }
}
