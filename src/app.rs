//! egui application layer — UI-only state and rendering.
//!
//! **Rule:** no protocol/tunnel logic in this module. The UI reads state
//! from [`crate::core`] and dispatches intents into it.
//!
//! Settings persistence uses eframe's built-in storage: loaded in
//! [`App::new`], written in [`eframe::App::save`] (on exit).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use eframe::egui;
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::core::engine::{Engine, EngineHandle, Event};
use crate::core::redirect::{compare_tld_first, registrable_domain};
use crate::core::settings::Settings;

/// Storage key under which [`Settings`] are persisted.
const SETTINGS_KEY: &str = "settings";

/// Storage key under which the engine-running state is persisted.
const ENGINE_RUNNING_KEY: &str = "engine_running";

/// Number of log lines kept in the tunnel tab.
const LOG_CAPACITY: usize = 200;

/// How long to wait before retrying a failed engine start (e.g. the VPN
/// not being up yet at boot).
const START_RETRY_INTERVAL: Duration = Duration::from_secs(15);

/// Which top-level tab is visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    /// Engine controls and event log.
    Tunnel,
    /// Domains seen by the resolver, with one-click redirect.
    Log,
    /// Persistent settings editor.
    Settings,
}

/// Owns the system tray icon and the shared state used to show/hide the
/// window. Kept alive for the lifetime of [`App`]; dropping it removes the
/// tray icon.
///
/// **Rule:** the tray thread only writes these atomics. It must never call
/// into [`egui::Context`] — doing so races with `Context` teardown when the
/// app is quitting and deadlocks `TrayIcon::drop` against the tray worker
/// thread (frozen process, unresponsive tray icon).
struct TrayState {
    /// The tray icon itself. Must stay alive.
    _icon: TrayIcon,
    /// Menu items are held so the menu keeps working (dropping a
    /// `MenuItem` detaches it from its menu).
    _show_hide: MenuItem,
    _quit: MenuItem,
    /// `true` while the window is hidden to the tray. Touched only from
    /// the UI thread.
    hidden: Arc<AtomicBool>,
    /// Set by the tray thread to request a show/hide toggle; consumed by
    /// [`App::ui`], which performs the toggle on the UI thread.
    toggle_requested: Arc<AtomicBool>,
    /// `true` when the user asked to quit from the tray. Set by the tray
    /// thread; read by [`App::ui`], which issues the `Close` command.
    quitting: Arc<AtomicBool>,
}

impl TrayState {
    /// Builds the tray icon and installs the global event handlers.
    ///
    /// The handlers run on the tray-icon worker thread and only store into
    /// the shared atomics — the UI thread polls and acts on them in
    /// [`App::ui`]. Touching [`egui::Context`] from here would deadlock
    /// `TrayIcon::drop` when the app is quitting.
    fn new(ctx: &egui::Context) -> Self {
        let hidden = Arc::new(AtomicBool::new(false));
        let toggle_requested = Arc::new(AtomicBool::new(false));
        let quitting = Arc::new(AtomicBool::new(false));

        let show_hide = MenuItem::new("Show / Hide", true, None);
        let quit = MenuItem::new("Quit", true, None);
        let menu = Menu::new();
        menu.append(&show_hide).expect("append show/hide");
        menu.append(&quit).expect("append quit");

        let show_hide_id = show_hide.id().clone();
        let quit_id = quit.id().clone();

        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_icon(default_tray_icon())
            .build()
            .expect("failed to create tray icon");

        // Left-click on the tray icon requests a show/hide toggle.
        {
            let toggle_requested = toggle_requested.clone();
            let ctx = ctx.clone();
            TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    toggle_requested.store(true, Ordering::SeqCst);
                    // Safe from any thread: just sets a wake flag. Needed
                    // because a hidden window on Windows may not run its
                    // repaint tick, so the UI thread would not otherwise
                    // notice the flag.
                    ctx.request_repaint();
                }
            }));
        }

        // Menu item clicks.
        {
            let toggle_requested = toggle_requested.clone();
            let quitting = quitting.clone();
            let ctx = ctx.clone();
            MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
                if event.id == show_hide_id {
                    toggle_requested.store(true, Ordering::SeqCst);
                } else if event.id == quit_id {
                    quitting.store(true, Ordering::SeqCst);
                } else {
                    return;
                }
                // See note on the tray-click handler: wake the UI thread.
                ctx.request_repaint();
            }));
        }

        Self {
            _icon: tray,
            _show_hide: show_hide,
            _quit: quit,
            hidden,
            toggle_requested,
            quitting,
        }
    }
}

// `toggle_window` is now a method on `App`, called from `App::ui` on the
// UI thread. It must not be invoked from the tray thread — see the note
// on `TrayState`.

/// Returns the current UTC time as `(hour, minute, second)`.
///
/// Uses `SystemTime` (no unsafe, no extra crate). The value is UTC — the
/// project forbids unsafe code, so `GetLocalTime` isn't an option and
/// adding a local-time crate for a timestamp prefix isn't worth the
/// dependency. If local time is wanted later, swap in `chrono::Local`
/// and delete this.
fn utc_hms() -> (u64, u64, u64) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs / 3600 % 24, secs / 60 % 60, secs % 60)
}

/// A plain solid-colour 32×32 tray icon, so we don't need an asset file.
fn default_tray_icon() -> tray_icon::Icon {
    let (w, h) = (32u32, 32u32);
    let mut rgba = vec![0u8; (w * h * 4) as usize];
    for chunk in rgba.chunks_exact_mut(4) {
        chunk[0] = 0x30; // R
        chunk[1] = 0x80; // G
        chunk[2] = 0xD0; // B
        chunk[3] = 0xFF; // A
    }
    tray_icon::Icon::from_rgba(rgba, w, h).expect("tray icon")
}

/// Main egui application.
///
/// Holds UI-only state and the committed [`Settings`].
/// All tunnel logic lives in [`crate::core`].
pub struct App {
    /// Committed settings — persisted and what the engine runs with.
    settings: Settings,
    /// Edits in the settings tab; not committed until saved.
    draft: Settings,
    /// Currently visible tab.
    tab: Tab,
    /// Running engine; dropping it performs a graceful shutdown.
    engine: Option<EngineHandle>,
    /// A start attempt running on a worker thread. `None` when idle; the
    /// receiver yields the engine handle (or an error message) when the
    /// worker is done. Keeping this off the UI thread matters because
    /// `Engine::start` shells out to PowerShell for peer discovery.
    starting: Option<mpsc::Receiver<Result<EngineHandle, String>>>,
    /// A stop request running on a worker thread. `None` when idle; the
    /// receiver yields once the old engine has fully shut down (threads
    /// joined, routes deleted). `EngineHandle::drop` joins engine threads
    /// and shells out to `route.exe delete` once per routed IP, so it must
    /// not run on the UI thread.
    stopping: Option<mpsc::Receiver<()>>,
    /// Event stream from the engine.
    events: Option<mpsc::Receiver<Event>>,
    /// Recent DNS queries only, oldest first (left panel).
    query_log: VecDeque<String>,
    /// Recent non-query engine events — start/stop, routes, warnings,
    /// errors, info (right panel).
    system_log: VecDeque<String>,
    /// Unique domains that went through the resolver (this session) and
    /// the processes that asked for them, when attribution is available.
    seen: BTreeMap<String, BTreeSet<String>>,
    /// Log-tab view: group everything by top-level domain instead of
    /// listing every domain.
    show_tlds_only: bool,
    /// Log-tab search box — case-insensitive substring filter on domains.
    /// In-memory only; reset on each launch.
    domain_filter: String,
    /// When the next automatic engine-start retry is due (`None` when no
    /// retry is pending).
    start_retry_at: Option<Instant>,
    /// The last start failure logged — repeated identical failures are not
    /// re-logged, to keep the retry loop quiet.
    last_start_error: Option<String>,
    /// System tray icon + shared hide/quit state.
    tray: TrayState,
    /// Set when the tray Quit handler shuts down a running engine before
    /// closing. Written to storage in [`eframe::App::save`] so the next
    /// launch knows to auto-start, even though `self.engine` is `None` by
    /// the time `save` runs.
    engine_running_at_exit: bool,
    /// Wall-clock moment the engine last reported `Started`. `None`
    /// whenever the engine is stopped; used for the status bar's uptime.
    engine_started_at: Option<Instant>,
    /// Total queries forwarded this session (survives engine restarts;
    /// resets only when the app itself is relaunched).
    queries_total: u64,
    /// Currently pinned route count, tracked from `RouteAdded` /
    /// `RouteRemoved` events.
    routes_total: u64,
    /// Current route next hop (from the last `Started` event), shown in
    /// the status bar.
    next_hop: Option<Ipv4Addr>,
    /// Set when the user clicks Restart: the stop worker completes, then
    /// `poll_stop` calls `start_engine` again.
    restart_after_stop: bool,
}

impl App {
    /// Creates the app, restoring persisted settings from `cc.storage`.
    #[must_use]
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let settings: Settings = cc
            .storage
            .and_then(|storage| eframe::get_value(storage, SETTINGS_KEY))
            .unwrap_or_default();
        let engine_was_running: bool = cc
            .storage
            .and_then(|storage| eframe::get_value(storage, ENGINE_RUNNING_KEY))
            .unwrap_or(false);
        let tray = TrayState::new(&cc.egui_ctx);
        let mut app = Self {
            draft: settings.clone(),
            settings,
            tab: Tab::Tunnel,
            engine: None,
            starting: None,
            stopping: None,
            events: None,
            query_log: VecDeque::new(),
            system_log: VecDeque::new(),
            seen: BTreeMap::new(),
            show_tlds_only: false,
            domain_filter: String::new(),
            start_retry_at: None,
            last_start_error: None,
            tray,
            engine_running_at_exit: false,
            engine_started_at: None,
            queries_total: 0,
            routes_total: 0,
            next_hop: None,
            restart_after_stop: false,
        };
        if engine_was_running {
            // The engine was running when the app last closed (without an
            // explicit Stop) — restore that state. `start_engine` already
            // logs failures and the engine itself emits `Started` on
            // success, so only log the *intent* here.
            app.push_log("engine was running at last exit — auto-starting".to_owned());
            app.start_engine();
        }
        app
    }

    fn log_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Domains");
        ui.separator();
        ui.label(
            "Every unique domain resolved through the engine this session. \
             Add the ones you want routed through the VPN.",
        );
        ui.horizontal(|ui| {
            ui.label("Search:");
            ui.add(
                egui::TextEdit::singleline(&mut self.domain_filter)
                    .hint_text("partial domain match")
                    .desired_width(240.0),
            );
            if ui.small_button("Clear").clicked() {
                self.domain_filter.clear();
            }
        });
        ui.checkbox(
            &mut self.show_tlds_only,
            "Group by registrable domain (company.tld)",
        );
        ui.separator();

        let needle = self.domain_filter.trim().to_lowercase();
        let mut add: Option<String> = None;
        if self.show_tlds_only {
            // Aggregate every domain into its registrable part; processes
            // are merged. The filter is applied to the *underlying* domain
            // so `www.example.com` still shows under `example.com` when the
            // user types `www`.
            let mut tlds: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            for (domain, processes) in &self.seen {
                if !needle.is_empty() && !domain.to_lowercase().contains(&needle) {
                    continue;
                }
                let tld = registrable_domain(domain);
                tlds.entry(tld.to_owned())
                    .or_default()
                    .extend(processes.iter().cloned());
            }
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (tld, processes) in &tlds {
                        let listed = self
                            .settings
                            .redirect_list
                            .iter()
                            .any(|existing| existing == tld);
                        if Self::list_row(ui, tld, Some(processes), listed) {
                            add = Some(tld.clone());
                        }
                    }
                });
        } else {
            let mut domains: Vec<&String> = self
                .seen
                .keys()
                .filter(|domain| {
                    needle.is_empty() || domain.to_lowercase().contains(&needle)
                })
                .collect();
            domains.sort_by(|a, b| compare_tld_first(a, b));
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for domain in domains {
                        let listed = self
                            .settings
                            .redirect_list
                            .iter()
                            .any(|existing| existing == domain);
                        if Self::list_row(ui, domain, self.seen.get(domain), listed) {
                            add = Some(domain.clone());
                        }
                    }
                });
        }
        if let Some(label) = add {
            self.add_to_redirect(&label);
        }
    }

    /// Renders one row of the domain/TLD list; returns `true` when the
    /// add-to-redirect button was clicked.
    fn list_row(
        ui: &mut egui::Ui,
        label: &str,
        processes: Option<&BTreeSet<String>>,
        listed: bool,
    ) -> bool {
        let mut clicked = false;
        ui.horizontal(|ui| {
            ui.monospace(label);
            if let Some(processes) = processes {
                let mut names: Vec<&String> = processes.iter().collect();
                names.sort_unstable();
                let names = names.into_iter().cloned().collect::<Vec<_>>().join(", ");
                ui.weak(format!("({names})"));
            }
            if listed {
                ui.weak("(in redirect list)");
            } else if ui.small_button("add to redirect").clicked() {
                clicked = true;
            }
        });
        clicked
    }

    /// Adds `domain` to the committed redirect list and pushes it to a
    /// running engine (hot — no restart needed).
    fn add_to_redirect(&mut self, domain: &str) {
        if self
            .settings
            .redirect_list
            .iter()
            .any(|existing| existing == domain)
        {
            return;
        }
        self.settings.redirect_list.push(domain.to_owned());
        self.settings = self.settings.normalized();
        // Mirror into the draft too: if the user has unsaved edits in the
        // Settings tab, a later Save overwrites `settings` from `draft` —
        // without this the just-added domain silently vanishes.
        self.draft.redirect_list.push(domain.to_owned());
        if let Some(engine) = &self.engine {
            engine.set_redirect_list(self.settings.redirect_list.clone());
        }
        self.push_log(format!("added `{domain}` to the redirect list"));
    }

    /// Shows the window if hidden, hides it otherwise. Called from the UI
    /// thread (either directly from the Tunnel tab, or from `App::ui` in
    /// response to a tray toggle request).
    fn toggle_window(&mut self, ctx: &egui::Context) {
        if self.tray.hidden.load(Ordering::SeqCst) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            self.tray.hidden.store(false, Ordering::SeqCst);
        } else {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            self.tray.hidden.store(true, Ordering::SeqCst);
        }
    }

    fn tunnel_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("DNS Tunnel");
        ui.separator();

        let running = self.engine.is_some();
        let starting = self.starting.is_some();
        let stopping = self.stopping.is_some();
        let settings_ok = self.settings.errors().is_empty();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !running && !starting && !stopping && settings_ok,
                    egui::Button::new("Start"),
                )
                .clicked()
            {
                self.start_engine();
            }
            if ui.add_enabled(running, egui::Button::new("Stop")).clicked() {
                // Drop runs on a worker thread — see `stop_engine`.
                self.stop_engine();
            }
            if ui
                .add_enabled(running && !stopping, egui::Button::new("Restart"))
                .clicked()
            {
                self.restart_engine();
            }

            if ui.button("Hide to tray").clicked() {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Visible(false));
                self.tray.hidden.store(true, Ordering::SeqCst);
            }
        });
        if !running && !starting && !stopping && !settings_ok {
            ui.label("Engine will not start — fix the settings first (Settings tab).");
        }

        // Status bar — one line, always visible, does not scroll away.
        ui.horizontal(|ui| {
            if running {
                ui.colored_label(egui::Color32::from_rgb(0x30, 0xC0, 0x30), "● running");
                if let Some(started) = self.engine_started_at {
                    let secs = started.elapsed().as_secs();
                    ui.label(format!(
                        "up {:02}:{:02}:{:02}",
                        secs / 3600,
                        (secs / 60) % 60,
                        secs % 60
                    ));
                }
            } else if starting {
                ui.colored_label(egui::Color32::from_rgb(0xC0, 0xC0, 0x30), "● starting…");
            } else if stopping {
                ui.colored_label(egui::Color32::from_rgb(0xC0, 0xC0, 0x30), "● stopping…");
            } else {
                ui.colored_label(egui::Color32::from_rgb(0xC0, 0x30, 0x30), "● stopped");
            }
            ui.separator();
            ui.label(format!("queries {}", self.queries_total));
            ui.separator();
            ui.label(format!("routes {}", self.routes_total));
            if let Some(peer) = self.next_hop {
                ui.separator();
                ui.label(format!("via {peer}"));
            }
        });

        ui.separator();
        ui.columns(2, |columns| {
            columns[0].push_id("query_header", |ui| {
                ui.horizontal(|ui| {
                    ui.label("DNS queries");
                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            if ui.small_button("Clear").clicked() {
                                self.query_log.clear();
                            }
                        },
                    );
                });
            });
            columns[0].separator();
            // Distinct id scope per column: without this, both ScrollAreas
            // derive the same widget id from identical structure and end
            // up sharing scroll state (the scrollbar of one moves the
            // other).
            columns[0].push_id("tunnel_query_log", |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for line in &self.query_log {
                            ui.monospace(line);
                        }
                    });
            });

            columns[1].push_id("system_header", |ui| {
                ui.horizontal(|ui| {
                    ui.label("System");
                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            if ui.small_button("Clear").clicked() {
                                self.system_log.clear();
                            }
                        },
                    );
                });
            });
            columns[1].separator();
            columns[1].push_id("tunnel_system_log", |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for line in &self.system_log {
                            ui.monospace(line);
                        }
                    });
            });
        });
    }

    /// Starts the engine with the committed settings.
    ///
    /// The actual start happens on a worker thread — `Engine::start` shells
    /// out to PowerShell for peer discovery, binds sockets, and touches the
    /// registry file; running it on the UI thread would freeze the window.
    /// The result arrives via [`Self::poll_start`].
    fn start_engine(&mut self) {
        if self.engine.is_some() || self.starting.is_some() {
            return;
        }
        // Subscribe to engine events *before* spawning: `Engine::start`
        // emits warnings/info before it returns, and the UI polls this
        // receiver every frame regardless of state.
        let (event_tx, event_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        self.events = Some(event_rx);
        self.starting = Some(result_rx);

        let settings = self.settings.clone();
        let spawn = std::thread::Builder::new()
            .name("engine-start".to_owned())
            .spawn(move || {
                // On failure `Engine::start` drops `event_tx`, so the UI's
                // event receiver disconnects cleanly.
                let result = Engine::start(&settings, event_tx).map_err(|e| e.to_string());
                // If the UI dropped `result_rx` (app closing), the handle
                // is dropped here on the worker thread — shutdown still runs.
                let _ = result_tx.send(result);
            });

        if let Err(e) = spawn {
            // Extremely unlikely; treat as a start failure so the retry
            // loop kicks in instead of a silent no-op.
            self.starting = None;
            self.events = None;
            let message = format!("error: failed to spawn start thread: {e}");
            if self.last_start_error.as_deref() != Some(message.as_str()) {
                self.push_log(message.clone());
                self.last_start_error = Some(message);
            }
            self.start_retry_at = Some(Instant::now() + START_RETRY_INTERVAL);
        }
    }

    /// Collects the outcome of a pending [`Self::start_engine`] attempt.
    fn poll_start(&mut self) {
        let Some(rx) = &self.starting else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok(handle)) => {
                self.engine = Some(handle);
                self.starting = None;
                self.start_retry_at = None;
                self.last_start_error = None;
            }
            Ok(Err(message)) => {
                let message = format!("error: failed to start engine: {message}");
                if self.last_start_error.as_deref() != Some(message.as_str()) {
                    self.push_log(message.clone());
                    self.last_start_error = Some(message);
                }
                self.start_retry_at = Some(Instant::now() + START_RETRY_INTERVAL);
                self.starting = None;
                self.events = None;
            }
            Err(mpsc::TryRecvError::Empty) => {} // still starting
            Err(mpsc::TryRecvError::Disconnected) => {
                // The worker panicked before sending a result.
                let message = "error: engine start thread panicked".to_owned();
                if self.last_start_error.as_deref() != Some(message.as_str()) {
                    self.push_log(message.clone());
                    self.last_start_error = Some(message);
                }
                self.start_retry_at = Some(Instant::now() + START_RETRY_INTERVAL);
                self.starting = None;
                self.events = None;
            }
        }
    }

    /// Stops the engine on a worker thread.
    ///
    /// `EngineHandle::drop` joins the engine threads and then shells out to
    /// `route.exe delete` once per routed IP — running that on the UI
    /// thread freezes the window for as long as the OS takes to remove the
    /// routes. Instead, the handle is moved to a worker and the UI polls
    /// for completion via [`Self::poll_stop`].
    fn stop_engine(&mut self) {
        if self.stopping.is_some() {
            return;
        }
        let Some(engine) = self.engine.take() else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.stopping = Some(rx);
        let spawn = std::thread::Builder::new()
            .name("engine-stop".to_owned())
            .spawn(move || {
                drop(engine);
                let _ = tx.send(());
            });
        if let Err(e) = spawn {
            // Extremely unlikely (OOM / OS thread limit). The closure — and
            // the `EngineHandle` it owns — was dropped by the failed spawn,
            // so the blocking cleanup already ran inline; just surface the
            // failure and clear the state machine.
            self.stopping = None;
            self.push_log(format!("error: failed to spawn stop thread: {e}"));
        }
    }

    /// Collects the completion of a pending [`Self::stop_engine`].
    fn poll_stop(&mut self) {
        let Some(rx) = &self.stopping else {
            return;
        };
        match rx.try_recv() {
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => {
                // `Ok` = clean shutdown; `Disconnected` = the worker
                // panicked after moving the handle. Either way the engine
                // is gone — `Stopped` and any last `RouteRemoved` events
                // still drain through `poll_events` because the channel
                // stays open until the handle's sender is dropped.
                self.stopping = None;
                if self.restart_after_stop {
                    self.restart_after_stop = false;
                    self.start_engine();
                }
            }
            Err(mpsc::TryRecvError::Empty) => {} // still stopping
        }
    }

    /// Restarts the engine in one click: stop, then start when the stop
    /// worker finishes (see [`Self::poll_stop`]).
    fn restart_engine(&mut self) {
        if self.engine.is_some() && self.stopping.is_none() {
            self.restart_after_stop = true;
            self.stop_engine();
        }
    }

    /// Retries a failed engine start once [`START_RETRY_INTERVAL`] has
    /// passed (e.g. the VPN came up after boot).
    fn poll_retry(&mut self) {
        let Some(at) = self.start_retry_at else {
            return;
        };
        if at <= Instant::now() {
            self.start_retry_at = None;
            if self.engine.is_none()
                && self.starting.is_none()
                && self.stopping.is_none()
                && self.settings.errors().is_empty()
            {
                self.start_engine();
            }
        }
    }

    /// Drains engine events into the log.
    fn poll_events(&mut self) {
        let Some(events) = &self.events else {
            return;
        };
        let batch: Vec<Event> = events.try_iter().collect();
        for event in batch {
            if let Event::QueryForwarded {
                domain,
                process,
                in_redirect_list: _,
            } = &event
            {
                let processes = self.seen.entry(domain.clone()).or_default();
                if let Some(process) = process {
                    processes.insert(process.clone());
                }
            }
            match event {
                Event::QueryForwarded {
                    domain,
                    process,
                    in_redirect_list,
                } => {
                    self.queries_total += 1;
                    let route_ident = if in_redirect_list { "🛡️" } else { "➡️" };
                    let line = match process {
                        Some(process) => format!("{route_ident} query -> {domain} ({process})"),
                        None => format!("{route_ident} query -> {domain}"),
                    };
                    self.push_query(line);
                }
                Event::Started { listen, gateway } => {
                    self.engine_started_at = Some(Instant::now());
                    self.next_hop = Some(gateway);
                    self.push_log(format!(
                        "started: listening on {listen}, routing via {gateway}"
                    ));
                }
                Event::Stopped => {
                    self.engine_started_at = None;
                    self.next_hop = None;
                    self.routes_total = 0;
                    self.push_log("stopped: routes cleaned up".to_owned());
                }
                Event::RouteAdded { ip } => {
                    self.routes_total = self.routes_total.saturating_add(1);
                    self.push_log(format!("route + {ip}"));
                }
                Event::RouteRemoved { ip } => {
                    self.routes_total = self.routes_total.saturating_sub(1);
                    self.push_log(format!("route - {ip}"));
                }
                Event::Error(message) => self.push_log(format!("error: {message}")),
                Event::Warning(message) => self.push_log(format!("warning: {message}")),
                Event::Info(message) => self.push_log(message),
            }
        }
    }

    /// Appends a line to the bounded system log (start/stop, routes,
    /// warnings, errors, info). Prefixes each line with a wall-clock time.
    fn push_log(&mut self, line: String) {
        let (h, m, s) = utc_hms();
        Self::push_bounded(
            &mut self.system_log,
            format!("[{h:02}:{m:02}:{s:02}] {line}"),
        );
    }

    /// Appends a line to the bounded DNS-query log.
    fn push_query(&mut self, line: String) {
        Self::push_bounded(&mut self.query_log, line);
    }

    /// Appends to a bounded log, dropping the oldest line when full.
    fn push_bounded(log: &mut VecDeque<String>, line: String) {
        if log.len() >= LOG_CAPACITY {
            log.pop_front();
        }
        log.push_back(line);
    }

    fn settings_tab(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.heading("Settings");
                ui.separator();

                egui::Grid::new("settings_grid")
                    .num_columns(2)
                    .spacing([12.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Listen address");
                        ui.text_edit_singleline(&mut self.draft.listen_addr);
                        ui.end_row();

                        ui.label("DNS server");
                        ui.text_edit_singleline(&mut self.draft.dns_server);
                        ui.end_row();

                        ui.label("VPN gateway (IPv4)");
                        ui.text_edit_singleline(&mut self.draft.vpn_gateway);
                        ui.end_row();

                        ui.label("VPN interface");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.draft.vpn_interface)
                                .hint_text("empty = auto-detect; or ifIndex/alias"),
                        );
                        ui.end_row();

                        ui.label("Timeout (ms)");
                        ui.add(
                            egui::DragValue::new(&mut self.draft.timeout_ms)
                                .range(1..=u64::MAX),
                        );
                        ui.end_row();
                    });

                ui.add_space(8.0);
                egui::CollapsingHeader::new(
                    "Redirect list (routed through the VPN, subdomains included)",
                )
                .default_open(true)
                .show(ui, |ui| {
                    let mut remove = None;
                    for (index, domain) in self.draft.redirect_list.iter_mut().enumerate() {
                        ui.horizontal(|ui| {
                            ui.text_edit_singleline(domain);
                            if ui.small_button("Remove").clicked() {
                                remove = Some(index);
                            }
                        });
                    }
                    if let Some(index) = remove {
                        self.draft.redirect_list.remove(index);
                    }
                    if ui.button("Add domain").clicked() {
                        self.draft.redirect_list.push(String::new());
                    }
                });

                ui.add_space(8.0);
                egui::CollapsingHeader::new(
                    "Static routes (CIDR — always routed while the engine runs)",
                )
                .default_open(true)
                .show(ui, |ui| {
                    let mut remove_cidr = None;
                    for (index, cidr) in self.draft.cidr_list.iter_mut().enumerate() {
                        ui.horizontal(|ui| {
                            ui.text_edit_singleline(cidr);
                            if ui.small_button("Remove").clicked() {
                                remove_cidr = Some(index);
                            }
                        });
                    }
                    if let Some(index) = remove_cidr {
                        self.draft.cidr_list.remove(index);
                    }
                    if ui.button("Add CIDR").clicked() {
                        self.draft.cidr_list.push(String::new());
                    }
                });

                let errors = self.draft.errors();
                for error in &errors {
                    ui.colored_label(egui::Color32::RED, error);
                }

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let save_clicked = ui
                        .add_enabled(
                            errors.is_empty() && self.draft != self.settings,
                            egui::Button::new("Save"),
                        )
                        .clicked();
                    if save_clicked {
                        self.settings = self.draft.normalized();
                        self.draft = self.settings.clone();
                        if let Some(engine) = &self.engine {
                            // The redirect list and static networks apply
                            // without an engine restart.
                            engine.set_redirect_list(self.settings.redirect_list.clone());
                            engine.set_cidr_list(self.settings.cidr_list.clone());
                        }
                    }
                    if ui
                        .add_enabled(self.draft != self.settings, egui::Button::new("Revert"))
                        .clicked()
                    {
                        self.draft = self.settings.clone();
                    }
                    if ui.button("Restore defaults").clicked() {
                        self.draft = Settings::default();
                    }
                });
            });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_events();
        self.poll_start();
        self.poll_stop();
        self.poll_retry();

        // Tray-initiated actions. The tray thread only sets flags (see
        // `TrayState::new`); all viewport work happens here, on the UI
        // thread, so `TrayIcon::drop` cannot deadlock against a worker
        // still inside an egui call.
        if self.tray.toggle_requested.swap(false, Ordering::SeqCst) {
            self.toggle_window(ui.ctx());
        }
        if self.tray.quitting.load(Ordering::SeqCst) {
            // Stop the engine first, on a worker thread — dropping the
            // handle on the UI thread joins engine threads and shells out
            // to `route.exe delete` once per routed IP (seconds). Only
            // issue `Close` once the shutdown is complete, otherwise
            // eframe drops `App` (and with it the `EngineHandle`) on the
            // UI thread and we stall.
            //
            // Remember the running intent before taking the handle away:
            // `save` runs after this and must write the auto-start flag
            // for the next launch.
            if self.engine.is_some() || self.starting.is_some() {
                self.engine_running_at_exit = true;
                self.stop_engine(); // no-op if already stopping or idle
            }
            if self.engine.is_none() && self.starting.is_none() && self.stopping.is_none() {
                // Also make sure the viewport is visible before asking it
                // to close: the winit backend silently ignores `Close` for
                // a hidden viewport.
                if self.tray.hidden.swap(false, Ordering::SeqCst) {
                    ui.ctx()
                        .send_viewport_cmd(egui::ViewportCommand::Visible(true));
                }
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }

        // Intercept the window close request: hide to the tray instead of
        // exiting, unless the user chose Quit from the tray menu.
        if ui.ctx().input(|i| i.viewport().close_requested())
            && !self.tray.quitting.load(Ordering::SeqCst)
        {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Visible(false));
            self.tray.hidden.store(true, Ordering::SeqCst);
        }

        // The tray thread cannot wake the event loop, so keep the loop
        // ticking at a low rate regardless of engine state — that bounds
        // the latency between a tray click and the action being applied to
        // one frame (~250 ms). This also covers engine polling when the
        // engine is running, a start is in flight, or a retry is pending.
        ui.ctx().request_repaint_after(Duration::from_millis(250));
        egui::Panel::top("tab_bar").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Tunnel, "Tunnel");
                ui.selectable_value(&mut self.tab, Tab::Log, "Log");
                ui.selectable_value(&mut self.tab, Tab::Settings, "Settings");
            });
        });

        egui::CentralPanel::default_margins().show(ui, |ui| match self.tab {
            Tab::Tunnel => self.tunnel_tab(ui),
            Tab::Log => self.log_tab(ui),
            Tab::Settings => self.settings_tab(ui),
        });
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, SETTINGS_KEY, &self.settings);
        let running = self.engine.is_some() || self.engine_running_at_exit;
        eframe::set_value(storage, ENGINE_RUNNING_KEY, &running);
    }
}
