//! egui application layer — UI-only state and rendering.
//!
//! **Rule:** no protocol/tunnel logic in this module. The UI reads state
//! from [`crate::core`] and dispatches intents into it.
//!
//! Settings persistence uses eframe's built-in storage: loaded in
//! [`App::new`], written in [`eframe::App::save`] (on exit).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use eframe::egui;

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
    /// Event stream from the engine.
    events: Option<mpsc::Receiver<Event>>,
    /// Recent engine events, oldest first.
    log: VecDeque<String>,
    /// Unique domains that went through the resolver (this session) and
    /// the processes that asked for them, when attribution is available.
    seen: BTreeMap<String, BTreeSet<String>>,
    /// Log-tab view: group everything by top-level domain instead of
    /// listing every domain.
    show_tlds_only: bool,
    /// When the next automatic engine-start retry is due (`None` when no
    /// retry is pending).
    start_retry_at: Option<Instant>,
    /// The last start failure logged — repeated identical failures are not
    /// re-logged, to keep the retry loop quiet.
    last_start_error: Option<String>,
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
        let mut app = Self {
            draft: settings.clone(),
            settings,
            tab: Tab::Tunnel,
            engine: None,
            events: None,
            log: VecDeque::new(),
            seen: BTreeMap::new(),
            show_tlds_only: false,
            start_retry_at: None,
            last_start_error: None,
        };
        if engine_was_running {
            // The engine was running when the app last closed (without an
            // explicit Stop) — restore that state.
            app.push_log("engine auto-started (was running at last exit)".to_owned());
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
        ui.separator();
        ui.checkbox(
            &mut self.show_tlds_only,
            "Group by registrable domain (company.tld)",
        );
        ui.separator();

        let mut add: Option<String> = None;
        if self.show_tlds_only {
            // Aggregate every domain into its registrable part; processes
            // are merged.
            let mut tlds: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            for (domain, processes) in &self.seen {
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
            let mut domains: Vec<&String> = self.seen.keys().collect();
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
        let has_pending_edits = self.draft != self.settings;
        self.settings.redirect_list.push(domain.to_owned());
        self.settings = self.settings.normalized();
        if !has_pending_edits {
            self.draft = self.settings.clone();
        }
        if let Some(engine) = &self.engine {
            engine.set_redirect_list(self.settings.redirect_list.clone());
        }
        self.push_log(format!("added `{domain}` to the redirect list"));
    }

    fn tunnel_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("DNS Tunnel");
        ui.separator();

        let running = self.engine.is_some();
        let settings_ok = self.settings.errors().is_empty();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!running && settings_ok, egui::Button::new("Start"))
                .clicked()
            {
                self.start_engine();
            }
            if ui.add_enabled(running, egui::Button::new("Stop")).clicked() {
                self.engine = None; // Drop → shutdown + route cleanup
            }
            ui.label(if running { "running" } else { "stopped" });
        });
        if !running && !settings_ok {
            ui.label("Engine will not start — fix the settings first (Settings tab).");
        }

        ui.separator();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for line in &self.log {
                    ui.monospace(line);
                }
            });
    }

    /// Starts the engine with the committed settings.
    fn start_engine(&mut self) {
        let (tx, rx) = mpsc::channel();
        match Engine::start(&self.settings, tx) {
            Ok(handle) => {
                self.engine = Some(handle);
                self.events = Some(rx);
                self.start_retry_at = None;
                self.last_start_error = None;
            }
            Err(e) => {
                let message = format!("error: failed to start engine: {e}");
                if self.last_start_error.as_deref() != Some(message.as_str()) {
                    self.push_log(message.clone());
                    self.last_start_error = Some(message);
                }
                self.start_retry_at = Some(Instant::now() + START_RETRY_INTERVAL);
            }
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
            if self.engine.is_none() && self.settings.errors().is_empty() {
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
            self.push_log(match event {
                Event::Started { listen, gateway } => {
                    format!("started: listening on {listen}, routing via {gateway}")
                }
                Event::Stopped => "stopped: routes cleaned up".to_owned(),
                Event::QueryForwarded {
                    domain,
                    process,
                    in_redirect_list,
                } => {
                    let route_ident = match in_redirect_list {
                        true => "🛡️",
                        false => "➡️",
                    };
                    match process {
                        Some(process) => format!("{route_ident} query -> {domain} ({process})",),
                        None => format!("{route_ident} query -> {domain}"),
                    }
                }
                Event::RouteAdded { ip } => format!("route + {ip}"),
                Event::RouteRemoved { ip } => format!("route - {ip}"),
                Event::Error(message) => format!("error: {message}"),
                Event::Warning(message) => format!("warning: {message}"),
                Event::Info(message) => message,
            });
        }
    }

    /// Appends a line to the bounded event log.
    fn push_log(&mut self, line: String) {
        if self.log.len() >= LOG_CAPACITY {
            self.log.pop_front();
        }
        self.log.push_back(line);
    }

    fn settings_tab(&mut self, ui: &mut egui::Ui) {
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
                ui.add(egui::DragValue::new(&mut self.draft.timeout_ms).range(1..=u64::MAX));
                ui.end_row();
            });

        ui.add_space(8.0);
        ui.label("Redirect list (routed through the VPN, subdomains included)");
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

        ui.add_space(8.0);
        ui.label("Static routes (CIDR — always routed while the engine runs)");
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
                    // The redirect list and static networks apply without an
                    // engine restart.
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
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_events();
        self.poll_retry();
        if self.engine.is_some() || self.start_retry_at.is_some() {
            // Keep polling events and retries while the engine runs or a
            // retry is pending.
            ui.ctx().request_repaint_after(Duration::from_millis(250));
        }
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
        eframe::set_value(storage, ENGINE_RUNNING_KEY, &self.engine.is_some());
    }
}
