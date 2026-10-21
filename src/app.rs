//! Application state and the per-frame UI.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use eframe::egui::{self, Key, RichText, ThemePreference};
use tokio::runtime::{Handle, Runtime};

use crate::export::{self, ExportRow};
use crate::model::{Favorite, Host, HostStatus, Mac, Persisted, Settings, ThemeChoice};
use crate::oui;
use crate::scanner::netinfo::NetInfo;
use crate::scanner::{self, ScanEvent, ScanHandle, ScanRequest, range};
use crate::ui::settings::{self, SettingsOutcome};
use crate::ui::table::{self, SortState};
use crate::ui::toolbar::{Toolbar, ToolbarAction};
use crate::ui::tools::{ToolKind, ToolWindow};
use crate::ui::{Action, Row, details};

const STORAGE_KEY: &str = "netscan";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Results,
    Favorites,
}

struct ActiveScan {
    handle: ScanHandle,
    started: Instant,
    done: usize,
    total: usize,
    /// A single-host rescan; it doesn't replace the last scan summary.
    single: bool,
}

struct Summary {
    alive: usize,
    total: usize,
    elapsed: Duration,
    cancelled: bool,
}

pub struct NetScanApp {
    /// `Option` so `Drop` can shut it down without waiting for blocking DNS lookups.
    rt: Option<Runtime>,
    handle: Handle,
    state: Persisted,
    net: NetInfo,
    iface_idx: Option<usize>,
    hosts: BTreeMap<Ipv4Addr, Host>,
    scan: Option<ActiveScan>,
    summary: Option<Summary>,
    notice: Option<String>,
    range_error: Option<String>,
    filter: String,
    tab: Tab,
    sort: SortState,
    fav_sort: SortState,
    selected_ip: Option<Ipv4Addr>,
    selected_fav: Option<String>,
    settings_draft: Option<Settings>,
    show_about: bool,
    tools: Vec<ToolWindow>,
    next_tool_id: u64,
    export_rx: Option<mpsc::Receiver<Result<String, String>>>,
    applied_theme: Option<ThemeChoice>,
}

impl NetScanApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut state: Persisted = cc
            .storage
            .and_then(|s| eframe::get_value(s, STORAGE_KEY))
            .unwrap_or_default();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("netscan-worker")
            .build()
            .expect("failed to start the tokio runtime");
        let net = NetInfo::detect();
        let iface_idx = net.primary;
        if state.last_range.trim().is_empty()
            && let Some(iface) = iface_idx.and_then(|i| net.ifaces.get(i))
        {
            state.last_range = iface.default_range();
        }
        Self {
            handle: rt.handle().clone(),
            rt: Some(rt),
            state,
            net,
            iface_idx,
            hosts: BTreeMap::new(),
            scan: None,
            summary: None,
            notice: None,
            range_error: None,
            filter: String::new(),
            tab: Tab::Results,
            sort: SortState::default(),
            fav_sort: SortState::default(),
            selected_ip: None,
            selected_fav: None,
            settings_draft: None,
            show_about: false,
            tools: Vec::new(),
            next_tool_id: 0,
            export_rx: None,
            applied_theme: None,
        }
    }

    fn start_scan(&mut self, ctx: &egui::Context) {
        if self.scan.is_some() {
            return;
        }
        let targets = match range::parse_targets(&self.state.last_range) {
            Ok(targets) => targets,
            Err(e) => {
                self.range_error = Some(e);
                return;
            }
        };
        self.range_error = None;
        self.notice = None;
        self.summary = None;
        self.hosts.clear();
        self.tab = Tab::Results;
        self.launch(targets, false, ctx);
    }

    fn rescan_host(&mut self, ip: Ipv4Addr, ctx: &egui::Context) {
        if self.scan.is_some() {
            self.notice =
                Some("Wait for the current scan to finish before rescanning a host.".into());
            return;
        }
        self.hosts.remove(&ip);
        self.launch(vec![ip], true, ctx);
    }

    fn launch(&mut self, targets: Vec<Ipv4Addr>, single: bool, ctx: &egui::Context) {
        let total = targets.len();
        let request = ScanRequest {
            targets,
            settings: self.state.settings.clone(),
            net: self.net.clone(),
        };
        let handle = scanner::start(&self.handle, request, ctx.clone());
        self.scan = Some(ActiveScan {
            handle,
            started: Instant::now(),
            done: 0,
            total,
            single,
        });
    }

    fn stop_scan(&mut self) {
        if let Some(scan) = &self.scan {
            scan.handle.cancel();
        }
    }

    fn drain_events(&mut self) {
        let Some(scan) = &mut self.scan else { return };
        let mut finished = None;
        while let Ok(event) = scan.handle.events.try_recv() {
            match event {
                ScanEvent::Host(host) => self
                    .hosts
                    .entry(host.ip)
                    .or_insert_with(|| Host::new(host.ip))
                    .merge(*host),
                ScanEvent::Progress { done, total } => {
                    scan.done = done;
                    scan.total = total;
                }
                ScanEvent::Notice(notice) => self.notice = Some(notice),
                ScanEvent::Finished { elapsed, cancelled } => {
                    finished = Some((elapsed, cancelled));
                    break;
                }
            }
        }
        let Some((elapsed, cancelled)) = finished else {
            return;
        };
        let scan = self.scan.take().expect("scan is running");
        if !scan.single {
            let alive = self
                .hosts
                .values()
                .filter(|h| h.status == HostStatus::Alive)
                .count();
            self.summary = Some(Summary {
                alive,
                total: scan.total,
                elapsed,
                cancelled,
            });
        }
        self.refresh_favorites();
    }

    /// Update favorites' last known IP and name from live results.
    fn refresh_favorites(&mut self) {
        for (key, fav) in &mut self.state.favorites {
            if let Some(host) =
                find_live(&self.hosts, key, fav).filter(|h| h.status == HostStatus::Alive)
            {
                fav.ip = host.ip;
                if host.name.is_some() {
                    fav.name = host.name.clone();
                }
                if host.mac.is_some() {
                    fav.mac = host.mac;
                }
            }
        }
    }

    fn export_csv(&mut self, ctx: &egui::Context) {
        let rows: Vec<ExportRow> = match self.tab {
            Tab::Results => result_rows(&self.hosts, &self.state, &self.filter, self.sort)
                .into_iter()
                .map(|r| ExportRow {
                    host: r.host.clone(),
                    comment: r.comment.to_owned(),
                })
                .collect(),
            Tab::Favorites => {
                let favs = favorite_hosts(&self.hosts, &self.state.favorites);
                favorite_rows(&favs, &self.state, &self.filter, self.fav_sort)
                    .into_iter()
                    .map(|r| ExportRow {
                        host: r.host.clone(),
                        comment: r.comment.to_owned(),
                    })
                    .collect()
            }
        };
        if rows.is_empty() {
            self.notice = Some("Nothing to export.".into());
            return;
        }
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let file_name = format!("netscan-{}.csv", chrono::Local::now().format("%Y%m%d-%H%M"));
            let Some(path) = rfd::FileDialog::new()
                .set_title("Export scan results")
                .set_file_name(file_name)
                .add_filter("CSV", &["csv"])
                .save_file()
            else {
                return;
            };
            let result = export::save_csv(&path, &rows)
                .map(|()| format!("Exported {} hosts to {}", rows.len(), path.display()));
            let _ = tx.send(result);
            ctx.request_repaint();
        });
        self.export_rx = Some(rx);
    }

    fn handle_actions(&mut self, actions: Vec<Action>, ctx: &egui::Context) {
        for action in actions {
            match action {
                Action::Select { ip, key } => match self.tab {
                    Tab::Results => self.selected_ip = Some(ip),
                    Tab::Favorites => self.selected_fav = Some(key),
                },
                Action::Launch(launch) => {
                    if let Err(e) = launch.run() {
                        self.notice = Some(e);
                    }
                }
                Action::Copy(text) => {
                    self.notice = Some(format!("Copied “{text}”"));
                    ctx.copy_text(text);
                }
                Action::Ping(ip) => self.open_tool(ToolKind::Ping, ip, ctx),
                Action::Trace(ip) => self.open_tool(ToolKind::Trace, ip, ctx),
                Action::Rescan(ip) => self.rescan_host(ip, ctx),
                Action::ToggleFavorite(host) => {
                    let key = host.key();
                    let removed = self.state.favorites.remove(&key).is_some()
                        || self.state.favorites.remove(&host.ip.to_string()).is_some();
                    if !removed {
                        self.state.favorites.insert(
                            key,
                            Favorite {
                                ip: host.ip,
                                mac: host.mac,
                                name: host.name.clone(),
                            },
                        );
                    }
                }
                Action::SetComment { key, text } => {
                    if text.trim().is_empty() {
                        self.state.comments.remove(&key);
                    } else {
                        self.state.comments.insert(key, text);
                    }
                }
            }
        }
    }

    fn open_tool(&mut self, kind: ToolKind, ip: Ipv4Addr, ctx: &egui::Context) {
        self.next_tool_id += 1;
        self.tools.push(ToolWindow::new(
            self.next_tool_id,
            kind,
            ip,
            &self.handle,
            ctx,
        ));
    }

    fn menu_bar(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("Export CSV…").clicked() {
                    self.export_csv(&ctx);
                    ui.close();
                }
                ui.separator();
                if ui.button("Quit").clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            ui.menu_button("View", |ui| {
                ui.checkbox(&mut self.state.show_dead, "Show dead hosts");
                ui.checkbox(&mut self.state.show_details, "Details panel");
                ui.separator();
                ui.weak("Theme");
                ui.radio_value(&mut self.state.theme, ThemeChoice::System, "Follow system");
                ui.radio_value(&mut self.state.theme, ThemeChoice::Light, "Light");
                ui.radio_value(&mut self.state.theme, ThemeChoice::Dark, "Dark");
            });
            if ui.button("Settings").clicked() {
                self.settings_draft = Some(self.state.settings.clone());
            }
            ui.menu_button("Help", |ui| {
                if ui.button("About NetScan").clicked() {
                    self.show_about = true;
                    ui.close();
                }
            });
        });
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let action = Toolbar {
            range: &mut self.state.last_range,
            filter: &mut self.filter,
            ifaces: &self.net.ifaces,
            iface_idx: &mut self.iface_idx,
            scanning: self.scan.is_some(),
            range_error: self.range_error.as_deref(),
        }
        .show(ui);
        match action {
            Some(ToolbarAction::Start) => self.start_scan(&ctx),
            Some(ToolbarAction::Stop) => self.stop_scan(),
            Some(ToolbarAction::InterfaceChanged) => self.use_selected_iface_range(),
            Some(ToolbarAction::Redetect) => {
                let previous = self
                    .iface_idx
                    .and_then(|i| self.net.ifaces.get(i))
                    .map(|i| i.name.clone());
                self.net = NetInfo::detect();
                self.iface_idx = previous
                    .and_then(|name| self.net.ifaces.iter().position(|i| i.name == name))
                    .or(self.net.primary);
                self.use_selected_iface_range();
            }
            None => {}
        }
    }

    fn use_selected_iface_range(&mut self) {
        if let Some(iface) = self.iface_idx.and_then(|i| self.net.ifaces.get(i)) {
            self.state.last_range = iface.default_range();
            self.range_error = None;
        }
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let alive = self
                .hosts
                .values()
                .filter(|h| h.status == HostStatus::Alive)
                .count();
            if let Some(scan) = &self.scan {
                let fraction = if scan.total == 0 {
                    0.0
                } else {
                    scan.done as f32 / scan.total as f32
                };
                ui.add(
                    egui::ProgressBar::new(fraction)
                        .desired_width(180.0)
                        .text(format!("{} / {}", scan.done, scan.total))
                        .animate(true),
                );
                ui.label(format!(
                    "Scanning… {alive} alive · {:.1} s",
                    scan.started.elapsed().as_secs_f32()
                ));
                ui.ctx().request_repaint_after(Duration::from_millis(100));
            } else if let Some(s) = &self.summary {
                let verb = if s.cancelled { "Stopped" } else { "Done" };
                ui.label(format!(
                    "{verb}: {} alive of {} scanned in {:.1} s",
                    s.alive,
                    s.total,
                    s.elapsed.as_secs_f32()
                ));
            } else {
                ui.weak("Ready – press Scan (F5)");
            }

            if let Some(notice) = self.notice.clone() {
                ui.separator();
                if ui.small_button("×").on_hover_text("Dismiss").clicked() {
                    self.notice = None;
                }
                // Notices that end in a command ("… run: sudo setcap …") copy just the command.
                let copyable = notice
                    .split_once("run: ")
                    .map_or(notice.as_str(), |(_, cmd)| cmd);
                if ui
                    .small_button("Copy")
                    .on_hover_text(format!("Copy “{copyable}”"))
                    .clicked()
                {
                    ui.ctx().copy_text(copyable.to_owned());
                }
                ui.add(
                    egui::Label::new(RichText::new(&notice).color(ui.visuals().warn_fg_color))
                        .truncate(),
                )
                .on_hover_text(&notice);
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(iface) = self.iface_idx.and_then(|i| self.net.ifaces.get(i)) {
                    let gateway = self
                        .net
                        .gateway
                        .map(|g| format!(" · gateway {g}"))
                        .unwrap_or_default();
                    ui.weak(format!("{}{gateway}", iface.label()));
                }
            });
        });
    }

    fn central(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        let alive = self
            .hosts
            .values()
            .filter(|h| h.status == HostStatus::Alive)
            .count();
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Results, format!("Results ({alive})"));
            ui.selectable_value(
                &mut self.tab,
                Tab::Favorites,
                format!("★ Favorites ({})", self.state.favorites.len()),
            );
        });
        ui.separator();

        let ssh_user = self.state.settings.ssh_user.clone();
        match self.tab {
            Tab::Results => {
                let rows = result_rows(&self.hosts, &self.state, &self.filter, self.sort);
                if rows.is_empty() {
                    empty_hint(
                        ui,
                        if self.scan.is_some() {
                            "Scanning…"
                        } else if self.hosts.is_empty() {
                            "No results yet. Enter a range and press Scan."
                        } else {
                            "No hosts match the current search."
                        },
                    );
                    return;
                }
                let selected = self.selected_ip;
                actions.extend(table::show(
                    ui,
                    "results",
                    &rows,
                    |r| Some(r.host.ip) == selected,
                    &mut self.sort,
                    &ssh_user,
                ));
            }
            Tab::Favorites => {
                let favs = favorite_hosts(&self.hosts, &self.state.favorites);
                let rows = favorite_rows(&favs, &self.state, &self.filter, self.fav_sort);
                if rows.is_empty() {
                    empty_hint(
                        ui,
                        if self.state.favorites.is_empty() {
                            "No favorites yet. Right-click a host and choose “Add to Favorites”."
                        } else {
                            "No favorites match the current search."
                        },
                    );
                    return;
                }
                let selected = self.selected_fav.clone();
                actions.extend(table::show(
                    ui,
                    "favorites",
                    &rows,
                    |r| selected.as_deref() == Some(r.key.as_str()),
                    &mut self.fav_sort,
                    &ssh_user,
                ));
            }
        }
    }

    fn details(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        let ssh_user = &self.state.settings.ssh_user;
        match self.tab {
            Tab::Results => {
                let row = self
                    .selected_ip
                    .and_then(|ip| self.hosts.get(&ip))
                    .map(|host| make_row(host, host.key(), &self.state));
                actions.extend(details::show(ui, row.as_ref(), ssh_user));
            }
            Tab::Favorites => {
                let favs = favorite_hosts(&self.hosts, &self.state.favorites);
                let row = self
                    .selected_fav
                    .as_ref()
                    .and_then(|key| favs.iter().find(|(k, _)| k == key))
                    .map(|(key, host)| make_row(host, key.clone(), &self.state));
                actions.extend(details::show(ui, row.as_ref(), ssh_user));
            }
        }
    }

    fn windows(&mut self, ctx: &egui::Context) {
        if let Some(draft) = &mut self.settings_draft {
            match settings::show(ctx, draft) {
                Some(SettingsOutcome::Apply) => {
                    self.state.settings = self.settings_draft.take().unwrap_or_default()
                }
                Some(SettingsOutcome::Cancel) => self.settings_draft = None,
                None => {}
            }
        }

        if self.show_about {
            egui::Window::new("About NetScan")
                .open(&mut self.show_about)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.heading(format!("NetScan {}", env!("CARGO_PKG_VERSION")));
                    ui.label("A fast LAN scanner for Linux, in the spirit of Advanced IP Scanner.");
                    ui.add_space(6.0);
                    ui.label("Finds hosts with ICMP, TCP and ARP; resolves DNS and NetBIOS names;");
                    ui.label(
                        "identifies vendors from the IEEE OUI registry and probes common services.",
                    );
                    ui.add_space(6.0);
                    ui.weak("Built with Rust, egui and tokio.");
                });
        }

        for tool in &mut self.tools {
            tool.show(ctx, &self.handle);
        }
        // Dropping a closed window stops its process.
        self.tools.retain(ToolWindow::is_open);
    }
}

impl eframe::App for NetScanApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();
        if let Some(rx) = &self.export_rx
            && let Ok(result) = rx.try_recv()
        {
            self.notice = Some(result.unwrap_or_else(|e| e));
            self.export_rx = None;
        }
        if self.applied_theme != Some(self.state.theme) {
            ctx.set_theme(match self.state.theme {
                ThemeChoice::System => ThemePreference::System,
                ThemeChoice::Light => ThemePreference::Light,
                ThemeChoice::Dark => ThemePreference::Dark,
            });
            self.applied_theme = Some(self.state.theme);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let mut actions = Vec::new();

        if ctx.input(|i| i.key_pressed(Key::F5)) {
            if self.scan.is_some() {
                self.stop_scan()
            } else {
                self.start_scan(&ctx)
            }
        }

        egui::Panel::top("menu").show(ui, |ui| self.menu_bar(ui));
        egui::Panel::top("toolbar")
            .frame(egui::Frame::side_top_panel(&ctx.global_style()).inner_margin(8.0))
            .show(ui, |ui| self.toolbar(ui));
        egui::Panel::bottom("status").show(ui, |ui| self.status_bar(ui));
        if self.state.show_details {
            egui::Panel::right("details")
                .resizable(true)
                .default_size(320.0)
                .size_range(240.0..=600.0)
                .show(ui, |ui| self.details(ui, &mut actions));
        }
        egui::CentralPanel::default().show(ui, |ui| self.central(ui, &mut actions));

        self.windows(&ctx);
        self.handle_actions(actions, &ctx);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, STORAGE_KEY, &self.state);
    }
}

impl Drop for NetScanApp {
    fn drop(&mut self) {
        self.stop_scan();
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

fn empty_hint(ui: &mut egui::Ui, text: &str) {
    ui.add_space(40.0);
    ui.vertical_centered(|ui| ui.weak(text));
}

fn make_row<'a>(host: &'a Host, key: String, state: &'a Persisted) -> Row<'a> {
    Row {
        comment: state
            .comments
            .get(&key)
            .map(String::as_str)
            .unwrap_or_default(),
        favorite: state.favorites.contains_key(&key),
        key,
        host,
    }
}

fn matches_filter(row: &Row<'_>, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let host = row.host;
    let fields = [
        host.name.as_deref(),
        host.dns_name.as_deref(),
        host.netbios_name.as_deref(),
        host.workgroup.as_deref(),
        host.vendor,
        Some(row.comment),
    ];
    host.ip.to_string().contains(needle)
        || host
            .mac
            .is_some_and(|m| m.to_string().to_lowercase().contains(needle))
        || host.services_text().to_lowercase().contains(needle)
        || fields
            .into_iter()
            .flatten()
            .any(|f| f.to_lowercase().contains(needle))
}

fn result_rows<'a>(
    hosts: &'a BTreeMap<Ipv4Addr, Host>,
    state: &'a Persisted,
    filter: &str,
    sort: SortState,
) -> Vec<Row<'a>> {
    let needle = filter.trim().to_lowercase();
    let mut rows: Vec<Row<'a>> = hosts
        .values()
        .filter(|h| state.show_dead || h.status == HostStatus::Alive)
        .map(|h| make_row(h, h.key(), state))
        .filter(|r| matches_filter(r, &needle))
        .collect();
    table::sort_rows(&mut rows, sort);
    rows
}

/// The live host for a favorite: matched by MAC, else by its last IP if that isn't another device.
fn find_live<'a>(
    hosts: &'a BTreeMap<Ipv4Addr, Host>,
    key: &str,
    fav: &Favorite,
) -> Option<&'a Host> {
    if let Ok(mac) = key.parse::<Mac>()
        && let Some(host) = hosts.values().find(|h| h.mac == Some(mac))
    {
        return Some(host);
    }
    hosts
        .get(&fav.ip)
        .filter(|h| h.mac.is_none() || h.mac == fav.mac)
}

/// Each favorite paired with its live host, or a placeholder built from what was last seen.
fn favorite_hosts<'a>(
    hosts: &'a BTreeMap<Ipv4Addr, Host>,
    favorites: &'a BTreeMap<String, Favorite>,
) -> Vec<(String, Cow<'a, Host>)> {
    favorites
        .iter()
        .map(|(key, fav)| {
            let host = match find_live(hosts, key, fav) {
                Some(live) => Cow::Borrowed(live),
                None => {
                    let mut host = Host::new(fav.ip);
                    host.mac = fav.mac;
                    host.vendor = fav.mac.and_then(oui::lookup);
                    host.name = fav.name.clone();
                    Cow::Owned(host)
                }
            };
            (key.clone(), host)
        })
        .collect()
}

fn favorite_rows<'a>(
    favs: &'a [(String, Cow<'a, Host>)],
    state: &'a Persisted,
    filter: &str,
    sort: SortState,
) -> Vec<Row<'a>> {
    let needle = filter.trim().to_lowercase();
    let mut rows: Vec<Row<'a>> = favs
        .iter()
        .map(|(key, host)| make_row(host, key.clone(), state))
        .filter(|r| matches_filter(r, &needle))
        .collect();
    table::sort_rows(&mut rows, sort);
    rows
}
