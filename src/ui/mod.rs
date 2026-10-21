//! egui views. Views never mutate app state directly; they return [`Action`]s.

pub mod details;
pub mod settings;
pub mod table;
pub mod toolbar;
pub mod tools;

use std::net::Ipv4Addr;

use eframe::egui::{self, Color32, Sense, Ui, Vec2};

use crate::actions::{self, Launch};
use crate::model::{Host, HostStatus};

pub enum Action {
    Select { ip: Ipv4Addr, key: String },
    Launch(Launch),
    Copy(String),
    Ping(Ipv4Addr),
    Trace(Ipv4Addr),
    ToggleFavorite(Box<Host>),
    Rescan(Ipv4Addr),
    SetComment { key: String, text: String },
}

/// A host as shown in a table: the host plus per-user annotations.
pub struct Row<'a> {
    pub host: &'a Host,
    pub key: String,
    pub comment: &'a str,
    pub favorite: bool,
}

pub const FAVORITE_COLOR: Color32 = Color32::from_rgb(0xe8, 0xb3, 0x3a);

pub fn status_color(ui: &Ui, status: HostStatus) -> Color32 {
    let dark = ui.visuals().dark_mode;
    match status {
        HostStatus::Alive if dark => Color32::from_rgb(0x4c, 0xc3, 0x5f),
        HostStatus::Alive => Color32::from_rgb(0x1f, 0x9d, 0x3a),
        HostStatus::Dead if dark => Color32::from_rgb(0xd0, 0x5a, 0x5a),
        HostStatus::Dead => Color32::from_rgb(0xc0, 0x39, 0x2b),
        HostStatus::Unknown => ui.visuals().weak_text_color(),
    }
}

/// A filled circle in the status color. Painted, since the default proportional fonts lack "●".
pub fn status_dot(ui: &mut Ui, host: &Host) {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
    let color = status_color(ui, host.status);
    ui.painter().circle_filled(rect.center(), 5.0, color);
    if host.is_self {
        ui.painter()
            .circle_stroke(rect.center(), 6.5, egui::Stroke::new(1.0, color));
    }
    let tip = if host.is_self {
        format!("{} (this computer)", host.status.label())
    } else {
        host.status.label().to_owned()
    };
    response.on_hover_text(tip);
}

pub fn format_rtt(host: &Host) -> String {
    match host.rtt {
        Some(rtt) if rtt.as_secs_f64() < 0.001 => "<1 ms".to_owned(),
        Some(rtt) => format!("{:.0} ms", rtt.as_secs_f64() * 1000.0),
        None => String::new(),
    }
}

/// Right-click menu for a host, shared by both tables and the details panel.
pub fn host_menu(ui: &mut Ui, row: &Row<'_>, ssh_user: &str, out: &mut Vec<Action>) {
    let host = row.host;
    let launches = actions::service_launches(host, ssh_user);
    ui.add_enabled_ui(!launches.is_empty(), |ui| {
        ui.menu_button("Open", |ui| {
            for (label, launch) in launches {
                let unavailable = matches!(launch, Launch::Unavailable(_));
                let tip = launch.describe();
                let response = ui.add_enabled(!unavailable, egui::Button::new(label));
                let response = if unavailable {
                    response.on_disabled_hover_text(tip)
                } else {
                    response.on_hover_text(tip)
                };
                if response.clicked() {
                    out.push(Action::Launch(launch));
                    ui.close();
                }
            }
        });
    });
    ui.menu_button("Copy", |ui| {
        let mut copy = |ui: &mut Ui, label: &str, value: Option<String>| {
            if ui
                .add_enabled(value.is_some(), egui::Button::new(label))
                .clicked()
            {
                out.push(Action::Copy(value.unwrap_or_default()));
                ui.close();
            }
        };
        copy(ui, "IP address", Some(host.ip.to_string()));
        copy(ui, "Name", host.name.clone());
        copy(ui, "MAC address", host.mac.map(|m| m.to_string()));
        copy(ui, "Manufacturer", host.vendor.map(str::to_owned));
        let line = [
            host.name.clone().unwrap_or_default(),
            host.ip.to_string(),
            host.vendor.unwrap_or_default().to_owned(),
            host.mac.map(|m| m.to_string()).unwrap_or_default(),
            host.services_text(),
            row.comment.to_owned(),
        ]
        .join("\t");
        copy(ui, "Whole row", Some(line));
    });
    ui.separator();
    if ui.button("Ping…").clicked() {
        out.push(Action::Ping(host.ip));
        ui.close();
    }
    if ui.button("Tracepath…").clicked() {
        out.push(Action::Trace(host.ip));
        ui.close();
    }
    if ui.button("Rescan host").clicked() {
        out.push(Action::Rescan(host.ip));
        ui.close();
    }
    ui.separator();
    let fav_label = if row.favorite {
        "Remove from Favorites"
    } else {
        "Add to Favorites"
    };
    if ui.button(fav_label).clicked() {
        out.push(Action::ToggleFavorite(Box::new(host.clone())));
        ui.close();
    }
}
