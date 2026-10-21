//! Side panel with everything known about the selected host.

use eframe::egui::{self, RichText, Ui};

use crate::actions::{self, Launch};

use super::{Action, FAVORITE_COLOR, Row, format_rtt, host_menu, status_color};

pub fn show(ui: &mut Ui, row: Option<&Row<'_>>, ssh_user: &str) -> Vec<Action> {
    let mut out = Vec::new();
    let Some(row) = row else {
        ui.add_space(24.0);
        ui.vertical_centered(|ui| ui.weak("Select a host to see its details."));
        return out;
    };
    let host = row.host;

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let star = if row.favorite {
                    RichText::new("★").color(FAVORITE_COLOR)
                } else {
                    RichText::new("☆")
                };
                let tip = if row.favorite {
                    "Remove from Favorites"
                } else {
                    "Add to Favorites"
                };
                if ui
                    .add(egui::Button::new(star.size(18.0)).frame(false))
                    .on_hover_text(tip)
                    .clicked()
                {
                    out.push(Action::ToggleFavorite(Box::new(host.clone())));
                }
                let title = host.name.clone().unwrap_or_else(|| host.ip.to_string());
                ui.add(egui::Label::new(RichText::new(title).heading()).truncate());
            });
            ui.add_space(4.0);

            egui::Grid::new("details_grid")
                .num_columns(2)
                .spacing([12.0, 4.0])
                .striped(true)
                .show(ui, |ui| {
                    let field = |ui: &mut Ui, label: &str, value: Option<String>| {
                        if let Some(value) = value.filter(|v| !v.is_empty()) {
                            ui.weak(label);
                            ui.add(egui::Label::new(value).wrap().selectable(true));
                            ui.end_row();
                        }
                    };
                    ui.weak("Status");
                    ui.colored_label(status_color(ui, host.status), host.status.label());
                    ui.end_row();
                    let role = match (host.is_self, host.is_gateway) {
                        (true, _) => Some("This computer".to_owned()),
                        (_, true) => Some("Default gateway".to_owned()),
                        _ => None,
                    };
                    field(ui, "Role", role);
                    field(ui, "IP address", Some(host.ip.to_string()));
                    field(ui, "DNS name", host.dns_name.clone());
                    field(ui, "NetBIOS name", host.netbios_name.clone());
                    field(ui, "Workgroup", host.workgroup.clone());
                    field(ui, "MAC address", host.mac.map(|m| m.to_string()));
                    field(ui, "Manufacturer", host.vendor.map(str::to_owned));
                    field(ui, "Round trip", Some(format_rtt(host)));
                });

            ui.add_space(8.0);
            ui.strong("Services");
            if host.services.is_empty() {
                ui.weak("No open ports found.");
            }
            for service in &host.services {
                ui.horizontal(|ui| {
                    let launch = actions::service_launch(service, host.ip, ssh_user);
                    match &launch {
                        Some(Launch::Unavailable(why)) => {
                            ui.add_enabled(false, egui::Button::new(service.badge()).small())
                                .on_disabled_hover_text(why);
                        }
                        Some(l) => {
                            if ui
                                .small_button(service.badge())
                                .on_hover_text(l.describe())
                                .clicked()
                            {
                                out.push(Action::Launch(l.clone()));
                            }
                        }
                        None => {
                            ui.label(service.badge());
                        }
                    }
                    ui.weak(format!("tcp/{}", service.port));
                });
                if let Some(banner) = &service.banner {
                    ui.indent(("banner", service.port), |ui| {
                        ui.add(
                            egui::Label::new(RichText::new(banner).small().weak())
                                .wrap()
                                .selectable(true),
                        );
                    });
                }
            }

            ui.add_space(8.0);
            ui.strong("Comments");
            let mut comment = row.comment.to_owned();
            let edit = egui::TextEdit::multiline(&mut comment)
                .hint_text("Notes about this host (saved automatically)")
                .desired_rows(3)
                .desired_width(f32::INFINITY);
            if ui.add(edit).changed() {
                out.push(Action::SetComment {
                    key: row.key.clone(),
                    text: comment,
                });
            }

            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                if ui.button("Ping…").clicked() {
                    out.push(Action::Ping(host.ip));
                }
                if ui.button("Tracepath…").clicked() {
                    out.push(Action::Trace(host.ip));
                }
                if ui.button("Rescan").clicked() {
                    out.push(Action::Rescan(host.ip));
                }
                ui.menu_button("More…", |ui| host_menu(ui, row, ssh_user, &mut out));
            });
        });
    out
}
