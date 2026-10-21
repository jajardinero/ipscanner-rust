//! The Settings window. Edits a draft copy that is applied on OK.

use eframe::egui::{self, Context, DragValue, Ui};

use crate::model::{Settings, parse_ports};

pub enum SettingsOutcome {
    Apply,
    Cancel,
}

pub fn show(ctx: &Context, draft: &mut Settings) -> Option<SettingsOutcome> {
    let mut outcome = None;
    let mut open = true;
    egui::Window::new("Settings")
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            egui::Grid::new("settings_grid")
                .num_columns(2)
                .spacing([16.0, 8.0])
                .show(ui, |ui| {
                    ui.heading("Performance");
                    ui.end_row();
                    row(ui, "Hosts scanned in parallel", |ui| {
                        ui.add(DragValue::new(&mut draft.max_parallel).range(1..=1024));
                    });
                    row(ui, "Ping timeout", |ui| {
                        ui.add(
                            DragValue::new(&mut draft.ping_timeout_ms)
                                .range(100..=10_000)
                                .speed(10)
                                .suffix(" ms"),
                        );
                    });
                    row(ui, "Ping attempts", |ui| {
                        ui.add(DragValue::new(&mut draft.ping_tries).range(1..=10));
                    });
                    row(ui, "TCP connect timeout", |ui| {
                        ui.add(
                            DragValue::new(&mut draft.tcp_timeout_ms)
                                .range(100..=10_000)
                                .speed(10)
                                .suffix(" ms"),
                        );
                    });

                    ui.heading("Detection");
                    ui.end_row();
                    row(ui, "Ports to probe", |ui| {
                        ui.add(egui::TextEdit::singleline(&mut draft.ports).desired_width(260.0));
                    });
                    if let Err(e) = parse_ports(&draft.ports) {
                        ui.label("");
                        ui.colored_label(ui.visuals().error_fg_color, e);
                        ui.end_row();
                    }
                    row(ui, "", |ui| {
                        ui.checkbox(&mut draft.resolve_dns, "Resolve names via DNS");
                    });
                    row(ui, "", |ui| {
                        ui.checkbox(
                            &mut draft.resolve_netbios,
                            "Query NetBIOS names (Windows / Samba)",
                        );
                    });
                    row(ui, "", |ui| {
                        ui.checkbox(
                            &mut draft.grab_banners,
                            "Read service banners and web page titles",
                        );
                    });
                    row(ui, "", |ui| {
                        ui.checkbox(&mut draft.raw_arp, "Raw ARP sweep on local subnets")
                            .on_hover_text(
                                "Needs CAP_NET_RAW: sudo setcap cap_net_raw+ep <path to netscan>",
                            );
                    });

                    ui.heading("Actions");
                    ui.end_row();
                    row(ui, "SSH user", |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut draft.ssh_user)
                                .hint_text("current user")
                                .desired_width(160.0),
                        );
                    });
                });

            ui.separator();
            ui.horizontal(|ui| {
                if ui.button("Restore defaults").clicked() {
                    *draft = Settings::default();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let valid = parse_ports(&draft.ports).is_ok();
                    if ui.add_enabled(valid, egui::Button::new("  OK  ")).clicked() {
                        outcome = Some(SettingsOutcome::Apply);
                    }
                    if ui.button("Cancel").clicked() {
                        outcome = Some(SettingsOutcome::Cancel);
                    }
                });
            });
        });
    if !open {
        outcome = Some(SettingsOutcome::Cancel);
    }
    outcome
}

fn row(ui: &mut Ui, label: &str, add: impl FnOnce(&mut Ui)) {
    ui.label(label);
    add(ui);
    ui.end_row();
}
