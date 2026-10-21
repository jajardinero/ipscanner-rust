//! Scan button, range field, interface picker and search box.

use eframe::egui::{self, Color32, Key, RichText, Ui};

use crate::scanner::netinfo::LocalIface;

pub enum ToolbarAction {
    Start,
    Stop,
    /// The user picked another interface; the range should follow it.
    InterfaceChanged,
    Redetect,
}

pub struct Toolbar<'a> {
    pub range: &'a mut String,
    pub filter: &'a mut String,
    pub ifaces: &'a [LocalIface],
    pub iface_idx: &'a mut Option<usize>,
    pub scanning: bool,
    pub range_error: Option<&'a str>,
}

impl Toolbar<'_> {
    pub fn show(self, ui: &mut Ui) -> Option<ToolbarAction> {
        let mut action = None;
        ui.horizontal(|ui| {
            let (label, fill) = if self.scanning {
                ("Stop", Color32::from_rgb(0xc0, 0x39, 0x2b))
            } else {
                ("Scan", Color32::from_rgb(0x1f, 0x9d, 0x3a))
            };
            let button = egui::Button::new(RichText::new(label).strong().size(15.0).color(Color32::WHITE))
                .fill(fill)
                .min_size(egui::vec2(96.0, 30.0));
            if ui.add(button).on_hover_text("Start or stop the scan (F5)").clicked() {
                action = Some(if self.scanning { ToolbarAction::Stop } else { ToolbarAction::Start });
            }

            ui.add_space(8.0);
            let range_edit = egui::TextEdit::singleline(self.range)
                .hint_text("e.g. 192.168.1.1-254, 10.0.0.0/24")
                .desired_width(280.0)
                .font(egui::TextStyle::Monospace);
            let response = ui.add_enabled(!self.scanning, range_edit);
            let response = match self.range_error {
                Some(err) => response.on_hover_text(RichText::new(err).color(ui.visuals().error_fg_color)),
                None => response.on_hover_text("IP ranges to scan: single IPs, a.b.c.d-e, a.b.c.d-e.f.g.h or CIDR, comma separated"),
            };
            if response.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) && !self.scanning {
                action = Some(ToolbarAction::Start);
            }

            let selected = self
                .iface_idx
                .and_then(|i| self.ifaces.get(i))
                .map(LocalIface::label)
                .unwrap_or_else(|| "No interface".to_owned());
            ui.add_enabled_ui(!self.scanning, |ui| {
                egui::ComboBox::from_id_salt("iface")
                    .selected_text(selected)
                    .width(220.0)
                    .show_ui(ui, |ui| {
                        for (i, iface) in self.ifaces.iter().enumerate() {
                            if ui.selectable_label(*self.iface_idx == Some(i), iface.label()).clicked() {
                                *self.iface_idx = Some(i);
                                action = Some(ToolbarAction::InterfaceChanged);
                            }
                        }
                    });
                if ui.button("Detect").on_hover_text("Re-detect interfaces and use the selected subnet").clicked() {
                    action = Some(ToolbarAction::Redetect);
                }
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if !self.filter.is_empty() && ui.small_button("×").on_hover_text("Clear search").clicked() {
                    self.filter.clear();
                }
                ui.add(
                    egui::TextEdit::singleline(self.filter)
                        .hint_text("Search name, IP, MAC, vendor…")
                        .desired_width(240.0),
                );
            });
        });
        if let Some(err) = self.range_error {
            ui.colored_label(ui.visuals().error_fg_color, err);
        }
        action
    }
}
