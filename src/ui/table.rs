//! The sortable host table used by the Results and Favorites tabs.

use std::cmp::Ordering;

use eframe::egui::{self, Align, Label, Layout, RichText, Sense, Shape, Stroke, Ui, Vec2, pos2};
use egui_extras::{Column, TableBuilder};

use crate::actions;

use super::{Action, FAVORITE_COLOR, Row, format_rtt, host_menu, status_dot};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SortColumn {
    Status,
    Name,
    #[default]
    Ip,
    Vendor,
    Mac,
    Services,
    Rtt,
    Comment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SortState {
    pub column: SortColumn,
    pub ascending: bool,
}

impl Default for SortState {
    fn default() -> Self {
        Self {
            column: SortColumn::Ip,
            ascending: true,
        }
    }
}

const COLUMNS: [(SortColumn, &str); 8] = [
    (SortColumn::Status, ""),
    (SortColumn::Name, "Name"),
    (SortColumn::Ip, "IP"),
    (SortColumn::Vendor, "Manufacturer"),
    (SortColumn::Mac, "MAC address"),
    (SortColumn::Services, "Services"),
    (SortColumn::Rtt, "RTT"),
    (SortColumn::Comment, "Comments"),
];

/// Missing values sort last regardless of direction.
fn cmp_opt<T: Ord>(a: Option<T>, b: Option<T>, ascending: bool) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) if ascending => a.cmp(&b),
        (Some(a), Some(b)) => b.cmp(&a),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

pub fn sort_rows(rows: &mut [Row<'_>], sort: SortState) {
    let asc = sort.ascending;
    let lower = |s: Option<&str>| s.filter(|s| !s.is_empty()).map(str::to_lowercase);
    rows.sort_by(|a, b| {
        let (x, y) = (a.host, b.host);
        let primary = match sort.column {
            SortColumn::Status => cmp_opt(Some(x.status), Some(y.status), asc),
            SortColumn::Name => cmp_opt(lower(x.name.as_deref()), lower(y.name.as_deref()), asc),
            SortColumn::Ip => cmp_opt(Some(x.ip), Some(y.ip), asc),
            SortColumn::Vendor => cmp_opt(lower(x.vendor), lower(y.vendor), asc),
            SortColumn::Mac => cmp_opt(x.mac, y.mac, asc),
            SortColumn::Services => {
                let services =
                    |h: &crate::model::Host| (!h.services.is_empty()).then(|| h.services_text());
                cmp_opt(services(x), services(y), asc)
            }
            SortColumn::Rtt => cmp_opt(x.rtt, y.rtt, asc),
            SortColumn::Comment => cmp_opt(lower(Some(a.comment)), lower(Some(b.comment)), asc),
        };
        primary.then(x.ip.cmp(&y.ip))
    });
}

pub fn show(
    ui: &mut Ui,
    id_salt: &str,
    rows: &[Row<'_>],
    is_selected: impl Fn(&Row<'_>) -> bool,
    sort: &mut SortState,
    ssh_user: &str,
) -> Vec<Action> {
    let mut out = Vec::new();
    let row_height = ui.spacing().interact_size.y + 4.0;

    TableBuilder::new(ui)
        .id_salt(id_salt)
        .striped(true)
        .resizable(true)
        .sense(Sense::click())
        .cell_layout(Layout::left_to_right(Align::Center))
        .column(Column::exact(18.0))
        .column(Column::initial(210.0).at_least(60.0).clip(true))
        .column(Column::initial(110.0).at_least(80.0))
        .column(Column::initial(190.0).at_least(60.0).clip(true))
        .column(Column::initial(135.0).at_least(60.0).clip(true))
        .column(Column::initial(200.0).at_least(60.0).clip(true))
        .column(Column::initial(60.0).at_least(40.0))
        .column(Column::remainder().at_least(80.0).clip(true))
        .min_scrolled_height(0.0)
        .auto_shrink([false, false])
        .header(row_height, |mut header| {
            for (column, title) in COLUMNS {
                header.col(|ui| {
                    let hint = if title.is_empty() {
                        "Sort by status".to_owned()
                    } else {
                        format!("Sort by {title}")
                    };
                    let label = Label::new(RichText::new(title).strong())
                        .sense(Sense::click())
                        .truncate();
                    let clicked = ui.add(label).on_hover_text(hint).clicked();
                    if sort.column == column {
                        sort_arrow(ui, sort.ascending);
                    }
                    if clicked {
                        if sort.column == column {
                            sort.ascending = !sort.ascending;
                        } else {
                            *sort = SortState {
                                column,
                                ascending: true,
                            };
                        }
                    }
                });
            }
        })
        .body(|body| {
            body.rows(row_height, rows.len(), |mut row| {
                let r = &rows[row.index()];
                let host = r.host;
                row.set_selected(is_selected(r));

                row.col(|ui| status_dot(ui, host));
                row.col(|ui| {
                    if r.favorite {
                        ui.label(RichText::new("★").color(FAVORITE_COLOR))
                            .on_hover_text("Favorite");
                    }
                    match &host.name {
                        Some(name) => ui.add(Label::new(name).truncate()),
                        None => ui.weak("—"),
                    };
                    if host.is_self {
                        ui.weak("this PC");
                    } else if host.is_gateway {
                        ui.weak("gateway");
                    }
                });
                row.col(|ui| {
                    ui.label(host.ip.to_string());
                });
                row.col(|ui| {
                    ui.add(Label::new(host.vendor.unwrap_or_default()).truncate());
                });
                row.col(|ui| {
                    if let Some(mac) = host.mac {
                        ui.monospace(mac.to_string());
                    }
                });
                row.col(|ui| {
                    ui.spacing_mut().item_spacing.x = 3.0;
                    for service in &host.services {
                        let button =
                            egui::Button::new(RichText::new(service.badge()).small()).small();
                        let launch = actions::service_launch(service, host.ip, ssh_user);
                        let tip = match (&service.banner, &launch) {
                            (Some(banner), Some(l)) => format!("{banner}\n{}", l.describe()),
                            (Some(banner), None) => banner.clone(),
                            (None, Some(l)) => l.describe(),
                            (None, None) => format!("TCP port {}", service.port),
                        };
                        if ui.add(button).on_hover_text(tip).clicked()
                            && let Some(launch) = launch
                        {
                            out.push(Action::Launch(launch));
                        }
                    }
                });
                row.col(|ui| {
                    ui.label(format_rtt(host));
                });
                row.col(|ui| {
                    ui.add(Label::new(r.comment).truncate());
                });

                let response = row.response();
                if response.clicked() || response.secondary_clicked() {
                    out.push(Action::Select {
                        ip: host.ip,
                        key: r.key.clone(),
                    });
                }
                response.context_menu(|ui| host_menu(ui, r, ssh_user, &mut out));
            });
        });
    out
}

/// A small painted triangle; the default fonts would render arrow characters as color emoji.
fn sort_arrow(ui: &mut Ui, ascending: bool) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
    let (c, h) = (rect.center(), 3.5);
    let points = if ascending {
        vec![
            pos2(c.x, c.y - h),
            pos2(c.x + h, c.y + h * 0.6),
            pos2(c.x - h, c.y + h * 0.6),
        ]
    } else {
        vec![
            pos2(c.x - h, c.y - h * 0.6),
            pos2(c.x + h, c.y - h * 0.6),
            pos2(c.x, c.y + h),
        ]
    };
    ui.painter().add(Shape::convex_polygon(
        points,
        ui.visuals().strong_text_color(),
        Stroke::NONE,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Host, HostStatus};

    #[test]
    fn missing_values_sort_last_both_ways() {
        let mut a = Host::new("10.0.0.2".parse().unwrap());
        a.name = Some("beta".into());
        let b = Host::new("10.0.0.1".parse().unwrap());
        let mut c = Host::new("10.0.0.3".parse().unwrap());
        c.name = Some("Alpha".into());
        c.status = HostStatus::Alive;
        let row = |h| Row {
            host: h,
            key: String::new(),
            comment: "",
            favorite: false,
        };

        let mut rows = vec![row(&a), row(&b), row(&c)];
        sort_rows(
            &mut rows,
            SortState {
                column: SortColumn::Name,
                ascending: true,
            },
        );
        assert_eq!(
            rows.iter()
                .map(|r| r.host.ip.octets()[3])
                .collect::<Vec<_>>(),
            vec![3, 2, 1]
        );
        sort_rows(
            &mut rows,
            SortState {
                column: SortColumn::Name,
                ascending: false,
            },
        );
        assert_eq!(
            rows.iter()
                .map(|r| r.host.ip.octets()[3])
                .collect::<Vec<_>>(),
            vec![2, 3, 1]
        );
        sort_rows(
            &mut rows,
            SortState {
                column: SortColumn::Ip,
                ascending: true,
            },
        );
        assert_eq!(
            rows.iter()
                .map(|r| r.host.ip.octets()[3])
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }
}
