//! CSV export of scan results.

use std::io::Write;
use std::path::Path;

use crate::model::Host;

pub struct ExportRow {
    pub host: Host,
    pub comment: String,
}

pub fn write_csv(writer: impl Write, rows: &[ExportRow]) -> csv::Result<()> {
    let mut out = csv::Writer::from_writer(writer);
    out.write_record([
        "Status",
        "Name",
        "IP",
        "Manufacturer",
        "MAC address",
        "Services",
        "RTT (ms)",
        "DNS name",
        "NetBIOS name",
        "Workgroup",
        "Comments",
    ])?;
    for ExportRow { host, comment } in rows {
        out.write_record([
            host.status.label().to_owned(),
            host.name.clone().unwrap_or_default(),
            host.ip.to_string(),
            host.vendor.unwrap_or_default().to_owned(),
            host.mac.map(|m| m.to_string()).unwrap_or_default(),
            host.services_text(),
            host.rtt
                .map(|r| format!("{:.2}", r.as_secs_f64() * 1000.0))
                .unwrap_or_default(),
            host.dns_name.clone().unwrap_or_default(),
            host.netbios_name.clone().unwrap_or_default(),
            host.workgroup.clone().unwrap_or_default(),
            comment.clone(),
        ])?;
    }
    out.flush()?;
    Ok(())
}

pub fn save_csv(path: &Path, rows: &[ExportRow]) -> Result<(), String> {
    let file = std::fs::File::create(path)
        .map_err(|e| format!("could not create {}: {e}", path.display()))?;
    write_csv(file, rows).map_err(|e| format!("could not write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HostStatus, Service};

    #[test]
    fn writes_header_and_quoted_fields() {
        let mut host = Host::new("10.0.0.5".parse().unwrap());
        host.status = HostStatus::Alive;
        host.name = Some("box, the first".into());
        host.services = vec![Service::new(22, None), Service::new(80, None)];
        let mut buf = Vec::new();
        write_csv(
            &mut buf,
            &[ExportRow {
                host,
                comment: "rack 3".into(),
            }],
        )
        .unwrap();
        let text = String::from_utf8(buf).unwrap();
        let mut lines = text.lines();
        assert!(lines.next().unwrap().starts_with("Status,Name,IP,"));
        assert_eq!(
            lines.next().unwrap(),
            "Alive,\"box, the first\",10.0.0.5,,,SSH HTTP,,,,,rack 3"
        );
    }
}
