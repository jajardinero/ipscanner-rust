//! Core data types shared by the scanner and the UI.

use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// An Ethernet MAC address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct Mac(pub [u8; 6]);

impl Mac {
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 6]
    }

    /// Locally administered addresses are typically randomized (phones, VMs, containers).
    pub fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02X}:{b:02X}:{c:02X}:{d:02X}:{e:02X}:{g:02X}")
    }
}

impl FromStr for Mac {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 6];
        let mut parts = s.trim().split([':', '-']);
        for byte in &mut bytes {
            let part = parts
                .next()
                .ok_or_else(|| format!("invalid MAC address: {s}"))?;
            *byte =
                u8::from_str_radix(part, 16).map_err(|_| format!("invalid MAC address: {s}"))?;
        }
        if parts.next().is_some() {
            return Err(format!("invalid MAC address: {s}"));
        }
        Ok(Mac(bytes))
    }
}

impl From<Mac> for String {
    fn from(mac: Mac) -> Self {
        mac.to_string()
    }
}

impl TryFrom<String> for Mac {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, PartialOrd, Ord)]
pub enum HostStatus {
    Alive,
    Dead,
    #[default]
    Unknown,
}

impl HostStatus {
    pub fn label(self) -> &'static str {
        match self {
            HostStatus::Alive => "Alive",
            HostStatus::Dead => "Dead",
            HostStatus::Unknown => "Unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ServiceKind {
    Ftp,
    Ssh,
    Telnet,
    Http,
    Https,
    NetBios,
    Smb,
    Rdp,
    Vnc,
    Other,
}

impl ServiceKind {
    pub fn from_port(port: u16) -> Self {
        match port {
            21 => ServiceKind::Ftp,
            22 => ServiceKind::Ssh,
            23 => ServiceKind::Telnet,
            80 | 8000 | 8008 | 8080 | 8081 | 8888 => ServiceKind::Http,
            443 | 8443 | 9443 => ServiceKind::Https,
            139 => ServiceKind::NetBios,
            445 => ServiceKind::Smb,
            3389 => ServiceKind::Rdp,
            5900..=5909 => ServiceKind::Vnc,
            _ => ServiceKind::Other,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ServiceKind::Ftp => "FTP",
            ServiceKind::Ssh => "SSH",
            ServiceKind::Telnet => "Telnet",
            ServiceKind::Http => "HTTP",
            ServiceKind::Https => "HTTPS",
            ServiceKind::NetBios => "NetBIOS",
            ServiceKind::Smb => "SMB",
            ServiceKind::Rdp => "RDP",
            ServiceKind::Vnc => "VNC",
            ServiceKind::Other => "TCP",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    pub port: u16,
    pub kind: ServiceKind,
    /// Greeting line, HTTP title or Server header, if one was read.
    pub banner: Option<String>,
}

impl Service {
    pub fn new(port: u16, banner: Option<String>) -> Self {
        Self {
            port,
            kind: ServiceKind::from_port(port),
            banner,
        }
    }

    /// Short label for badges: "HTTP", or "HTTP:8080" for non-default ports.
    pub fn badge(&self) -> String {
        let default_port = matches!(
            (self.kind, self.port),
            (ServiceKind::Ftp, 21)
                | (ServiceKind::Ssh, 22)
                | (ServiceKind::Telnet, 23)
                | (ServiceKind::Http, 80)
                | (ServiceKind::Https, 443)
                | (ServiceKind::NetBios, 139)
                | (ServiceKind::Smb, 445)
                | (ServiceKind::Rdp, 3389)
                | (ServiceKind::Vnc, 5900)
        );
        if default_port {
            self.kind.label().to_owned()
        } else {
            format!("{}:{}", self.kind.label(), self.port)
        }
    }
}

#[derive(Clone, Debug)]
pub struct Host {
    pub ip: Ipv4Addr,
    pub status: HostStatus,
    /// Display name: reverse DNS, falling back to the NetBIOS name (local hostname for this PC).
    pub name: Option<String>,
    pub dns_name: Option<String>,
    pub netbios_name: Option<String>,
    pub workgroup: Option<String>,
    pub mac: Option<Mac>,
    pub vendor: Option<&'static str>,
    pub rtt: Option<Duration>,
    pub services: Vec<Service>,
    pub is_self: bool,
    pub is_gateway: bool,
}

impl Host {
    pub fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            status: HostStatus::Unknown,
            name: None,
            dns_name: None,
            netbios_name: None,
            workgroup: None,
            mac: None,
            vendor: None,
            rtt: None,
            services: Vec::new(),
            is_self: false,
            is_gateway: false,
        }
    }

    /// Stable identity used for favorites and comments: the MAC if known, else the IP.
    pub fn key(&self) -> String {
        host_key(self.mac, self.ip)
    }

    /// Merge newer information into this host without discarding what is already known.
    pub fn merge(&mut self, other: Host) {
        self.status = match (self.status, other.status) {
            (HostStatus::Alive, _) | (_, HostStatus::Alive) => HostStatus::Alive,
            (_, HostStatus::Dead) | (HostStatus::Dead, _) => HostStatus::Dead,
            _ => HostStatus::Unknown,
        };
        if other.name.is_some() {
            self.name = other.name;
        }
        if other.dns_name.is_some() {
            self.dns_name = other.dns_name;
        }
        if other.netbios_name.is_some() {
            self.netbios_name = other.netbios_name;
        }
        if other.workgroup.is_some() {
            self.workgroup = other.workgroup;
        }
        if other.mac.is_some() {
            self.mac = other.mac;
        }
        if other.vendor.is_some() {
            self.vendor = other.vendor;
        }
        if other.rtt.is_some() {
            self.rtt = other.rtt;
        }
        for service in other.services {
            match self.services.iter_mut().find(|s| s.port == service.port) {
                Some(existing) => {
                    if service.banner.is_some() {
                        existing.banner = service.banner;
                    }
                }
                None => self.services.push(service),
            }
        }
        self.services.sort_by_key(|s| s.port);
        self.is_self |= other.is_self;
        self.is_gateway |= other.is_gateway;
    }

    pub fn service(&self, kind: ServiceKind) -> Option<&Service> {
        self.services.iter().find(|s| s.kind == kind)
    }

    pub fn services_text(&self) -> String {
        self.services
            .iter()
            .map(Service::badge)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub fn host_key(mac: Option<Mac>, ip: Ipv4Addr) -> String {
    match mac {
        Some(mac) => mac.to_string(),
        None => ip.to_string(),
    }
}

/// User-tunable scan settings.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Maximum number of hosts probed concurrently.
    pub max_parallel: usize,
    pub ping_timeout_ms: u64,
    pub ping_tries: u32,
    pub tcp_timeout_ms: u64,
    /// Comma-separated list of TCP ports probed on alive hosts.
    pub ports: String,
    pub resolve_dns: bool,
    pub resolve_netbios: bool,
    pub grab_banners: bool,
    /// Use a raw ARP sweep on local subnets when the binary has CAP_NET_RAW.
    pub raw_arp: bool,
    /// User name for SSH sessions; empty means the current user.
    pub ssh_user: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_parallel: 128,
            ping_timeout_ms: 800,
            ping_tries: 2,
            tcp_timeout_ms: 500,
            ports: "21,22,23,80,139,443,445,3389,5900,8080,8443".to_owned(),
            resolve_dns: true,
            resolve_netbios: true,
            grab_banners: true,
            raw_arp: true,
            ssh_user: String::new(),
        }
    }
}

impl Settings {
    pub fn port_list(&self) -> Result<Vec<u16>, String> {
        parse_ports(&self.ports)
    }
}

/// Parse "22, 80,443 8000-8010" into a sorted, de-duplicated port list.
pub fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for item in input
        .split([',', ' ', '\t', '\n'])
        .filter(|s| !s.is_empty())
    {
        let parse = |s: &str| {
            s.trim()
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("invalid port: {s}"))
        };
        match item.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (parse(a)?, parse(b)?);
                if a > b {
                    return Err(format!("invalid port range: {item}"));
                }
                ports.extend(a..=b);
            }
            None => ports.push(parse(item)?),
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.len() > 1024 {
        return Err("at most 1024 ports can be probed".to_owned());
    }
    Ok(ports)
}

/// A host pinned to the Favorites tab, with its last known details.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Favorite {
    pub ip: Ipv4Addr,
    pub mac: Option<Mac>,
    pub name: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ThemeChoice {
    #[default]
    System,
    Light,
    Dark,
}

/// Everything that survives an app restart.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Persisted {
    pub settings: Settings,
    pub favorites: BTreeMap<String, Favorite>,
    pub comments: BTreeMap<String, String>,
    pub last_range: String,
    pub show_dead: bool,
    pub show_details: bool,
    pub theme: ThemeChoice,
}

impl Default for Persisted {
    fn default() -> Self {
        Self {
            settings: Settings::default(),
            favorites: BTreeMap::new(),
            comments: BTreeMap::new(),
            last_range: String::new(),
            show_dead: false,
            show_details: true,
            theme: ThemeChoice::System,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_roundtrip() {
        let mac: Mac = "00:50:56:94:c6:c9".parse().unwrap();
        assert_eq!(mac.0, [0x00, 0x50, 0x56, 0x94, 0xc6, 0xc9]);
        assert_eq!(mac.to_string(), "00:50:56:94:C6:C9");
        assert_eq!("00-50-56-94-C6-C9".parse::<Mac>().unwrap(), mac);
        assert!("00:50:56".parse::<Mac>().is_err());
        assert!("00:50:56:94:c6:c9:00".parse::<Mac>().is_err());
    }

    #[test]
    fn ports_parse() {
        assert_eq!(parse_ports("80, 22,443 22").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("8000-8002").unwrap(), vec![8000, 8001, 8002]);
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("70000").is_err());
        assert!(parse_ports("90-80").is_err());
        assert!(parse_ports("1-2000").is_err());
    }

    #[test]
    fn merge_keeps_known_fields() {
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        let mut host = Host::new(ip);
        host.status = HostStatus::Alive;
        host.mac = Some(Mac([1, 2, 3, 4, 5, 6]));
        host.services
            .push(Service::new(22, Some("SSH-2.0-OpenSSH".into())));

        let mut update = Host::new(ip);
        update.status = HostStatus::Dead;
        update.name = Some("box.lan".into());
        update.services.push(Service::new(22, None));
        update.services.push(Service::new(80, None));
        host.merge(update);

        assert_eq!(host.status, HostStatus::Alive);
        assert_eq!(host.name.as_deref(), Some("box.lan"));
        assert!(host.mac.is_some());
        assert_eq!(host.services.len(), 2);
        assert_eq!(host.services[0].banner.as_deref(), Some("SSH-2.0-OpenSSH"));
    }
}
